"""
Phase 1-2: Download CICIDS2017, clean it, train RF + XGBoost classifiers,
save best model as severity_model.pkl for use in ml_classifier.py.

Run once:
    python train_classifier.py

Outputs:
    severity_model.pkl     -- best model (by F1 on malicious class)
    cicids_clean.csv       -- cleaned dataset (for inspection / reuse)
    retrain_history.csv    -- initial training record
"""

import os
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, f1_score
import pickle

# ── 1. DOWNLOAD VIA KAGGLEHUB ────────────────────────────────────────────────
print("=" * 60)
print("Step 1: Downloading CICIDS2017 via kagglehub...")
print("=" * 60)

df_raw = None

try:
    import kagglehub

    # Use dataset_download() → returns local directory path (avoids file_path="" bug)
    dataset_path = kagglehub.dataset_download("dhoogla/cicids2017")
    print(f"  Dataset cached at: {dataset_path}")

    # Walk the directory and collect all data files
    all_files = []
    for root, dirs, files in os.walk(dataset_path):
        for f in files:
            all_files.append(os.path.join(root, f))

    print(f"  Files found ({len(all_files)}): {[os.path.basename(f) for f in all_files]}")

    csv_files     = sorted([f for f in all_files if f.lower().endswith(".csv")])
    parquet_files = sorted([f for f in all_files if f.lower().endswith(".parquet")])

    dfs = []
    if csv_files:
        print(f"  Loading {len(csv_files)} CSV file(s)...")
        for fp in csv_files[:5]:   # cap at 5 days — ~750k rows max
            print(f"    Reading: {os.path.basename(fp)}")
            try:
                dfs.append(pd.read_csv(fp, low_memory=False))
            except Exception as e:
                print(f"    Skipped ({e})")
    elif parquet_files:
        print(f"  Loading {len(parquet_files)} parquet file(s)...")
        for fp in parquet_files[:3]:
            print(f"    Reading: {os.path.basename(fp)}")
            dfs.append(pd.read_parquet(fp))
    else:
        raise RuntimeError(f"No usable data files under {dataset_path}")

    if not dfs:
        raise RuntimeError("All files failed to load.")

    df_raw = pd.concat(dfs, ignore_index=True)
    print(f"  Combined: {len(df_raw):,} rows x {df_raw.shape[1]} columns")

except Exception as e:
    print(f"  kagglehub failed: {e}")
    print("  Trying local fallback CSV...")
    for candidate in [
        "cicids2017.csv",
        "cicids_clean.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    ]:
        if os.path.exists(candidate):
            df_raw = pd.read_csv(candidate, low_memory=False)
            print(f"  Loaded fallback: {candidate}  ({len(df_raw):,} rows)")
            break

if df_raw is None:
    raise RuntimeError(
        "Could not load CICIDS2017. Either:\n"
        "  1) Configure Kaggle credentials: place kaggle.json in ~/.kaggle/\n"
        "  2) Manually download a CICIDS2017 CSV and place it in D:\\MICROSOFT HACKATHON\\"
    )

print(f"\nLabel distribution (raw):\n{df_raw.iloc[:, -1].value_counts()}\n")

# ── 2. CLEAN ─────────────────────────────────────────────────────────────────
print("=" * 60)
print("Step 2: Cleaning...")
print("=" * 60)

df = df_raw.copy()

# Normalise column names
df.columns = (
    df.columns.str.strip()
              .str.lower()
              .str.replace(" ", "_")
              .str.replace("/", "_per_")
              .str.replace("-", "_")
)

# Find label column (last column or 'label')
label_col = "label" if "label" in df.columns else df.columns[-1]
print(f"  Label column: '{label_col}'")

# Drop infinite / NaN
df = df.replace([np.inf, -np.inf], np.nan)
before = len(df)
df = df.dropna()
print(f"  Dropped {before - len(df):,} NaN/Inf rows  ({len(df):,} remain)")

# Binary label
df["is_malicious"] = (df[label_col].str.strip().str.upper() != "BENIGN").astype(int)
df["attack_type"]  = df[label_col].str.strip()

print(f"\n  is_malicious: {df['is_malicious'].value_counts().to_dict()}")
print(f"  Attack types:\n{df['attack_type'].value_counts()}")

# ── 3. FEATURE SELECTION ─────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("Step 3: Selecting features...")
print("=" * 60)

CANDIDATE_FEATURES = [
    "flow_duration", "total_fwd_packets", "total_backward_packets",
    "total_length_of_fwd_packets", "total_length_of_bwd_packets",
    "fwd_packet_length_max", "fwd_packet_length_min", "fwd_packet_length_mean",
    "bwd_packet_length_max", "bwd_packet_length_min", "bwd_packet_length_mean",
    "flow_bytes_per_s", "flow_packets_per_s",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_mean", "bwd_iat_mean",
    "fwd_psh_flags", "bwd_psh_flags",
    "init_win_bytes_forward", "init_win_bytes_backward",
    "act_data_pkt_fwd", "average_packet_size",
    "avg_fwd_segment_size", "avg_bwd_segment_size",
]

available = [f for f in CANDIDATE_FEATURES if f in df.columns]
if len(available) < 10:
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    extra = [c for c in numeric_cols if c not in available and c != "is_malicious"]
    available += extra[:max(0, 15 - len(available))]

FEATURES = available[:20]
print(f"  Using {len(FEATURES)} features: {FEATURES}")

X = df[FEATURES].values
y = df["is_malicious"].values

# Sub-sample to max 150k rows (balanced) to keep training fast
MAX_ROWS = 150_000
if len(X) > MAX_ROWS:
    rng = np.random.default_rng(42)
    idx_mal = np.where(y == 1)[0]
    idx_ben = np.where(y == 0)[0]
    n_each  = MAX_ROWS // 2
    idx = np.concatenate([
        rng.choice(idx_mal, min(n_each, len(idx_mal)), replace=False),
        rng.choice(idx_ben, min(n_each, len(idx_ben)), replace=False),
    ])
    X, y = X[idx], y[idx]
    print(f"  Subsampled to {len(X):,} rows (balanced)")

# ── 4. TRAIN/TEST SPLIT ──────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("Step 4: Train/test split (stratified 80/20)...")
print("=" * 60)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)
print(f"  Train: {len(X_train):,}   Test: {len(X_test):,}")

scaler     = StandardScaler()
X_train_s  = scaler.fit_transform(X_train)
X_test_s   = scaler.transform(X_test)

# ── 5. RANDOM FOREST ─────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("Step 5: Training RandomForest...")
print("=" * 60)

rf = RandomForestClassifier(
    n_estimators=200, max_depth=20, min_samples_leaf=5,
    class_weight="balanced", n_jobs=-1, random_state=42,
)
rf.fit(X_train_s, y_train)
rf_f1 = f1_score(y_test, rf.predict(X_test_s))
print(f"\n  RF F1 (malicious): {rf_f1:.4f}")
print(classification_report(y_test, rf.predict(X_test_s), target_names=["Benign", "Malicious"]))

best_model, best_f1, best_name = rf, rf_f1, "RandomForest"

# ── 6. XGBOOST ───────────────────────────────────────────────────────────────
print("=" * 60)
print("Step 6: Training XGBoost...")
print("=" * 60)

try:
    from xgboost import XGBClassifier
    scale_pos = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
    xgb = XGBClassifier(
        n_estimators=300, max_depth=8, learning_rate=0.1,
        scale_pos_weight=scale_pos, eval_metric="logloss",
        random_state=42, n_jobs=-1, verbosity=0,
    )
    xgb.fit(X_train_s, y_train)
    xgb_f1 = f1_score(y_test, xgb.predict(X_test_s))
    print(f"\n  XGB F1 (malicious): {xgb_f1:.4f}")
    print(classification_report(y_test, xgb.predict(X_test_s), target_names=["Benign", "Malicious"]))
    if xgb_f1 > best_f1:
        best_model, best_f1, best_name = xgb, xgb_f1, "XGBoost"
except ImportError:
    print("  XGBoost not installed — using RandomForest only.")

print(f"\n  Best model: {best_name}  (F1={best_f1:.4f})")

# ── 7. SAVE ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("Step 7: Saving model + artefacts...")
print("=" * 60)

bundle = {"model": best_model, "scaler": scaler, "features": FEATURES,
          "name": best_name, "f1": best_f1}
with open("severity_model.pkl", "wb") as fh:
    pickle.dump(bundle, fh)
print("  Saved: severity_model.pkl")

df[FEATURES + ["is_malicious", "attack_type"]].to_csv("cicids_clean.csv", index=False)
print(f"  Saved: cicids_clean.csv  ({len(df):,} rows)")

import csv, datetime
write_header = not os.path.exists("retrain_history.csv")
with open("retrain_history.csv", "a", newline="") as fh:
    w = csv.writer(fh)
    if write_header:
        w.writerow(["timestamp", "model", "n_train_samples", "f1_score"])
    w.writerow([datetime.datetime.utcnow().isoformat(), best_name, len(X_train), round(best_f1, 4)])
print("  Saved: retrain_history.csv")

if hasattr(best_model, "feature_importances_"):
    importances = sorted(zip(FEATURES, best_model.feature_importances_),
                         key=lambda x: x[1], reverse=True)[:10]
    print("\n  Top-10 feature importances:")
    for feat, imp in importances:
        print(f"    {feat:<40} {imp:.4f}")

print("\n" + "=" * 60)
print(f"  DONE — {best_name}  F1={best_f1:.4f}")
print("=" * 60)
