"""
model_eval.py — Complete model evaluation. ALL outputs go to outputs/.

Saves:
  outputs/model_evaluation_report.md   full numeric report (open in any editor)
  outputs/model_eval_charts.png        learning curve + feature importance
  outputs/confusion_matrix.png         confusion matrix heatmap
  outputs/roc_curve.png                ROC-AUC curve
  outputs/cv_fold_scores.csv           per-fold CV scores
  outputs/per_class_metrics.csv        precision/recall/f1 per class

Run:
    python model_eval.py
"""

import os, pickle, warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
from sklearn.model_selection import (
    cross_val_score, StratifiedKFold, learning_curve, train_test_split
)
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, roc_curve, f1_score,
    precision_score, recall_score, accuracy_score
)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

OUT_DIR = os.path.join(os.path.dirname(__file__), "outputs")
os.makedirs(OUT_DIR, exist_ok=True)

DARK   = "#0B0D10"
SURF   = "#15191F"
SURFE  = "#1B2028"
BORDER = "#292F38"
TEXT   = "#F1F3F5"
TEXT2  = "#A0A8B4"
ACCENT = "#6EA8FE"
RED    = "#EF4444"
ORANGE = "#F97316"
GREEN  = "#22C55E"
YELLOW = "#EAB308"

plt.rcParams.update({
    "figure.facecolor": DARK,
    "axes.facecolor":   SURF,
    "text.color":       TEXT,
    "axes.labelcolor":  TEXT2,
    "xtick.color":      TEXT2,
    "ytick.color":      TEXT2,
    "axes.edgecolor":   BORDER,
    "grid.color":       BORDER,
    "font.family":      "sans-serif",
})

lines_report = []
def log(msg=""):
    print(msg)
    lines_report.append(msg)

log("=" * 70)
log("  MODEL EVALUATION REPORT — SOC Alert Triage Pipeline")
log("  Microsoft Hackathon 2026")
log("=" * 70)

# ── Load bundle ───────────────────────────────────────────────────────────────
with open("severity_model.pkl", "rb") as fh:
    bundle = pickle.load(fh)
model    = bundle["model"]
scaler   = bundle["scaler"]
features = bundle["features"]

log(f"\nModel      : {bundle['name']}")
log(f"Saved F1   : {bundle['f1']:.4f}  (malicious class, held-out test set)")
log(f"Features   : {len(features)}")
log(f"Feature list: {features}")

# ── Reload data ───────────────────────────────────────────────────────────────
log("\nLoading cicids_clean.csv ...")
df = pd.read_csv("cicids_clean.csv")
log(f"  Total rows : {len(df):,}")
log(f"  Malicious  : {df['is_malicious'].sum():,}  ({df['is_malicious'].mean()*100:.1f}%)")
log(f"  Benign     : {(df['is_malicious']==0).sum():,}  ({(1-df['is_malicious'].mean())*100:.1f}%)")
log(f"  Attack types:\n{df['attack_type'].value_counts().to_string()}")

X = df[features].values
y = df["is_malicious"].values

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
    log(f"\n  Subsampled (balanced): {len(X):,} rows")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)
X_train_s = scaler.transform(X_train)
X_test_s  = scaler.transform(X_test)

log(f"\n  Train set : {len(X_train):,}")
log(f"  Test set  : {len(X_test):,}")

# ═══════════════════════════════════════════════════════════════════════════════
# CHECK 1 — Train vs Test Gap
# ═══════════════════════════════════════════════════════════════════════════════
log("\n" + "=" * 70)
log("  CHECK 1: Train vs Test Performance Gap  (primary overfitting signal)")
log("=" * 70)

y_train_pred = model.predict(X_train_s)
y_test_pred  = model.predict(X_test_s)

train_f1   = f1_score(y_train, y_train_pred)
test_f1    = f1_score(y_test,  y_test_pred)
train_acc  = accuracy_score(y_train, y_train_pred)
test_acc   = accuracy_score(y_test,  y_test_pred)
train_prec = precision_score(y_train, y_train_pred)
test_prec  = precision_score(y_test,  y_test_pred)
train_rec  = recall_score(y_train, y_train_pred)
test_rec   = recall_score(y_test,  y_test_pred)

gap_f1   = train_f1  - test_f1
gap_acc  = train_acc - test_acc
gap_prec = train_prec - test_prec
gap_rec  = train_rec  - test_rec

log(f"\n  {'Metric':<22} {'Train':>10} {'Test':>10} {'Gap':>12} {'Status':>10}")
log(f"  {'-'*66}")
log(f"  {'F1 (malicious)':<22} {train_f1:>10.4f} {test_f1:>10.4f} {gap_f1:>+12.4f} {'OK' if gap_f1 < 0.05 else 'WARN':>10}")
log(f"  {'Accuracy':<22} {train_acc:>10.4f} {test_acc:>10.4f} {gap_acc:>+12.4f} {'OK' if gap_acc < 0.05 else 'WARN':>10}")
log(f"  {'Precision':<22} {train_prec:>10.4f} {test_prec:>10.4f} {gap_prec:>+12.4f} {'OK' if gap_prec < 0.05 else 'WARN':>10}")
log(f"  {'Recall':<22} {train_rec:>10.4f} {test_rec:>10.4f} {gap_rec:>+12.4f} {'OK' if gap_rec < 0.05 else 'WARN':>10}")

if gap_f1 < 0.05:
    verdict_gap = "PASS — NO OVERFITTING (gap < 5pp)"
elif gap_f1 < 0.10:
    verdict_gap = "MILD OVERFITTING (gap 5-10pp, acceptable)"
else:
    verdict_gap = "FAIL — OVERFITTING (gap > 10pp)"
log(f"\n  Verdict: {verdict_gap}")

# ═══════════════════════════════════════════════════════════════════════════════
# CHECK 2 — 5-Fold Cross-Validation
# ═══════════════════════════════════════════════════════════════════════════════
log("\n" + "=" * 70)
log("  CHECK 2: 5-Fold Stratified Cross-Validation")
log("=" * 70)

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_f1 = cross_val_score(model, X_train_s, y_train, cv=cv, scoring="f1",       n_jobs=-1)
cv_pr = cross_val_score(model, X_train_s, y_train, cv=cv, scoring="precision", n_jobs=-1)
cv_rc = cross_val_score(model, X_train_s, y_train, cv=cv, scoring="recall",    n_jobs=-1)
cv_ac = cross_val_score(model, X_train_s, y_train, cv=cv, scoring="accuracy",  n_jobs=-1)

log(f"\n  {'Fold':<8} {'F1':>10} {'Precision':>12} {'Recall':>10} {'Accuracy':>12}")
log(f"  {'-'*54}")
for i, (f, p, r, a) in enumerate(zip(cv_f1, cv_pr, cv_rc, cv_ac), 1):
    log(f"  {'Fold '+str(i):<8} {f:>10.4f} {p:>12.4f} {r:>10.4f} {a:>12.4f}")
log(f"  {'-'*54}")
log(f"  {'Mean':<8} {cv_f1.mean():>10.4f} {cv_pr.mean():>12.4f} {cv_rc.mean():>10.4f} {cv_ac.mean():>12.4f}")
log(f"  {'Std':<8} {cv_f1.std():>10.4f} {cv_pr.std():>12.4f} {cv_rc.std():>10.4f} {cv_ac.std():>12.4f}")

if cv_f1.std() < 0.02:
    verdict_cv = "PASS — Very stable (std < 0.02, no overfitting signal)"
elif cv_f1.std() < 0.05:
    verdict_cv = "ACCEPTABLE — Moderate variance (std < 0.05)"
else:
    verdict_cv = "FAIL — High variance (std > 0.05, model unstable)"
log(f"\n  Verdict: {verdict_cv}")

# Save CV scores CSV
cv_df = pd.DataFrame({
    "fold": [f"Fold {i}" for i in range(1, 6)],
    "f1": cv_f1, "precision": cv_pr, "recall": cv_rc, "accuracy": cv_ac
})
cv_df.to_csv(os.path.join(OUT_DIR, "cv_fold_scores.csv"), index=False)
log(f"  Saved: outputs/cv_fold_scores.csv")

# ═══════════════════════════════════════════════════════════════════════════════
# CHECK 3 — Full Classification Report
# ═══════════════════════════════════════════════════════════════════════════════
log("\n" + "=" * 70)
log("  CHECK 3: Full Classification Report on Held-Out Test Set")
log("=" * 70)

report = classification_report(y_test, y_test_pred,
                                target_names=["Benign", "Malicious"],
                                output_dict=True)
report_str = classification_report(y_test, y_test_pred,
                                    target_names=["Benign", "Malicious"])
log(f"\n{report_str}")

y_proba = model.predict_proba(X_test_s)[:, 1]
auc = roc_auc_score(y_test, y_proba)
log(f"  ROC-AUC: {auc:.4f}")

cm = confusion_matrix(y_test, y_test_pred)
tn, fp, fn, tp = cm.ravel()
fpr_val = fp / (fp + tn)
fnr_val = fn / (fn + tp)
ppv = tp / (tp + fp)  # precision
npv = tn / (tn + fn)  # negative predictive value

log(f"\n  CONFUSION MATRIX")
log(f"  {'':20} Predicted Benign   Predicted Malicious")
log(f"  {'Actual Benign':<20} {tn:>16,}   {fp:>18,}")
log(f"  {'Actual Malicious':<20} {fn:>16,}   {tp:>18,}")
log(f"\n  True  Positives (TP): {tp:,}   — real attacks correctly caught")
log(f"  True  Negatives (TN): {tn:,}  — benign correctly filtered")
log(f"  False Positives (FP): {fp:,}     — benign flagged as malicious (noise to analyst)")
log(f"  False Negatives (FN): {fn:,}      — real attacks missed")
log(f"\n  False Positive Rate (FPR): {fpr_val*100:.2f}%   <- noise passed to analyst")
log(f"  False Negative Rate (FNR): {fnr_val*100:.2f}%   <- real attacks missed")
log(f"  Positive Predictive Value : {ppv*100:.2f}%   <- when flagged, how often real")
log(f"  Negative Predictive Value : {npv*100:.2f}%   <- when cleared, how often safe")

# Per-class CSV
per_class = pd.DataFrame({
    "class": ["Benign", "Malicious"],
    "precision": [report["Benign"]["precision"], report["Malicious"]["precision"]],
    "recall":    [report["Benign"]["recall"],    report["Malicious"]["recall"]],
    "f1":        [report["Benign"]["f1-score"],  report["Malicious"]["f1-score"]],
    "support":   [report["Benign"]["support"],   report["Malicious"]["support"]],
})
per_class.to_csv(os.path.join(OUT_DIR, "per_class_metrics.csv"), index=False)
log(f"\n  Saved: outputs/per_class_metrics.csv")

# ═══════════════════════════════════════════════════════════════════════════════
# CHECK 4 — Feature Importance
# ═══════════════════════════════════════════════════════════════════════════════
log("\n" + "=" * 70)
log("  CHECK 4: Feature Importance (all 20 features)")
log("=" * 70)

imps = sorted(zip(features, model.feature_importances_), key=lambda x: x[1], reverse=True)
log(f"\n  {'Rank':<5} {'Feature':<42} {'Importance':>12} {'Bar':}")
log(f"  {'-'*80}")
for i, (feat, imp) in enumerate(imps, 1):
    bar = "#" * int(imp * 300)
    log(f"  {i:<5} {feat:<42} {imp:>12.4f}  {bar}")

# ═══════════════════════════════════════════════════════════════════════════════
# CHECK 5 — Learning Curve
# ═══════════════════════════════════════════════════════════════════════════════
log("\n" + "=" * 70)
log("  CHECK 5: Learning Curve")
log("=" * 70)

train_sizes, train_scores, val_scores = learning_curve(
    model, X_train_s, y_train,
    cv=StratifiedKFold(n_splits=3, shuffle=True, random_state=42),
    scoring="f1",
    train_sizes=np.linspace(0.1, 1.0, 8),
    n_jobs=-1,
)

log(f"\n  {'Train Size':<12} {'Train F1':>12} {'Val F1':>12} {'Gap':>10}")
log(f"  {'-'*48}")
for sz, tr, vl in zip(train_sizes, train_scores.mean(1), val_scores.mean(1)):
    log(f"  {sz:<12,.0f} {tr:>12.4f} {vl:>12.4f} {tr-vl:>+10.4f}")

final_gap = train_scores.mean(1)[-1] - val_scores.mean(1)[-1]
if final_gap < 0.05:
    verdict_lc = "PASS — Learning curves converge (no overfitting)"
elif final_gap < 0.10:
    verdict_lc = "MILD — Some gap, but converging"
else:
    verdict_lc = "FAIL — Curves diverge (overfitting)"
log(f"\n  Final gap at max training size: {final_gap:+.4f}")
log(f"  Verdict: {verdict_lc}")

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
log("\n" + "=" * 70)
log("  FINAL VERDICT SUMMARY")
log("=" * 70)
log(f"""
  Algorithm        : {bundle['name']}
  Training data    : CICIDS2017 (1,024,583 rows, 8 attack scenarios)
  Train samples    : {len(X_train):,}
  Test samples     : {len(X_test):,}
  Features used    : {len(features)}

  ── Performance ──────────────────────────────────────────
  Test F1          : {test_f1:.4f}
  Test Precision   : {test_prec:.4f}
  Test Recall      : {test_rec:.4f}
  Test Accuracy    : {test_acc:.4f}
  ROC-AUC          : {auc:.4f}

  ── Overfitting Checks ───────────────────────────────────
  Train/Test F1 Gap: {gap_f1:+.4f}   [{verdict_gap}]
  CV Mean F1       : {cv_f1.mean():.4f} +/- {cv_f1.std():.4f}   [{verdict_cv}]
  Learning Curve   : [{verdict_lc}]

  ── Error Rates ──────────────────────────────────────────
  FPR (noise to analyst): {fpr_val*100:.2f}%
  FNR (attacks missed)  : {fnr_val*100:.2f}%
  TP={tp}  TN={tn}  FP={fp}  FN={fn}
""")

# ═══════════════════════════════════════════════════════════════════════════════
# PLOTS
# ═══════════════════════════════════════════════════════════════════════════════

# ── Figure 1: Learning Curve + Feature Importance ─────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(16, 6))
fig.suptitle("Model Evaluation — RandomForest (CICIDS2017)", color=TEXT, fontsize=14, y=1.01)

ax = axes[0]
ax.set_facecolor(SURF)
ax.plot(train_sizes, train_scores.mean(1), "o-", color=ACCENT,  lw=2, label="Train F1", ms=6)
ax.fill_between(train_sizes,
                train_scores.mean(1) - train_scores.std(1),
                train_scores.mean(1) + train_scores.std(1),
                alpha=0.15, color=ACCENT)
ax.plot(train_sizes, val_scores.mean(1),   "o-", color=GREEN, lw=2, label="Val F1",   ms=6)
ax.fill_between(train_sizes,
                val_scores.mean(1) - val_scores.std(1),
                val_scores.mean(1) + val_scores.std(1),
                alpha=0.15, color=GREEN)
ax.axhline(test_f1, color=ORANGE, lw=1.5, ls="--", label=f"Test F1={test_f1:.4f}")
ax.set_title("Learning Curve", color=TEXT, pad=10)
ax.set_xlabel("Training Samples")
ax.set_ylabel("F1 Score (malicious)")
ax.legend(framealpha=0.2, labelcolor=TEXT)
ax.spines[:].set_color(BORDER)
ax.set_ylim([0.7, 1.05])
ax.grid(True, alpha=0.2)
ax.annotate(f"Final gap: {final_gap:+.4f}", fontsize=9, color=YELLOW,
            xy=(train_sizes[-1], val_scores.mean(1)[-1]),
            xytext=(train_sizes[3], val_scores.mean(1)[-1] - 0.04),
            arrowprops=dict(arrowstyle="->", color=YELLOW))

ax2 = axes[1]
ax2.set_facecolor(SURF)
top_feats = [f for f, _ in imps[:15]][::-1]
top_imps  = [v for _, v in imps[:15]][::-1]
colors    = [ACCENT if v > 0.08 else GREEN if v > 0.04 else TEXT2 for v in top_imps]
ax2.barh(top_feats, top_imps, color=colors, alpha=0.85)
ax2.set_title("Top-15 Feature Importances", color=TEXT, pad=10)
ax2.set_xlabel("Importance Score")
ax2.spines[:].set_color(BORDER)
ax2.grid(True, axis="x", alpha=0.2)
for spine in ax2.spines.values():
    spine.set_color(BORDER)

plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "model_eval_charts.png"), dpi=150, bbox_inches="tight", facecolor=DARK)
plt.close()
log("  Saved: outputs/model_eval_charts.png")

# ── Figure 2: Confusion Matrix ────────────────────────────────────────────────
fig2, ax3 = plt.subplots(figsize=(7, 6))
fig2.patch.set_facecolor(DARK)
ax3.set_facecolor(SURF)

cm_norm = cm.astype(float) / cm.sum(axis=1)[:, np.newaxis]
im = ax3.imshow(cm_norm, interpolation="nearest", cmap="Blues", vmin=0, vmax=1)
plt.colorbar(im, ax=ax3, fraction=0.046, pad=0.04)

labels = ["Benign", "Malicious"]
tick_marks = np.arange(len(labels))
ax3.set_xticks(tick_marks); ax3.set_xticklabels(labels, color=TEXT)
ax3.set_yticks(tick_marks); ax3.set_yticklabels(labels, color=TEXT)
ax3.set_title(f"Confusion Matrix (normalised)\nFPR={fpr_val*100:.2f}%  FNR={fnr_val*100:.2f}%  AUC={auc:.4f}",
              color=TEXT, pad=12)
ax3.set_xlabel("Predicted Label", color=TEXT2)
ax3.set_ylabel("True Label", color=TEXT2)

for i in range(2):
    for j in range(2):
        raw = cm[i, j]
        pct = cm_norm[i, j]
        color = "white" if pct > 0.5 else TEXT
        ax3.text(j, i, f"{raw:,}\n({pct*100:.1f}%)", ha="center", va="center",
                 color=color, fontsize=12, fontweight="bold")

ax3.spines[:].set_color(BORDER)
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "confusion_matrix.png"), dpi=150, bbox_inches="tight", facecolor=DARK)
plt.close()
log("  Saved: outputs/confusion_matrix.png")

# ── Figure 3: ROC Curve ───────────────────────────────────────────────────────
fig3, ax4 = plt.subplots(figsize=(7, 6))
fig3.patch.set_facecolor(DARK)
ax4.set_facecolor(SURF)

fpr_curve, tpr_curve, _ = roc_curve(y_test, y_proba)
ax4.plot(fpr_curve, tpr_curve, color=ACCENT, lw=2.5, label=f"RandomForest (AUC = {auc:.4f})")
ax4.plot([0, 1], [0, 1], color=BORDER, lw=1.5, ls="--", label="Random baseline (AUC=0.50)")
ax4.fill_between(fpr_curve, tpr_curve, alpha=0.08, color=ACCENT)
ax4.set_xlim([0, 1]); ax4.set_ylim([0, 1.02])
ax4.set_xlabel("False Positive Rate (FPR)")
ax4.set_ylabel("True Positive Rate (TPR / Recall)")
ax4.set_title("ROC Curve — Malicious Traffic Detection", color=TEXT, pad=12)
ax4.legend(framealpha=0.2, labelcolor=TEXT)
ax4.spines[:].set_color(BORDER)
ax4.grid(True, alpha=0.2)
ax4.annotate(f"Operating point\nFPR={fpr_val*100:.2f}%  TPR={(1-fnr_val)*100:.2f}%",
             xy=(fpr_val, 1-fnr_val), xytext=(0.3, 0.5),
             color=YELLOW, fontsize=9,
             arrowprops=dict(arrowstyle="->", color=YELLOW))
ax4.scatter([fpr_val], [1-fnr_val], color=RED, s=100, zorder=5)

plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "roc_curve.png"), dpi=150, bbox_inches="tight", facecolor=DARK)
plt.close()
log("  Saved: outputs/roc_curve.png")

# ── Figure 4: CV Fold bars ────────────────────────────────────────────────────
fig4, axes4 = plt.subplots(1, 2, figsize=(13, 5))
fig4.patch.set_facecolor(DARK)
fig4.suptitle("Cross-Validation (5-Fold Stratified) Results", color=TEXT, fontsize=13)

fold_labels = [f"Fold {i}" for i in range(1, 6)]

ax5 = axes4[0]
ax5.set_facecolor(SURF)
bar_colors = [GREEN if f >= cv_f1.mean() else ACCENT for f in cv_f1]
bars = ax5.bar(fold_labels, cv_f1, color=bar_colors, alpha=0.85, edgecolor=BORDER)
ax5.axhline(cv_f1.mean(), color=ORANGE, ls="--", lw=2, label=f"Mean={cv_f1.mean():.4f}")
ax5.axhline(test_f1,      color=RED,    ls=":",  lw=2, label=f"Test F1={test_f1:.4f}")
ax5.set_title("F1 Score per Fold", color=TEXT)
ax5.set_ylabel("F1 Score (malicious)")
ax5.set_ylim([0.90, 1.0])
ax5.legend(framealpha=0.2, labelcolor=TEXT)
ax5.spines[:].set_color(BORDER)
ax5.grid(True, axis="y", alpha=0.2)
for bar, val in zip(bars, cv_f1):
    ax5.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.001,
             f"{val:.4f}", ha="center", color=TEXT, fontsize=9)

ax6 = axes4[1]
ax6.set_facecolor(SURF)
metrics_labels = ["Precision", "Recall", "F1", "Accuracy"]
means  = [cv_pr.mean(), cv_rc.mean(), cv_f1.mean(), cv_ac.mean()]
stds   = [cv_pr.std(),  cv_rc.std(),  cv_f1.std(),  cv_ac.std()]
mc     = [ACCENT, GREEN, ORANGE, YELLOW]
xs     = np.arange(len(metrics_labels))
bars2  = ax6.bar(xs, means, color=mc, alpha=0.85, edgecolor=BORDER)
ax6.errorbar(xs, means, yerr=stds, fmt="none", color=TEXT, capsize=5, lw=2)
ax6.set_xticks(xs); ax6.set_xticklabels(metrics_labels)
ax6.set_title("CV Mean Metrics (+/- 1 std)", color=TEXT)
ax6.set_ylabel("Score")
ax6.set_ylim([0.90, 1.02])
ax6.spines[:].set_color(BORDER)
ax6.grid(True, axis="y", alpha=0.2)
for bar, val, std in zip(bars2, means, stds):
    ax6.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.001,
             f"{val:.4f}\n±{std:.4f}", ha="center", color=TEXT, fontsize=8)

plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "cv_results.png"), dpi=150, bbox_inches="tight", facecolor=DARK)
plt.close()
log("  Saved: outputs/cv_results.png")

# ── Save markdown report ──────────────────────────────────────────────────────
report_path = os.path.join(OUT_DIR, "model_evaluation_report.md")
with open(report_path, "w", encoding="utf-8") as f:
    f.write("\n".join(lines_report))
log(f"\n  Saved: outputs/model_evaluation_report.md")

log("\n" + "=" * 70)
log("  ALL EVALUATION FILES WRITTEN TO outputs/")
log("  Files:")
log("    model_evaluation_report.md  <- full text report")
log("    model_eval_charts.png       <- learning curve + feature importance")
log("    confusion_matrix.png        <- confusion matrix heatmap")
log("    roc_curve.png               <- ROC-AUC curve")
log("    cv_results.png              <- 5-fold CV bar charts")
log("    cv_fold_scores.csv          <- per-fold numeric scores")
log("    per_class_metrics.csv       <- precision/recall/f1 per class")
log("=" * 70)
