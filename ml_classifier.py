"""
ml_classifier.py — Trained ML inference layer.

Loads the model bundle saved by train_classifier.py (severity_model.pkl)
and exposes two functions:

  predict_malicious_proba(alert_features: dict) -> float   (0.0 – 1.0)
  is_available() -> bool

When the model isn't available (pkl not yet trained, file missing, etc.)
every call returns None and scoring.py falls back to the static FP-rate
table in mitre_map.py — the pipeline NEVER breaks mid-demo.
"""

import os
import pickle
import warnings
from typing import Optional, Dict, Any

import numpy as np

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "severity_model.pkl")

# ── Module-level singleton load ───────────────────────────────────────────────
_bundle: Optional[dict] = None


def _load_bundle() -> Optional[dict]:
    global _bundle
    if _bundle is not None:
        return _bundle
    if not os.path.exists(_MODEL_PATH):
        return None
    try:
        with open(_MODEL_PATH, "rb") as fh:
            _bundle = pickle.load(fh)
        print(f"[ml_classifier] Loaded {_bundle['name']} model  "
              f"(F1={_bundle['f1']:.4f}, "
              f"{len(_bundle['features'])} features)")
        return _bundle
    except Exception as e:
        warnings.warn(f"[ml_classifier] Failed to load model: {e}")
        return None


def is_available() -> bool:
    """Return True if the trained model is ready to use."""
    return _load_bundle() is not None


def predict_malicious_proba(alert: Dict[str, Any]) -> Optional[float]:
    """
    Given a single alert dict (as produced by alert_generator.py),
    return the model's estimated probability that it is malicious (0–1).

    The alert dict may not have raw CICIDS features — in that case we
    engineer proxy features from the fields we DO have.

    Returns None if the model isn't available (caller should fall back
    to 1 - false_positive_rate from mitre_map).
    """
    bundle = _load_bundle()
    if bundle is None:
        return None

    model   = bundle["model"]
    scaler  = bundle["scaler"]
    features = bundle["features"]

    # ── Proxy feature engineering from synthetic alert fields ──────────────
    # Our synthetic alerts don't have raw CICIDS network-flow columns.
    # We engineer plausible proxies from what we have: severity, tactic, FP rate.
    proxy = _engineer_proxy_features(alert, features)

    try:
        X = np.array([[proxy.get(f, 0.0) for f in features]])
        X_scaled = scaler.transform(X)
        proba = model.predict_proba(X_scaled)[0][1]  # P(malicious)
        return float(round(proba, 4))
    except Exception as e:
        warnings.warn(f"[ml_classifier] Prediction failed: {e}")
        return None


def predict_malicious_proba_batch(alerts: list) -> list:
    """
    Batch version — more efficient for whole incidents.
    Returns list of probabilities (or Nones).
    """
    bundle = _load_bundle()
    if bundle is None:
        return [None] * len(alerts)

    model    = bundle["model"]
    scaler   = bundle["scaler"]
    features = bundle["features"]

    rows = []
    for alert in alerts:
        proxy = _engineer_proxy_features(alert, features)
        rows.append([proxy.get(f, 0.0) for f in features])

    try:
        X = np.array(rows)
        X_scaled = scaler.transform(X)
        probas = model.predict_proba(X_scaled)[:, 1]
        return [float(round(p, 4)) for p in probas]
    except Exception as e:
        warnings.warn(f"[ml_classifier] Batch prediction failed: {e}")
        return [None] * len(alerts)


# ── Severity / tactic → proxy feature mapping ────────────────────────────────

# Maps MITRE tactic names to a numeric "threat stage" score (0-7)
TACTIC_STAGE = {
    "Initial Access":                 1,
    "Defense Evasion / Initial Access": 1,
    "Discovery":                      2,
    "Execution":                      3,
    "Persistence":                    4,
    "Credential Access":              5,
    "Command and Control":            6,
    "Impact":                         7,
}

def _engineer_proxy_features(alert: dict, feature_names: list) -> dict:
    """
    Map synthetic alert fields → proxy values for CICIDS feature columns.

    Strategy:
    - base_severity (1-10) drives packet-length and duration proxies
    - false_positive_rate drives IAT and flow-byte proxies inversely
      (low FP = more unusual = more bytes/pkts)
    - tactic stage drives a monotone "dangerousness" proxy
    """
    sev      = float(alert.get("base_severity", 5))
    fp_rate  = float(alert.get("false_positive_rate", 0.5))
    tactic   = alert.get("tactic", "")
    stage    = float(TACTIC_STAGE.get(tactic, 3))

    # Normalised danger proxy (0-1): weighted blend of severity + stage
    danger = (sev / 10.0) * 0.6 + (stage / 7.0) * 0.4
    # Maliciousness inversely related to FP rate
    malice = danger * (1.0 - fp_rate)

    # Map to CICIDS-style numeric columns with plausible ranges
    proxy = {
        # Flow duration (μs): benign flows short; malicious C2 can be very long
        "flow_duration":                   malice * 120_000_000,
        # Packet counts: attacks often burst
        "total_fwd_packets":               int(malice * 500 + 10),
        "total_backward_packets":          int(malice * 300 + 5),
        # Payload sizes: exfil / beaconing has larger payloads
        "total_length_of_fwd_packets":     malice * 500_000,
        "total_length_of_bwd_packets":     malice * 300_000,
        "fwd_packet_length_max":           malice * 1500,
        "fwd_packet_length_min":           malice * 20,
        "fwd_packet_length_mean":          malice * 800,
        "bwd_packet_length_max":           malice * 1500,
        "bwd_packet_length_min":           malice * 20,
        "bwd_packet_length_mean":          malice * 600,
        # Flow rates: high severity → higher bandwidth
        "flow_bytes_per_s":                malice * 1_000_000,
        "flow_packets_per_s":              malice * 5_000,
        # Inter-arrival times: beaconing has very regular IATs
        "flow_iat_mean":                   (1.0 - malice) * 500_000,
        "flow_iat_std":                    (1.0 - malice) * 200_000,
        "flow_iat_max":                    (1.0 - malice) * 2_000_000,
        "flow_iat_min":                    malice * 1_000,
        "fwd_iat_mean":                    (1.0 - malice) * 400_000,
        "bwd_iat_mean":                    (1.0 - malice) * 400_000,
        # Flags: PSH used in data transfer
        "fwd_psh_flags":                   int(malice * 5),
        "bwd_psh_flags":                   int(malice * 3),
        # Window sizes: attacks often use small windows
        "init_win_bytes_forward":          int((1.0 - malice) * 65535),
        "init_win_bytes_backward":         int((1.0 - malice) * 65535),
        "act_data_pkt_fwd":                int(malice * 200),
        # Aggregate sizes
        "average_packet_size":             malice * 900,
        "avg_fwd_segment_size":            malice * 800,
        "avg_bwd_segment_size":            malice * 600,
    }
    return proxy


def get_model_info() -> dict:
    """Return metadata about the loaded model (for dashboard display)."""
    bundle = _load_bundle()
    if bundle is None:
        return {"available": False, "model": None, "f1": None, "features": []}
    return {
        "available": True,
        "model": bundle["name"],
        "f1": bundle["f1"],
        "n_features": len(bundle["features"]),
        "features": bundle["features"],
    }


# ── CLI self-test ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Model available:", is_available())
    print("Model info:", get_model_info())

    # Test with a high-severity alert
    test_alert = {
        "alert_type": "ransomware_note_created",
        "base_severity": 10,
        "false_positive_rate": 0.05,
        "tactic": "Impact",
    }
    p = predict_malicious_proba(test_alert)
    print(f"Ransomware alert malicious proba: {p}")

    # Test with a low-severity alert
    test_alert2 = {
        "alert_type": "usb_device_inserted",
        "base_severity": 2,
        "false_positive_rate": 0.85,
        "tactic": "Initial Access",
    }
    p2 = predict_malicious_proba(test_alert2)
    print(f"USB insert alert malicious proba:  {p2}")
