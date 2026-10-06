"""Feedback-loop utilities.

Analyst labels are persisted by ``human_loop``.  Once enough labels exist,
this module records a retraining-ready checkpoint.  A production deployment
can replace the conservative calibration step with a full model retrain on
raw alert features; synthetic incident labels alone must not be treated as
network-flow training data.
"""

import csv
import os
import pickle
from datetime import datetime, timezone


def feedback_summary(path="feedback_log.csv"):
    if not os.path.exists(path):
        return {"samples": 0, "true_positive": 0, "false_positive": 0, "escalated": 0}
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return {"samples": len(rows),
            "true_positive": sum(r.get("disposition") == "TRUE_POSITIVE" for r in rows),
            "false_positive": sum(r.get("disposition") == "FALSE_POSITIVE" for r in rows),
            "escalated": sum(r.get("disposition") == "ESCALATED" for r in rows)}


def retrain_if_ready(threshold=20, feedback_path="feedback_log.csv", history_path="retrain_history.csv"):
    summary = feedback_summary(feedback_path)
    if summary["samples"] < threshold:
        return {"ready": False, **summary}
    # Train an incident-level calibration model on analyst labels.  This is
    # intentionally separate from the CICIDS flow model because feedback rows
    # do not contain raw network-flow features.
    model_path = None
    try:
        import pandas as pd
        from sklearn.linear_model import LogisticRegression
        frame = pd.read_csv(feedback_path)
        frame = frame[frame["disposition"].isin(["TRUE_POSITIVE", "FALSE_POSITIVE"])]
        if len(frame) >= threshold and frame["disposition"].nunique() == 2:
            features = frame[["risk_score"]].astype(float)
            labels = (frame["disposition"] == "TRUE_POSITIVE").astype(int)
            model = LogisticRegression(random_state=42).fit(features, labels)
            model_path = os.path.join(os.path.dirname(history_path) or ".", "feedback_calibrator.pkl")
            with open(model_path, "wb") as fh:
                pickle.dump({"model": model, "features": ["risk_score"]}, fh)
    except Exception:
        model_path = None

    # Record a checkpoint and validation status.
    exists = os.path.exists(history_path)
    with open(history_path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["timestamp", "model", "n_train_samples", "f1_score", "source"])
        if not exists:
            writer.writeheader()
        writer.writerow({"timestamp": datetime.now(timezone.utc).isoformat(),
                         "model": "incident-feedback-calibrator", "n_train_samples": summary["samples"],
                         "f1_score": "trained" if model_path else "pending_validation", "source": feedback_path})
    return {"ready": True, **summary}
