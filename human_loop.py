"""
Human-in-the-loop layer.

The pipeline NEVER auto-closes or auto-remediates anything above LOW risk.
It only ever produces a ranked, briefed queue for a human analyst to
disposition. This module models that queue and the disposition action an
analyst takes, so the audit trail (who closed what, when, why) exists --
a hard requirement for MSSP compliance (SOC 2 / ISO 27001 change logs).
"""

from datetime import datetime, timezone
import csv
import os

VALID_DISPOSITIONS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "ESCALATED", "MERGE", "PENDING"}

AUTO_CLOSE_ELIGIBLE_TIERS = {"LOW"}  # only LOW-risk, high-FP-rate clusters
# even then: auto-close SUGGESTS, a human still confirms via review_queue export.


def build_review_queue(scored_incidents):
    queue = []
    for inc in scored_incidents:
        auto_suggest_close = (
            inc["risk_tier"] in AUTO_CLOSE_ELIGIBLE_TIERS
            and inc["confidence"] < 0.35  # i.e. false-positive rate > 65%
        )
        queue.append({
            "incident_id": inc["incident_id"],
            "risk_tier": inc["risk_tier"],
            "risk_score": inc["risk_score"],
            "asset_id": inc["asset_id"],
            "disposition": "PENDING",
            "auto_suggested_disposition": (
                "FALSE_POSITIVE" if auto_suggest_close else None
            ),
            "reviewed_by": None,
            "reviewed_at": None,
            "notes": None,
        })
    return queue


def apply_disposition(queue, incident_id, disposition, analyst, notes=""):
    if disposition not in VALID_DISPOSITIONS:
        raise ValueError(f"Invalid disposition: {disposition}")
    for item in queue:
        if item["incident_id"] == incident_id:
            item["disposition"] = disposition
            item["reviewed_by"] = analyst
            item["reviewed_at"] = datetime.now(timezone.utc).isoformat()
            item["notes"] = notes
            _append_feedback(item, analyst, notes)
            return item
    raise KeyError(f"Incident {incident_id} not found in queue")


def _append_feedback(item, analyst, notes):
    path = os.environ.get("FEEDBACK_LOG_PATH", os.path.join(os.path.dirname(__file__), "feedback_log.csv"))
    fields = ["timestamp", "incident_id", "risk_tier", "risk_score", "asset_id",
              "disposition", "analyst", "notes"]
    exists = os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        if not exists:
            writer.writeheader()
        writer.writerow({"timestamp": item["reviewed_at"], "incident_id": item["incident_id"],
                         "risk_tier": item["risk_tier"], "risk_score": item["risk_score"],
                         "asset_id": item["asset_id"], "disposition": item["disposition"],
                         "analyst": analyst, "notes": notes})


def merge_incidents(first, second):
    """Merge two incidents and return a fresh re-scored incident."""
    from scoring import score_incident, risk_tier
    alerts = sorted(first.get("alerts", []) + second.get("alerts", []),
                    key=lambda a: a["timestamp"])
    assets = sorted(set(first.get("assets", [first["asset_id"]]) +
                        second.get("assets", [second["asset_id"]])))
    candidate = {
        "incident_id": f"INC-MERGED-{first['incident_id']}-{second['incident_id']}",
        "asset_id": first["asset_id"], "assets": assets, "alerts": alerts,
        "alert_ids": [a["alert_id"] for a in alerts], "alert_count": len(alerts),
        "start_time": alerts[0]["timestamp"], "end_time": alerts[-1]["timestamp"],
        "techniques": sorted({a["technique_id"] for a in alerts}),
        "tactics": sorted({a["tactic"] for a in alerts}),
        "correlation_method": "analyst_merge",
    }
    result = score_incident(candidate)
    result["risk_tier"] = risk_tier(result["risk_score"])
    return result
