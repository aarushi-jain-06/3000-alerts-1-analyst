"""Deterministic, auditable investigation tools for high-risk incidents.

This is an offline-safe investigator.  It records a tool trace now and can be
extended with CMDB, EDR, and threat-intelligence connectors later.
"""

from assets import ASSET_REGISTRY, asset_info


def check_asset_inventory(asset_ids):
    return [{"asset_id": aid, **asset_info(aid)} for aid in asset_ids]


def check_ip_reputation(ips):
    # No external reputation claims are made without a configured feed.
    return [{"ip": ip, "verdict": "UNKNOWN", "source": "offline-demo"} for ip in sorted(ips) if ip]


def get_recent_alerts_for_asset(incident):
    return [{"alert_id": a["alert_id"], "timestamp": a["timestamp"],
             "alert_type": a["alert_type"]} for a in incident.get("alerts", [])]


def investigate(incident, max_steps=5):
    """Run a bounded investigation and attach an audit-friendly trace."""
    if incident.get("risk_tier") not in {"CRITICAL", "HIGH"}:
        return []
    assets = incident.get("impacted_assets", incident.get("assets", [incident["asset_id"]]))
    ips = {a.get("src_ip") for a in incident.get("alerts", [])}
    ips.update(a.get("dst_ip") for a in incident.get("alerts", []))
    steps = [
        ("check_asset_inventory", check_asset_inventory(assets)),
        ("get_recent_alerts_for_asset", get_recent_alerts_for_asset(incident)),
        ("check_ip_reputation", check_ip_reputation(ips)),
    ][:max_steps]
    return [{"step": i + 1, "tool": name, "result": result} for i, (name, result) in enumerate(steps)]
