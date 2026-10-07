"""
investigator.py - Timeline, Attack Path, and Investigation Trace Engine.

Reconstructs chronological timelines from incident telemetry, detects attack
trajectories across hosts and network hops, isolates affected entities,
and produces a structured, audit-ready investigation trace for summarization.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Union
from schemas import Alert, Incident


def _parse_ts(ts_str: str) -> datetime:
    """Safely parse ISO timestamp strings."""
    try:
        clean_ts = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean_ts)
    except Exception:
        return datetime.min


def build_timeline(incident: Union[Incident, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build a chronologically ordered list of events for the incident.
    
    Args:
        incident: Incident instance or dict with 'alerts'.
        
    Returns:
        List of chronological event dicts:
        [{timestamp, host, user, alert_type, severity, alert_id, evidence}]
    """
    raw_alerts = incident.alerts if isinstance(incident, Incident) else incident.get("alerts", [])

    events = []
    for a in raw_alerts:
        if isinstance(a, Alert):
            aid = a.alert_id
            ts = a.timestamp
            atype = a.alert_type
            sev = a.severity
            host = a.host
            user = a.user
            desc = a.description
        else:
            aid = a.get("alert_id", "UNKNOWN")
            ts = a.get("timestamp", "")
            atype = a.get("alert_type", "unknown")
            sev = a.get("severity", a.get("base_severity", 1))
            host = a.get("host", a.get("asset_id", "unknown"))
            user = a.get("user", "unknown")
            desc = a.get("description", "")

        events.append({
            "timestamp": ts,
            "host": host,
            "user": user,
            "alert_type": atype,
            "severity": sev,
            "alert_id": aid,
            "evidence": f"[{aid}] {atype} on {host} ({user}): {desc}",
        })

    # Sort strictly by timestamp
    events.sort(key=lambda x: _parse_ts(x["timestamp"]))
    return events


def detect_attack_path(incident: Union[Incident, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Detect the attack progression and identify affected assets, users, and IP indicators.
    
    Returns:
        Dict containing:
            - transitions: list of transition steps
            - path_summary: concise string representing attack hops
            - affected_assets: list of unique hosts
            - affected_users: list of unique usernames
            - src_ips: list of source IPs
            - dst_ips: list of destination IPs
            - pivot_points: hosts that served as internal launchpads
    """
    timeline = build_timeline(incident)
    raw_alerts = incident.alerts if isinstance(incident, Incident) else incident.get("alerts", [])

    affected_assets: Set[str] = set()
    affected_users: Set[str] = set()
    src_ips: Set[str] = set()
    dst_ips: Set[str] = set()
    transitions = []
    prev_host = None

    for evt in timeline:
        host = evt["host"]
        user = evt["user"]
        atype = evt["alert_type"]

        if host and host != "unknown":
            affected_assets.add(host)
        if user and user not in ("unknown", "", "None"):
            affected_users.add(user)

        step_desc = f"{host} ({atype})"
        if prev_host and prev_host != host:
            step_desc = f"LATERAL PIVOT: {prev_host} -> {host} via {atype}"
        transitions.append(step_desc)
        prev_host = host

    for a in raw_alerts:
        sip = a.src_ip if isinstance(a, Alert) else a.get("src_ip", "")
        dip = a.dst_ip if isinstance(a, Alert) else a.get("dst_ip", "")
        if sip:
            src_ips.add(sip)
        if dip:
            dst_ips.add(dip)

    path_summary = " -> ".join([f"{e['host']}:{e['alert_type']}" for e in timeline]) if timeline else "No events"

    return {
        "transitions": transitions,
        "path_summary": path_summary,
        "affected_assets": sorted(list(affected_assets)),
        "affected_users": sorted(list(affected_users)),
        "src_ips": sorted(list(src_ips)),
        "dst_ips": sorted(list(dst_ips)),
    }


def investigate(incident: Union[Incident, Dict[str, Any]], max_steps: int = 5) -> Dict[str, Any]:
    """
    Run investigation and return a comprehensive trace dict for the summarizer.
    
    Includes chronological timeline, detected attack path, network IOCs,
    and structured audit steps.
    """
    timeline = build_timeline(incident)
    path_info = detect_attack_path(incident)

    inc_id = incident.incident_id if isinstance(incident, Incident) else incident.get("incident_id", "INC-UNKNOWN")
    alert_ids = [e["alert_id"] for e in timeline]

    # Calculate duration
    duration_secs = 0.0
    if len(timeline) >= 2:
        t_start = _parse_ts(timeline[0]["timestamp"])
        t_end = _parse_ts(timeline[-1]["timestamp"])
        if t_start != datetime.min and t_end != datetime.min:
            duration_secs = max(0.0, (t_end - t_start).total_seconds())

    # Audit steps for SOAR / compliance logs
    steps = [
        {"step": 1, "tool": "build_timeline", "result": f"Parsed {len(timeline)} events chronologically"},
        {"step": 2, "tool": "detect_attack_path", "result": path_info["path_summary"]},
        {"step": 3, "tool": "entity_enumeration", "result": {
            "assets": path_info["affected_assets"],
            "users": path_info["affected_users"],
            "src_ips": path_info["src_ips"],
            "dst_ips": path_info["dst_ips"],
        }},
    ]

    return {
        "incident_id": inc_id,
        "timeline": timeline,
        "attack_path": path_info["path_summary"],
        "transitions": path_info["transitions"],
        "affected_assets": path_info["affected_assets"],
        "affected_users": path_info["affected_users"],
        "src_ips": path_info["src_ips"],
        "dst_ips": path_info["dst_ips"],
        "evidence_alert_ids": alert_ids,
        "start_time": timeline[0]["timestamp"] if timeline else "",
        "end_time": timeline[-1]["timestamp"] if timeline else "",
        "duration_seconds": duration_secs,
        "steps": steps[:max_steps],
    }


# Backward-compatibility helpers for teammate scripts if imported
def check_asset_inventory(asset_ids):
    try:
        from assets import asset_info
        return [{"asset_id": aid, **asset_info(aid)} for aid in asset_ids]
    except Exception:
        return [{"asset_id": aid, "type": "Host", "criticality": 3} for aid in asset_ids]


def check_ip_reputation(ips):
    return [{"ip": ip, "verdict": "UNKNOWN", "source": "offline-demo"} for ip in sorted(ips) if ip]


def get_recent_alerts_for_asset(incident):
    alerts = incident.alerts if isinstance(incident, Incident) else incident.get("alerts", [])
    res = []
    for a in alerts:
        aid = a.alert_id if isinstance(a, Alert) else a.get("alert_id")
        ts = a.timestamp if isinstance(a, Alert) else a.get("timestamp")
        atype = a.alert_type if isinstance(a, Alert) else a.get("alert_type")
        res.append({"alert_id": aid, "timestamp": ts, "alert_type": atype})
    return res
