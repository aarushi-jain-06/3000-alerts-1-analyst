"""
mitre_map.py - MITRE ATT&CK (Enterprise) Mapping Engine.

Maps individual security alerts to MITRE ATT&CK tactics and techniques,
aggregates incident-level kill-chain stages in chronological attack order,
and flags uncertain or unmapped events for human review.
"""

from typing import Any, Dict, List, Optional, Union
from schemas import Alert, Incident

# MITRE Tactics canonical sequence (Enterprise Matrix Kill Chain)
TACTIC_CATALOG = {
    "Initial Access":        {"id": "TA0001", "stage_order": 1},
    "Execution":             {"id": "TA0002", "stage_order": 2},
    "Discovery":             {"id": "TA0007", "stage_order": 3},
    "Persistence":           {"id": "TA0003", "stage_order": 4},
    "Privilege Escalation":  {"id": "TA0004", "stage_order": 5},
    "Defense Evasion":       {"id": "TA0005", "stage_order": 6},
    "Credential Access":     {"id": "TA0006", "stage_order": 7},
    "Lateral Movement":      {"id": "TA0008", "stage_order": 8},
    "Collection":            {"id": "TA0009", "stage_order": 9},
    "Command and Control":   {"id": "TA0011", "stage_order": 10},
    "Exfiltration":          {"id": "TA0010", "stage_order": 11},
    "Impact":                {"id": "TA0040", "stage_order": 12},
    # Secondary / composite mappings
    "Defense Evasion / Initial Access": {"id": "TA0005", "stage_order": 6},
    "Unknown":               {"id": "TA0000", "stage_order": 99},
}

# Granular kill-chain stage order for alert types and techniques:
# - brute_force before successful_login
# - port_scan and port_scan_detected after initial access and execution
# - lsass_access after execution and privilege escalation but before lateral_movement
STAGE_ORDER = {
    # 1. Pre-attack / Credential Guessing (brute_force before successful_login)
    "brute_force": 1,
    "failed_logon_spike": 1,
    "T1110": 1,
    # 2. Access / Valid accounts
    "successful_login": 2,
    "impossible_travel_login": 2,
    "vpn_geo_anomaly": 2,
    "phishing": 2,
    "phishing_attachment": 2,
    "usb_device_inserted": 2,
    "T1078": 2,
    "T1566": 2,
    "T1200": 2,
    # 3. Execution
    "malware_execution": 3,
    "powershell_encoded_cmd": 3,
    "av_signature_hit": 3,
    "T1204": 3,
    "T1204.002": 3,
    "T1059.001": 3,
    # 4. Discovery (port_scan & port_scan_detected after initial access and execution)
    "port_scan": 4,
    "port_scan_detected": 4,
    "T1046": 4,
    # 5. Persistence
    "new_scheduled_task": 5,
    "registry_run_key_mod": 5,
    "T1053.005": 5,
    "T1547.001": 5,
    # 6. Privilege Escalation
    "privilege_escalation": 6,
    "T1548": 6,
    "T1068": 6,
    # 7. Post-escalation Credential Access (lsass_access after execution & privilege escalation, before lateral_movement)
    "lsass_access": 7,
    "T1003.001": 7,
    # 8. Lateral Movement
    "lateral_movement": 8,
    "T1021": 8,
    "T1021.002": 8,
    # 9. Command and Control
    "c2_beaconing": 9,
    "c2_beacon_blocked": 9,
    "dns_tunneling_suspected": 9,
    "T1071": 9,
    "T1071.001": 9,
    "T1071.004": 9,
    # 10. Exfiltration
    "data_exfiltration": 10,
    "exfiltration": 10,
    "T1041": 10,
    # 11. Impact
    "ransomware_note_created": 11,
    "T1486": 11,
    "T1531": 11,
}


def stage_order(item: str) -> int:
    """Return stage order integer for an alert_type, technique_id, or tactic."""
    clean = str(item).strip()
    if clean in STAGE_ORDER:
        return STAGE_ORDER[clean]
    if clean.lower() in STAGE_ORDER:
        return STAGE_ORDER[clean.lower()]
    if clean in TACTIC_CATALOG:
        return TACTIC_CATALOG[clean]["stage_order"]
    return 99

# technique_id -> (name, tactic)
ATTACK_TECHNIQUES = {
    "T1110":       ("Brute Force",                           "Credential Access"),
    "T1078":       ("Valid Accounts",                        "Initial Access"),
    "T1566":       ("Phishing",                              "Initial Access"),
    "T1204":       ("User Execution",                        "Execution"),
    "T1204.002":   ("Malicious File Execution",               "Execution"),
    "T1059.001":   ("PowerShell",                             "Execution"),
    "T1068":       ("Exploitation for Privilege Escalation",  "Privilege Escalation"),
    "T1548":       ("Abuse Elevation Control Mechanism",     "Privilege Escalation"),
    "T1003.001":   ("LSASS Memory Access",                    "Credential Access"),
    "T1021":       ("Remote Services (Lateral Movement)",    "Lateral Movement"),
    "T1021.002":   ("SMB/Windows Admin Shares",              "Lateral Movement"),
    "T1071":       ("Application Layer Protocol",            "Command and Control"),
    "T1071.001":   ("Web Protocols (C2 Beacon)",              "Command and Control"),
    "T1071.004":   ("DNS Tunneling",                          "Command and Control"),
    "T1041":       ("Exfiltration Over C2 Channel",           "Exfiltration"),
    "T1046":       ("Network Service Discovery",              "Discovery"),
    "T1053.005":   ("Scheduled Task",                         "Persistence"),
    "T1547.001":   ("Registry Run Keys / Startup Folder",     "Persistence"),
    "T1486":       ("Data Encrypted for Impact",              "Impact"),
    "T1200":       ("Hardware Additions (USB)",               "Initial Access"),
    "T1531":       ("Account Access Removal",                 "Impact"),
}

# Short descriptive summaries for local retrieval / RAG
ATTACK_DESCRIPTIONS = {
    "T1110": "Adversaries may use brute force techniques to attempt password guessing, password spraying, or credential stuffing to gain access.",
    "T1078": "Adversaries may obtain and abuse credentials of existing accounts to gain Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
    "T1566": "Adversaries may send phishing messages with malicious attachments or links to gain execution on victim systems.",
    "T1204": "Adversaries may rely upon specific actions by a user, such as opening an email attachment or clicking a link, to execute malware.",
    "T1204.002": "Adversaries may trick a user into running a malicious file payload disguised as legitimate documents.",
    "T1059.001": "PowerShell execution is abused by adversaries to execute code, run download cradles, and manipulate system configuration.",
    "T1068": "Adversaries may exploit vulnerabilities to elevate privileges from standard user to SYSTEM, root, or Administrator.",
    "T1548": "Adversaries may circumvent mechanisms designed to control elevate privileges to run with higher permissions.",
    "T1003.001": "Adversaries may attempt to access credential material stored in the Local Security Authority Subsystem Service (LSASS) process memory.",
    "T1021": "Adversaries may use valid credentials or exploits to log onto remote systems within the enterprise network and move laterally.",
    "T1021.002": "Adversaries may use SMB and administrative shares (e.g. ADMIN$) with PsExec or similar tools to execute commands remotely.",
    "T1071": "Adversaries may communicate using application layer protocols to blend Command and Control traffic with normal network operations.",
    "T1071.001": "Web protocols like HTTP and HTTPS are commonly used for periodic C2 beaconing to external attacker-controlled infrastructure.",
    "T1071.004": "DNS tunneling encodes commands and exfiltrated payloads inside DNS queries to bypass network firewalls.",
    "T1041": "Adversaries may steal and exfiltrate sensitive data over existing command and control channels or dedicated protocols.",
    "T1046": "Adversaries may attempt to get a listing of services running on remote hosts to find vulnerable targets for follow-on actions.",
    "T1053.005": "Adversaries may abuse the Windows Task Scheduler to execute programs at specific dates or recurrent times for persistence.",
    "T1547.001": "Adversaries may modify registry run keys to maintain persistence upon user logon.",
    "T1486": "Adversaries may encrypt data on target systems to interrupt availability and extort ransom payments.",
    "T1200": "Adversaries may introduce rogue hardware or USB drives into systems to bridge air gaps or deliver payloads.",
    "T1531": "Adversaries may delete or modify accounts to interrupt user access or cause administrative disruption.",
}

# Catalog mapping alert_type -> (technique_id, base_severity 1-10, false_positive_rate 0-1, confidence 0-1)
ALERT_TYPE_CATALOG = {
    # Core Hackathon requirements
    "brute_force":              ("T1110",     6, 0.40, 0.95),
    "failed_logon_spike":       ("T1110",     6, 0.55, 0.90),
    "phishing":                 ("T1566",     7, 0.30, 0.95),
    "phishing_attachment":      ("T1566",     7, 0.25, 0.95),
    "malware_execution":        ("T1204.002", 8, 0.20, 0.95),
    "powershell_encoded_cmd":   ("T1059.001", 7, 0.40, 0.90),
    "successful_login":         ("T1078",     5, 0.45, 0.40),
    "impossible_travel_login":  ("T1078",     7, 0.35, 0.90),
    "vpn_geo_anomaly":          ("T1078",     6, 0.50, 0.80),
    "privilege_escalation":     ("T1548",     8, 0.15, 0.90),
    "lsass_access":             ("T1003.001", 9, 0.20, 0.95),
    "lateral_movement":         ("T1021.002", 8, 0.15, 0.95),
    "c2_beaconing":             ("T1071.001", 8, 0.25, 0.90),
    "c2_beacon_blocked":        ("T1071.001", 8, 0.30, 0.50),
    "dns_tunneling_suspected":  ("T1071.004", 7, 0.45, 0.85),
    "data_exfiltration":        ("T1041",     9, 0.10, 0.95),
    "exfiltration":             ("T1041",     9, 0.10, 0.95),
    "ransomware_note_created":  ("T1486",    10, 0.05, 0.98),
    "new_scheduled_task":       ("T1053.005", 5, 0.60, 0.80),
    "registry_run_key_mod":     ("T1547.001", 5, 0.55, 0.80),
    "port_scan":                ("T1046",     4, 0.70, 0.90),
    "port_scan_detected":       ("T1046",     4, 0.70, 0.90),
    "av_signature_hit":         ("T1204.002", 4, 0.75, 0.50),
    "usb_device_inserted":      ("T1200",     2, 0.85, 0.60),
}


def technique_for(alert_type: str) -> Dict[str, Any]:
    """Backward compatibility helper for existing codebase callers."""
    if alert_type in ("authorized_usb", "authorized_usb_device", "authorized_usb_inserted"):
        return {
            "technique_id": None,
            "technique_name": "None",
            "tactic": "None",
            "base_severity": 1,
            "false_positive_rate": 0.95,
        }
    entry = ALERT_TYPE_CATALOG.get(alert_type)
    if entry:
        tid = entry[0]
        sev = entry[1]
        fp_rate = entry[2]
        if tid is None:
            name, tactic = ("None", "None")
        else:
            name, tactic = ATTACK_TECHNIQUES.get(tid, ("Unknown Technique", "Unknown"))
    else:
        tid = "T0000"
        sev = 3
        fp_rate = 0.50
        name, tactic = ("Unmapped Technique", "Unknown")
    return {
        "technique_id": tid,
        "technique_name": name,
        "tactic": tactic,
        "base_severity": sev,
        "false_positive_rate": fp_rate,
    }


def map_alert(alert: Union[Alert, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Map an individual alert to its MITRE ATT&CK technique and tactic.
    
    Args:
        alert: Alert instance or dictionary with 'alert_type'.
        
    Returns:
        List of dicts: [{tactic, tactic_id, technique, technique_id, confidence, needs_human_review, is_benign (optional)}]
    """
    if isinstance(alert, Alert):
        alert_type = alert.alert_type or "unknown"
        desc = alert.description or ""
    elif isinstance(alert, dict):
        alert_type = alert.get("alert_type", "unknown") or "unknown"
        desc = alert.get("description", "") or ""
    else:
        alert_type = str(alert)
        desc = ""

    alert_type_key = alert_type.lower().strip()
    desc_lower = desc.lower()

    # Rule 3: Authorized USB check -> maps to NO technique, marked benign
    is_auth_usb = (
        alert_type_key in ("authorized_usb", "authorized_usb_device", "authorized_usb_inserted")
        or ("usb" in alert_type_key and any(w in desc_lower for w in ["authoriz", "approv", "whitelist", "benign", "standard peripheral", "mouse", "keyboard"]))
        or any(w in desc_lower for w in ["authorized usb", "approved usb", "whitelisted usb"])
    )
    if is_auth_usb:
        return [{
            "tactic": "None",
            "tactic_id": "TA0000",
            "technique": "None",
            "technique_id": None,
            "confidence": 0.95,
            "needs_human_review": False,
            "is_benign": True,
        }]

    # Rule 2: privilege_escalation check for exploit vs elevation control mechanism abuse
    if alert_type_key == "privilege_escalation":
        exploit_keywords = ["exploit", "cve", "vulnerability", "buffer overflow", "heap corruption", "zero-day", "0-day"]
        if any(k in desc_lower for k in exploit_keywords):
            tid = "T1068"
        else:
            tid = "T1548"
        tech_name, tactic_name = ATTACK_TECHNIQUES[tid]
        tactic_meta = TACTIC_CATALOG.get(tactic_name, {"id": "TA0004", "stage_order": 4})
        return [{
            "tactic": tactic_name,
            "tactic_id": tactic_meta["id"],
            "technique": tech_name,
            "technique_id": tid,
            "confidence": 0.90,
            "needs_human_review": False,
        }]

    # Rule 1: successful_login mapped to T1078 with LOW confidence (0.40) and needs_human_review=True in isolation
    if alert_type_key == "successful_login":
        tech_name, tactic_name = ATTACK_TECHNIQUES["T1078"]
        tactic_meta = TACTIC_CATALOG.get(tactic_name, {"id": "TA0001", "stage_order": 1})
        return [{
            "tactic": tactic_name,
            "tactic_id": tactic_meta["id"],
            "technique": tech_name,
            "technique_id": "T1078",
            "confidence": 0.40,
            "needs_human_review": True,
        }]

    # Rule 4 & Catalog lookup
    if alert_type_key in ALERT_TYPE_CATALOG:
        catalog_entry = ALERT_TYPE_CATALOG[alert_type_key]
        tid = catalog_entry[0]
        confidence = catalog_entry[3] if len(catalog_entry) > 3 else 0.90
        if tid is None:
            return [{
                "tactic": "None",
                "tactic_id": "TA0000",
                "technique": "None",
                "technique_id": None,
                "confidence": round(confidence, 2),
                "needs_human_review": False,
                "is_benign": True,
            }]
        tech_name, tactic_name = ATTACK_TECHNIQUES.get(tid, ("Unknown Technique", "Unknown"))
        tactic_meta = TACTIC_CATALOG.get(tactic_name, {"id": "TA0000", "stage_order": 99})
        tactic_id = tactic_meta["id"]
        needs_review = confidence < 0.70
        return [{
            "tactic": tactic_name,
            "tactic_id": tactic_id,
            "technique": tech_name,
            "technique_id": tid,
            "confidence": round(confidence, 2),
            "needs_human_review": needs_review,
        }]

    # Fallback heuristic for unmapped alert types
    inferred_tactic = "Unknown"
    inferred_tactic_id = "TA0000"
    inferred_tech = "Unmapped Technique"
    inferred_tid = "T0000"
    confidence = 0.30

    desc_lower_combined = (alert_type_key + " " + desc).lower()
    if any(k in desc_lower_combined for k in ["logon", "login", "auth", "brute", "password"]):
        inferred_tactic = "Credential Access"
        inferred_tactic_id = "TA0006"
        inferred_tech = "Credential Access Attempt"
        inferred_tid = "T1110"
        confidence = 0.60
    elif any(k in desc_lower_combined for k in ["phish", "email", "attachment", "mail"]):
        inferred_tactic = "Initial Access"
        inferred_tactic_id = "TA0001"
        inferred_tech = "Phishing Activity"
        inferred_tid = "T1566"
        confidence = 0.60
    elif any(k in desc_lower_combined for k in ["beacon", "c2", "command and control", "dns tunnel"]):
        inferred_tactic = "Command and Control"
        inferred_tactic_id = "TA0011"
        inferred_tech = "Application Layer Protocol"
        inferred_tid = "T1071"
        confidence = 0.60
    elif any(k in desc_lower_combined for k in ["exfil", "upload", "leak", "streamed"]):
        inferred_tactic = "Exfiltration"
        inferred_tactic_id = "TA0010"
        inferred_tech = "Data Exfiltration"
        inferred_tid = "T1041"
        confidence = 0.60
    elif any(k in desc_lower_combined for k in ["lateral", "psexec", "smb", "remote service"]):
        inferred_tactic = "Lateral Movement"
        inferred_tactic_id = "TA0008"
        inferred_tech = "Remote Services"
        inferred_tid = "T1021"
        confidence = 0.60
    elif any(k in desc_lower_combined for k in ["elevat", "privilege", "token", "root", "system"]):
        inferred_tactic = "Privilege Escalation"
        inferred_tactic_id = "TA0004"
        inferred_tech = "Privilege Escalation"
        inferred_tid = "T1548"
        confidence = 0.60

    return [{
        "tactic": inferred_tactic,
        "tactic_id": inferred_tactic_id,
        "technique": inferred_tech,
        "technique_id": inferred_tid,
        "confidence": round(confidence, 2),
        "needs_human_review": True,
    }]


def map_incident(incident: Union[Incident, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Map an entire incident's alerts to MITRE ATT&CK, aggregate unique
    techniques and tactics, sort them in chronological kill-chain order,
    and detect if any alert requires human review.
    
    Args:
        incident: Incident instance or dict.
        
    Returns:
        Dict containing:
            - tactics: list of sorted tactic names
            - tactic_details: list of dicts {tactic, tactic_id, stage_order}
            - techniques: list of unique technique IDs
            - technique_details: list of dicts {technique_id, technique_name, tactic}
            - mappings: per-alert mappings
            - needs_human_review: bool
            - review_reasons: list of reasons if review is needed
    """
    alerts = incident.alerts if isinstance(incident, Incident) else incident.get("alerts", [])

    def _get_ts(a: Any) -> str:
        if isinstance(a, Alert):
            return a.timestamp or ""
        return str(a.get("timestamp", "") or "")

    def _get_user_host(a: Any) -> tuple:
        if isinstance(a, Alert):
            u = (a.user or "").strip()
            h = (a.host or "").strip()
        else:
            u = str(a.get("user", "") or "").strip()
            h = str(a.get("host", a.get("asset_id", "")) or "").strip()
        return u, h

    def _get_aid_type(a: Any) -> tuple:
        if isinstance(a, Alert):
            return a.alert_id or "unknown", (a.alert_type or "unknown").lower().strip()
        return a.get("alert_id", "unknown"), str(a.get("alert_type", "unknown")).lower().strip()

    # Sort alerts chronologically
    sorted_alerts = sorted(alerts, key=lambda a: _get_ts(a))

    all_mappings = []
    seen_tactics = {}
    seen_techniques = {}
    review_reasons = []

    # Track preceding brute force attempts (user, host)
    seen_brute_force_targets = []

    for alert in sorted_alerts:
        aid, atype = _get_aid_type(alert)
        u, h = _get_user_host(alert)
        alert_mappings = map_alert(alert)

        for m in alert_mappings:
            mapping_entry = {"alert_id": aid, **m}

            # Rule 1: successful_login correlation check
            if atype == "successful_login":
                # Check if preceded by a brute force for same user or same host
                preceded_by_bf = any(
                    (bf_u and bf_u == u) or (bf_h and bf_h == h)
                    for (bf_u, bf_h) in seen_brute_force_targets
                )
                if preceded_by_bf:
                    # Treat as confirmed attack step
                    mapping_entry["needs_human_review"] = False
                    mapping_entry["attack_step"] = True
                else:
                    # Do not treat as attack step; flag for human review
                    mapping_entry["needs_human_review"] = True
                    mapping_entry["attack_step"] = False
                    review_reasons.append(
                        f"Alert {aid} ('successful_login') for user '{u}' on host '{h}' is not preceded by a brute force attempt - unverified logon requires human review."
                    )

            # Record brute force alerts for subsequent checks
            if atype in ("brute_force", "failed_logon_spike"):
                seen_brute_force_targets.append((u, h))

            all_mappings.append(mapping_entry)

            # Benign / None technique alerts (e.g. Authorized USB) map to NO technique and are not attack steps
            if mapping_entry.get("is_benign") or mapping_entry.get("technique_id") is None:
                continue

            # If successful_login is NOT an attack step, do NOT add to incident attack techniques/tactics
            if atype == "successful_login" and not mapping_entry.get("attack_step"):
                continue

            tactic = mapping_entry["tactic"]
            tactic_id = mapping_entry["tactic_id"]
            if tactic not in seen_tactics and tactic not in ("None", "Unknown"):
                order = TACTIC_CATALOG.get(tactic, {}).get("stage_order", 99)
                seen_tactics[tactic] = {"tactic": tactic, "tactic_id": tactic_id, "stage_order": order}

            tid = mapping_entry["technique_id"]
            if tid and tid not in seen_techniques:
                seen_techniques[tid] = {
                    "technique_id": tid,
                    "technique_name": mapping_entry["technique"],
                    "tactic": tactic,
                }

            if mapping_entry.get("needs_human_review") and atype != "successful_login":
                review_reasons.append(
                    f"Alert {aid} ('{atype}') has low mapping confidence ({mapping_entry['confidence']}) or unverified technique."
                )

    # Sort tactics by kill chain order
    sorted_tactics = sorted(seen_tactics.values(), key=lambda t: t["stage_order"])
    ordered_tactic_names = [t["tactic"] for t in sorted_tactics]

    # Collect technique IDs ordered by granular stage order
    technique_ids = sorted(seen_techniques.keys(), key=lambda tid: stage_order(tid))
    sorted_technique_details = sorted(seen_techniques.values(), key=lambda t: stage_order(t["technique_id"]))

    needs_review = len(review_reasons) > 0

    return {
        "tactics": ordered_tactic_names,
        "tactic_details": sorted_tactics,
        "techniques": technique_ids,
        "technique_details": sorted_technique_details,
        "mappings": all_mappings,
        "needs_human_review": needs_review,
        "review_reasons": review_reasons,
    }
