"""
Minimal MITRE ATT&CK (Enterprise) mapping.
Each synthetic alert TYPE is mapped to a technique ID/name/tactic so every
incident brief can cite ATT&CK coverage instead of a free-text label.
"""

# technique_id -> (name, tactic)
ATTACK_TECHNIQUES = {
    "T1110":       ("Brute Force",                          "Credential Access"),
    "T1078":       ("Valid Accounts (Impossible Travel)",    "Defense Evasion / Initial Access"),
    "T1059.001":   ("PowerShell",                            "Execution"),
    "T1053.005":   ("Scheduled Task",                        "Persistence"),
    "T1547.001":   ("Registry Run Keys / Startup Folder",    "Persistence"),
    "T1003.001":   ("LSASS Memory Access",                   "Credential Access"),
    "T1046":       ("Network Service Discovery",             "Discovery"),
    "T1071.001":   ("Web Protocols (C2 Beacon)",             "Command and Control"),
    "T1071.004":   ("DNS Tunneling",                         "Command and Control"),
    "T1486":       ("Data Encrypted for Impact",             "Impact"),
    "T1204.002":   ("Malicious File Execution",              "Execution"),
    "T1200":       ("Hardware Additions (USB)",              "Initial Access"),
    "T1531":       ("Account Access Removal (false alarm)",  "Impact"),
}

# Short, local ATT&CK knowledge base used by the grounded brief generator.
# Keeping this local makes the demo deterministic and usable without network
# access; teams can replace it with the official STIX/TAXII feed in production.
ATTACK_DESCRIPTIONS = {
    "T1110": "Repeated authentication failures may indicate password guessing or brute force.",
    "T1078": "Valid accounts or impossible-travel activity can indicate compromised credentials.",
    "T1059.001": "PowerShell execution is commonly used for scripted discovery, execution, and evasion.",
    "T1053.005": "Scheduled tasks can provide persistence or delayed execution.",
    "T1547.001": "Registry Run Keys can launch malware automatically at user logon.",
    "T1003.001": "LSASS memory access may expose password hashes or authentication secrets.",
    "T1046": "Network service discovery can identify reachable hosts and services for follow-on movement.",
    "T1071.001": "Web-protocol C2 can blend command traffic into ordinary HTTP or HTTPS traffic.",
    "T1071.004": "DNS tunneling can encode command or data traffic in DNS requests.",
    "T1486": "Data encrypted for impact is a common ransomware behavior.",
    "T1204.002": "User execution of a malicious file can begin payload execution.",
    "T1200": "An added hardware device may introduce removable-media risk.",
    "T1531": "Account access removal can disrupt users or be a false-positive policy event.",
}

# alert_type -> (technique_id, base_severity 1-10, false_positive_rate 0-1)
ALERT_TYPE_CATALOG = {
    "failed_logon_spike":       ("T1110",     6, 0.55),
    "impossible_travel_login":  ("T1078",     7, 0.35),
    "powershell_encoded_cmd":   ("T1059.001", 7, 0.40),
    "new_scheduled_task":       ("T1053.005", 5, 0.60),
    "registry_run_key_mod":     ("T1547.001", 5, 0.55),
    "lsass_access":             ("T1003.001", 9, 0.20),
    "port_scan_detected":       ("T1046",     4, 0.70),
    "c2_beacon_blocked":        ("T1071.001", 8, 0.30),
    "dns_tunneling_suspected":  ("T1071.004", 7, 0.45),
    "ransomware_note_created":  ("T1486",     10, 0.05),
    "av_signature_hit":         ("T1204.002", 3, 0.75),
    "usb_device_inserted":      ("T1200",     2, 0.85),
    "vpn_geo_anomaly":          ("T1078",     6, 0.50),
}


def technique_for(alert_type: str):
    tid, sev, fp_rate = ALERT_TYPE_CATALOG[alert_type]
    name, tactic = ATTACK_TECHNIQUES[tid]
    return {
        "technique_id": tid,
        "technique_name": name,
        "tactic": tactic,
        "base_severity": sev,
        "false_positive_rate": fp_rate,
    }
