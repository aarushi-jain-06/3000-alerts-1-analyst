# Data Contract: Alerts and Incidents

This document defines the interface contract between the upstream alert generator / grouping stages and downstream investigation, MITRE mapping, scoring, and summarization modules.

---

## 1. Alert Schema

Each incoming security alert MUST conform to the following specification:

| Field | Type | Allowed Values / Format | Description | Example |
| :--- | :--- | :--- | :--- | :--- |
| `alert_id` | `str` | Non-empty string | Unique identifier for the alert | `"ALT-2026-001"` |
| `timestamp` | `str` | ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`) | When the alert occurred | `"2026-10-07T08:15:00Z"` |
| `alert_type` | `str` | Standardized category identifier | High-level detection or alert class | `"brute_force"`, `"phishing"`, `"lateral_movement"` |
| `severity` | `int` | `1` to `5` | Alert severity (1: Info/Low, 5: Critical) | `4` |
| `host` | `str` | Non-empty string | Hostname, server name, or device ID | `"WKSTN-892"`, `"DC-01"` |
| `user` | `str` | String (or `"unknown"`) | User account or security principal | `"aditiverma"`, `"SYSTEM"` |
| `src_ip` | `str` | IPv4 / IPv6 string (or empty) | Originating network IP | `"198.51.100.24"` |
| `dst_ip` | `str` | IPv4 / IPv6 string (or empty) | Target network IP | `"10.0.1.15"` |
| `description` | `str` | Non-empty string | Telemetry summary / detection rationale | `"45 failed logon attempts followed by success"` |
| `asset_criticality` | `int` | `1` to `5` | Criticality of the affected asset (1: Dev/Lab, 5: Crown Jewel) | `5` |

### JSON Example: Alert
```json
{
  "alert_id": "ALT-1001",
  "timestamp": "2026-10-07T08:12:00Z",
  "alert_type": "brute_force",
  "severity": 3,
  "host": "AUTH-SRV-01",
  "user": "asmith",
  "src_ip": "198.51.100.44",
  "dst_ip": "10.0.1.5",
  "description": "50 consecutive Kerberos pre-auth failures for user asmith from external IP",
  "asset_criticality": 4
}
```

---

## 2. Incident Schema

The grouping engine bundles correlated alerts into an Incident:

| Field | Type | Description |
| :--- | :--- | :--- |
| `incident_id` | `str` | Unique incident cluster identifier (e.g. `"INC-2026-001"`) |
| `alerts` | `list[Alert]` | List of 1 or more `Alert` objects belonging to the incident |

### JSON Example: Incident
```json
{
  "incident_id": "INC-2026-001",
  "alerts": [
    {
      "alert_id": "ALT-1001",
      "timestamp": "2026-10-07T08:12:00Z",
      "alert_type": "brute_force",
      "severity": 3,
      "host": "AUTH-SRV-01",
      "user": "asmith",
      "src_ip": "198.51.100.44",
      "dst_ip": "10.0.1.5",
      "description": "50 consecutive Kerberos pre-auth failures for user asmith",
      "asset_criticality": 4
    },
    {
      "alert_id": "ALT-1002",
      "timestamp": "2026-10-07T08:18:00Z",
      "alert_type": "successful_login",
      "severity": 2,
      "host": "AUTH-SRV-01",
      "user": "asmith",
      "src_ip": "198.51.100.44",
      "dst_ip": "10.0.1.5",
      "description": "Logon success for user asmith after multiple failed attempts",
      "asset_criticality": 4
    },
    {
      "alert_id": "ALT-1003",
      "timestamp": "2026-10-07T08:24:00Z",
      "alert_type": "lateral_movement",
      "severity": 5,
      "host": "DC-01",
      "user": "asmith",
      "src_ip": "10.0.1.5",
      "dst_ip": "10.0.0.1",
      "description": "PsExec execution and SMB session created on DC-01 using compromised account asmith",
      "asset_criticality": 5
    }
  ]
}
```

---

## 3. Standard Alert Types Supported

| Alert Type | MITRE Technique | Tactic | Stage Order | Meaning |
| :--- | :--- | :--- | :---: | :--- |
| `brute_force` | T1110 | Credential Access | 2 | Multiple repeated authentication failures attempting password guessing or credential stuffing against an account. |
| `failed_logon_spike` | T1110 | Credential Access | 2 | Rapid anomalous burst of failed authentication attempts across one or more user accounts. |
| `phishing` | T1566 | Initial Access | 1 | Deceptive email message received attempting social engineering or credential harvesting. |
| `phishing_attachment` | T1566 | Initial Access | 1 | Malicious email attachment delivered to a user to execute initial payload upon opening. |
| `malware_execution` | T1204.002 | Execution | 4 | Malicious file or binary launched and executing on the target endpoint. |
| `powershell_encoded_cmd` | T1059.001 | Execution | 4 | Obfuscated or base64-encoded PowerShell process execution indicating stealth command running. |
| `successful_login` | T1078 | Initial Access | 3 | Valid authentication logon event, treated as attack step only when preceded by brute force on same user/host. |
| `impossible_travel_login` | T1078 | Initial Access | 3 | User account authentication from geographically distant locations within an impossible timeframe. |
| `vpn_geo_anomaly` | T1078 | Initial Access | 3 | Unusual remote VPN connection originating from an uncharacteristic foreign IP/region. |
| `privilege_escalation` | T1548 / T1068 | Privilege Escalation | 5 | Unauthorized elevation of user rights via token/control abuse (T1548) or exploit payload (T1068). |
| `lsass_access` | T1003.001 | Credential Access | 2 | Direct process memory read of LSASS to harvest plaintext credentials or authentication hashes. |
| `lateral_movement` | T1021.002 | Lateral Movement | 6 | Remote execution or administrative share access (e.g. SMB/PsExec) across internal enterprise hosts. |
| `c2_beaconing` | T1071.001 | Command and Control | 7 | Regular periodic outbound network traffic with jitter to external command-and-control infrastructure. |
| `c2_beacon_blocked` | T1071.001 | Command and Control | 7 | Gateway/firewall interception of periodic outbound connection to known malicious C2 domain or IP. |
| `dns_tunneling_suspected` | T1071.004 | Command and Control | 7 | Encoded or anomalous high-volume DNS requests used to tunnel commands or bypass network boundary inspection. |
| `data_exfiltration` | T1041 | Exfiltration | 8 | Bulk unauthorized extraction or egress transfer of sensitive internal data over external channels. |
| `exfiltration` | T1041 | Exfiltration | 8 | General outbound unauthorized data transfer or archive staging to an untrusted external destination. |
| `ransomware_note_created` | T1486 | Impact | 9 | Mass file encryption accompanied by the dropping of an extortion/ransomware instruction file. |
| `new_scheduled_task` | T1053.005 | Persistence | 4 | Creation of a Windows scheduled task or cron job to maintain persistent execution upon reboot. |
| `registry_run_key_mod` | T1547.001 | Persistence | 4 | Modification of registry Run/RunOnce keys or startup folders to achieve persistent execution. |
| `port_scan` | T1046 | Discovery | 2 | Network reconnaissance probing multiple ports on one or more hosts to discover open services. |
| `port_scan_detected` | T1046 | Discovery | 2 | Detection of systematic port scanning and network service enumeration across subnet assets. |
| `av_signature_hit` | T1204.002 | Execution | 4 | Antivirus or EDR detection of a known malicious signature or script on disk. |
| `usb_device_inserted` | T1200 | Initial Access | 1 | Rogue or unrecognized physical USB hardware/storage drive connected to an endpoint. |
| `authorized_usb` | None | None | - | Verified and approved corporate USB peripheral or whitelisted storage device connection (benign event). |

> **Note on USB Alerts:** `usb_device_inserted` maps to T1200 only if the description does not say authorized/approved; otherwise it maps to no technique (marked benign and cannot raise risk score).

Unrecognized or newly introduced `alert_type` strings will still be processed, flagged with `needs_human_review = True`, and evaluated gracefully.
