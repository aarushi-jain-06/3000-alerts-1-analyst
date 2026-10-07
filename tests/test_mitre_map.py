"""
Unit tests for mitre_map.py (MITRE ATT&CK Mapping).
"""

from schemas import Alert, Incident
from mitre_map import map_alert, map_incident, technique_for


def test_map_all_sample_alert_types():
    expected_mappings = {
        "brute_force": ("T1110", "Credential Access"),
        "phishing": ("T1566", "Initial Access"),
        "malware_execution": ("T1204.002", "Execution"),
        "lateral_movement": ("T1021.002", "Lateral Movement"),
        "data_exfiltration": ("T1041", "Exfiltration"),
        "c2_beaconing": ("T1071.001", "Command and Control"),
        "port_scan_detected": ("T1046", "Discovery"),
    }

    for alert_type, (expected_tid, expected_tactic) in expected_mappings.items():
        alert = Alert(
            alert_id=f"ALT-{alert_type}",
            timestamp="2026-10-07T08:00:00Z",
            alert_type=alert_type,
            severity=3,
            host="HOST1",
            user="user1",
            description="Test alert",
            asset_criticality=3,
        )
        mapped = map_alert(alert)
        assert len(mapped) >= 1
        assert mapped[0]["technique_id"] == expected_tid
        assert mapped[0]["tactic"] == expected_tactic
        assert mapped[0]["confidence"] >= 0.80
        assert mapped[0]["needs_human_review"] is False


def test_unmapped_alert_triggers_human_review():
    alert = Alert(
        alert_id="ALT-UNKNOWN",
        timestamp="2026-10-07T08:00:00Z",
        alert_type="mysterious_firmware_flashing",
        severity=4,
        host="HOST1",
        user="root",
        description="Unknown proprietary device anomaly",
        asset_criticality=4,
    )
    mapped = map_alert(alert)
    assert len(mapped) >= 1
    assert mapped[0]["needs_human_review"] is True


def test_map_incident_kill_chain_order():
    incident = Incident(
        incident_id="INC-CHAIN-01",
        alerts=[
            Alert(
                alert_id="A1",
                timestamp="2026-10-07T08:00:00Z",
                alert_type="data_exfiltration",  # Exfiltration (stage 11)
                severity=5,
                host="DB-01",
                user="admin",
                description="Egress stream",
                asset_criticality=5,
            ),
            Alert(
                alert_id="A2",
                timestamp="2026-10-07T07:30:00Z",
                alert_type="phishing",  # Initial Access (stage 1)
                severity=3,
                host="WKSTN-01",
                user="bob",
                description="Malicious link clicked",
                asset_criticality=2,
            ),
            Alert(
                alert_id="A3",
                timestamp="2026-10-07T07:45:00Z",
                alert_type="privilege_escalation",  # Privilege Escalation (stage 4)
                severity=4,
                host="WKSTN-01",
                user="bob",
                description="Kernel exploit privilege escalation",
                asset_criticality=2,
            ),
        ],
    )

    res = map_incident(incident)
    tactics = res["tactics"]
    # Initial Access -> Privilege Escalation -> Exfiltration
    assert tactics == ["Initial Access", "Privilege Escalation", "Exfiltration"]
    assert "T1566" in res["techniques"]
    assert "T1068" in res["techniques"]
    assert "T1041" in res["techniques"]


def test_technique_for_backward_compat():
    tf = technique_for("brute_force")
    assert tf["technique_id"] == "T1110"
    assert tf["tactic"] == "Credential Access"


def test_successful_login_with_and_without_preceding_brute_force():
    # 1. Isolated map_alert maps to T1078 with LOW confidence (0.40) & needs_human_review
    isolated_alert = Alert(
        alert_id="A-LOGIN-1",
        timestamp="2026-10-07T08:15:00Z",
        alert_type="successful_login",
        severity=2,
        host="AUTH-SRV-01",
        user="asmith",
        description="Successful interactive logon",
        asset_criticality=3,
    )
    mapped = map_alert(isolated_alert)
    assert len(mapped) == 1
    assert mapped[0]["technique_id"] == "T1078"
    assert mapped[0]["tactic"] == "Initial Access"
    assert mapped[0]["confidence"] == 0.40
    assert mapped[0]["needs_human_review"] is True

    # 2. In map_incident: preceded by brute_force on same user/host -> treated as attack step
    inc_preceded = Incident(
        incident_id="INC-CORRELATED",
        alerts=[
            Alert(
                alert_id="A-BF-1",
                timestamp="2026-10-07T08:10:00Z",
                alert_type="brute_force",
                severity=3,
                host="AUTH-SRV-01",
                user="asmith",
                description="100 failed password attempts",
                asset_criticality=3,
            ),
            isolated_alert,
        ],
    )
    res_corr = map_incident(inc_preceded)
    assert "T1078" in res_corr["techniques"]
    assert "Initial Access" in res_corr["tactics"]
    # Does not trigger human review on incident for the correlated login
    assert res_corr["needs_human_review"] is False

    # 3. In map_incident: NOT preceded by brute force -> NOT treated as attack step
    inc_unpreceded = Incident(
        incident_id="INC-SOLO",
        alerts=[isolated_alert],
    )
    res_solo = map_incident(inc_unpreceded)
    assert "T1078" not in res_solo["techniques"]
    assert "Initial Access" not in res_solo["tactics"]
    assert res_solo["needs_human_review"] is True
    assert any("successful_login" in r for r in res_solo["review_reasons"])


def test_privilege_escalation_description_dispatch_t1068_vs_t1548():
    # When alert describes an actual exploit -> T1068
    exploit_alert = Alert(
        alert_id="A-PE-1",
        timestamp="2026-10-07T08:00:00Z",
        alert_type="privilege_escalation",
        severity=4,
        host="DB-01",
        user="svc",
        description="Local privilege escalation exploit leveraging CVE-2024-21338 kernel vulnerability",
        asset_criticality=4,
    )
    res_exploit = map_alert(exploit_alert)
    assert res_exploit[0]["technique_id"] == "T1068"
    assert res_exploit[0]["technique"] == "Exploitation for Privilege Escalation"
    assert res_exploit[0]["tactic"] == "Privilege Escalation"

    # When alert does not describe an exploit (token / elevation control abuse) -> T1548
    token_alert = Alert(
        alert_id="A-PE-2",
        timestamp="2026-10-07T08:00:00Z",
        alert_type="privilege_escalation",
        severity=4,
        host="DB-01",
        user="svc",
        description="Token manipulation and abuse of elevation control mechanisms (SeImpersonatePrivilege)",
        asset_criticality=4,
    )
    res_token = map_alert(token_alert)
    assert res_token[0]["technique_id"] == "T1548"
    assert res_token[0]["technique"] == "Abuse Elevation Control Mechanism"
    assert res_token[0]["tactic"] == "Privilege Escalation"

    # Default catalog without exploit keywords also yields T1548
    generic_alert = Alert(
        alert_id="A-PE-3",
        timestamp="2026-10-07T08:00:00Z",
        alert_type="privilege_escalation",
        severity=4,
        host="DB-01",
        user="svc",
        description="Standard elevation of privileges to administrator",
        asset_criticality=4,
    )
    res_generic = map_alert(generic_alert)
    assert res_generic[0]["technique_id"] == "T1548"


def test_authorized_usb_maps_to_no_technique_and_cannot_raise_score():
    from scoring import score_incident

    # Alert mapping verification
    auth_usb_alert = Alert(
        alert_id="A-USB-1",
        timestamp="2026-10-07T08:00:00Z",
        alert_type="usb_device_inserted",
        severity=1,
        host="RECEPTION-PC",
        user="frontdesk",
        description="Approved ergonomic USB mouse plugged into workstation",
        asset_criticality=1,
    )
    mapped = map_alert(auth_usb_alert)
    assert len(mapped) == 1
    assert mapped[0]["technique_id"] is None
    assert mapped[0]["technique"] == "None"
    assert mapped[0]["tactic"] == "None"
    assert mapped[0]["is_benign"] is True

    # Base malicious incident
    base_alert = Alert(
        alert_id="A-MAL-1",
        timestamp="2026-10-07T08:00:00Z",
        alert_type="malware_execution",
        severity=3,
        host="WKSTN-10",
        user="bob",
        description="Suspicious binary executed",
        asset_criticality=2,
    )
    inc_base = Incident(incident_id="INC-BASE", alerts=[base_alert])
    score_base = score_incident(inc_base)

    # Incident with malicious alert PLUS high-severity/high-criticality authorized USB alert
    high_usb_alert = Alert(
        alert_id="A-USB-HIGH",
        timestamp="2026-10-07T08:05:00Z",
        alert_type="authorized_usb",
        severity=5,
        host="CRITICAL-SERVER-99",
        user="admin",
        description="Whitelisted authorized USB diagnostic key connected",
        asset_criticality=5,
    )
    inc_with_usb = Incident(incident_id="INC-WITH-USB", alerts=[base_alert, high_usb_alert])
    score_with_usb = score_incident(inc_with_usb)

    # The authorized USB alert must NOT raise the incident's risk score
    assert score_with_usb["risk_score"] <= score_base["risk_score"]

    # An incident containing ONLY authorized USB alerts scores 0.0 (LOW tier)
    inc_only_usb = Incident(incident_id="INC-ONLY-USB", alerts=[auth_usb_alert])
    score_only_usb = score_incident(inc_only_usb)
    assert score_only_usb["risk_score"] == 0.0
    assert score_only_usb["risk_tier"] == "LOW"


def test_port_scan_maps_to_t1046():
    for atype in ("port_scan", "port_scan_detected"):
        alert = Alert(
            alert_id=f"A-{atype}",
            timestamp="2026-10-07T08:00:00Z",
            alert_type=atype,
            severity=2,
            host="SCANNER-01",
            user="netsec",
            description="TCP SYN port scan across subnet",
            asset_criticality=2,
        )
        mapped = map_alert(alert)
        assert len(mapped) == 1
        assert mapped[0]["technique_id"] == "T1046"
        assert mapped[0]["technique"] == "Network Service Discovery"
        assert mapped[0]["tactic"] == "Discovery"
        assert mapped[0]["confidence"] >= 0.85
        assert mapped[0]["needs_human_review"] is False


def test_stage_order_rules():
    from mitre_map import stage_order

    # 1. lsass_access after execution and privilege escalation, before lateral_movement
    assert stage_order("lsass_access") > stage_order("malware_execution")
    assert stage_order("lsass_access") > stage_order("privilege_escalation")
    assert stage_order("lsass_access") < stage_order("lateral_movement")

    # 2. port_scan and port_scan_detected after initial access and execution
    assert stage_order("port_scan") > stage_order("phishing")
    assert stage_order("port_scan") > stage_order("malware_execution")
    assert stage_order("port_scan_detected") > stage_order("phishing")
    assert stage_order("port_scan_detected") > stage_order("malware_execution")

    # 3. brute_force before successful_login
    assert stage_order("brute_force") < stage_order("successful_login")
    assert stage_order("failed_logon_spike") < stage_order("successful_login")


def test_c2_beacon_blocked_and_av_hit_confidence_and_brief():
    from summarizer import generate_brief

    # Verify confidence capped at 0.50
    alert_c2 = Alert(
        alert_id="A-C2-BLOCKED",
        timestamp="2026-10-07T08:00:00Z",
        alert_type="c2_beacon_blocked",
        severity=4,
        host="WKSTN-1",
        user="bob",
        description="Blocked C2 beacon to dynamic DNS",
        asset_criticality=2,
    )
    mapped_c2 = map_alert(alert_c2)
    assert mapped_c2[0]["confidence"] <= 0.50

    alert_av = Alert(
        alert_id="A-AV-HIT",
        timestamp="2026-10-07T08:05:00Z",
        alert_type="av_signature_hit",
        severity=3,
        host="WKSTN-1",
        user="bob",
        description="AV signature matched dropper script",
        asset_criticality=2,
    )
    mapped_av = map_alert(alert_av)
    assert mapped_av[0]["confidence"] <= 0.50

    # Incident with blocked/detected events
    inc = Incident(
        incident_id="INC-BLOCKED-01",
        alerts=[alert_c2, alert_av],
    )
    brief = generate_brief(inc)

    # Brief states activity was blocked/detected only
    assert "blocked/detected only" in brief["what_happened"].lower() or (
        "blocked only" in brief["what_happened"].lower() and "detected only" in brief["what_happened"].lower()
    )
    assert "blocked/detected only" in str(brief).lower() or (
        "blocked only" in str(brief).lower() and "detected only" in str(brief).lower()
    )


