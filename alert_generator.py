"""
Generates a synthetic batch of ~3000 SOC alerts over a 24h window.
Most alerts are independent noise (typical tier-1 reality: high volume,
mostly benign/duplicate). A handful of ASSET+TIME clusters are seeded as
genuine multi-stage attack chains so the grouping/scoring logic has real
signal to find.
"""

import random
from datetime import datetime, timedelta

from assets import ASSET_REGISTRY
from mitre_map import ALERT_TYPE_CATALOG, technique_for

random.seed(42)

WINDOW_START = datetime(2026, 9, 26, 0, 0, 0)
WINDOW_HOURS = 24

ALL_ASSETS = list(ASSET_REGISTRY.keys())
ALL_ALERT_TYPES = list(ALERT_TYPE_CATALOG.keys())

SRC_IP_POOL = [f"10.20.{random.randint(0,30)}.{random.randint(2,254)}" for _ in range(60)]
EXTERNAL_IP_POOL = [f"185.220.{random.randint(0,255)}.{random.randint(2,254)}" for _ in range(30)]
_ALERT_COUNTER = 0


def _rand_time():
    offset_min = random.uniform(0, WINDOW_HOURS * 60)
    return WINDOW_START + timedelta(minutes=offset_min)


def _make_alert(alert_type, asset_id, ts, src_ip=None, dst_ip=None, note=""):
    global _ALERT_COUNTER
    _ALERT_COUNTER += 1
    meta = technique_for(alert_type)
    return {
        "alert_id": f"A-{_ALERT_COUNTER:05d}",
        "timestamp": ts.isoformat(),
        "asset_id": asset_id,
        "alert_type": alert_type,
        "src_ip": src_ip or random.choice(SRC_IP_POOL),
        "dst_ip": dst_ip or random.choice(SRC_IP_POOL + EXTERNAL_IP_POOL),
        "technique_id": meta["technique_id"],
        "technique_name": meta["technique_name"],
        "tactic": meta["tactic"],
        "base_severity": meta["base_severity"],
        "false_positive_rate": meta["false_positive_rate"],
        "note": note,
    }


def _seed_attack_chains(n_chains=6):
    """Seed a small number of realistic multi-stage attack chains,
    each hitting one asset within a tight time window -- this is what
    the grouping engine should surface as high-risk incidents."""
    chains = []
    chain_templates = [
        # Credential compromise -> lateral movement style chain
        ["impossible_travel_login", "failed_logon_spike", "lsass_access"],
        # Ransomware precursor chain
        ["powershell_encoded_cmd", "registry_run_key_mod", "new_scheduled_task", "ransomware_note_created"],
        # C2 / exfil chain
        ["port_scan_detected", "c2_beacon_blocked", "dns_tunneling_suspected"],
    ]
    critical_or_high_assets = [
        a for a, info in ASSET_REGISTRY.items()
        if info["criticality"] in ("CRITICAL", "HIGH")
    ]
    for i in range(n_chains):
        asset = random.choice(critical_or_high_assets)
        template = random.choice(chain_templates)
        start = _rand_time()
        ext_ip = random.choice(EXTERNAL_IP_POOL)
        for step_i, atype in enumerate(template):
            ts = start + timedelta(minutes=step_i * random.uniform(2, 9))
            chains.append(
                _make_alert(
                    atype, asset, ts,
                    dst_ip=ext_ip if "c2" in atype or "dns" in atype else None,
                    note=f"seeded_chain_{i}",
                )
            )
    return chains


def generate_alerts(total=3000, n_chains=6, seed=42):
    """Generate a reproducible batch without mutating global RNG state."""
    state = random.getstate()
    random.seed(seed)
    try:
        global _ALERT_COUNTER
        _ALERT_COUNTER = 0
        alerts = []
        alerts.extend(_seed_attack_chains(n_chains))
        remaining = total - len(alerts)
        for _ in range(remaining):
            atype = random.choice(ALL_ALERT_TYPES)
            asset = random.choice(ALL_ASSETS)
            ts = _rand_time()
            alerts.append(_make_alert(atype, asset, ts))
        alerts.sort(key=lambda a: a["timestamp"])
        return alerts
    finally:
        random.setstate(state)


if __name__ == "__main__":
    batch = generate_alerts()
    print(f"Generated {len(batch)} alerts")
    print(batch[0])
