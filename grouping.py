"""
Groups raw alerts into candidate incidents.

Correlation key: same asset_id, alerts within a rolling CORRELATION_WINDOW.
This is deliberately simple (union-find style time-chaining) so it's easy
to audit -- production systems would add entity graphs (shared src/dst IP,
user session, process lineage) on top of this same skeleton.
"""

from datetime import datetime, timedelta
from collections import defaultdict

CORRELATION_WINDOW = timedelta(minutes=20)


def _parse(ts):
    return datetime.fromisoformat(ts)


def group_alerts_into_incidents(alerts):
    """Correlate alerts into incidents using an entity graph.

    Alerts are connected when they share an asset, source/destination IP, or
    are close in time on the same entity.  Connected components allow a
    lateral-movement chain to span multiple assets while retaining the old
    asset/time implementation as a deterministic fallback.
    """
    if not alerts:
        return []
    try:
        return group_alerts_graph(alerts)
    except (KeyError, TypeError, ValueError):
        return group_by_asset_time(alerts)


def group_by_asset_time(alerts):
    """Legacy, auditable fallback correlation strategy."""
    by_asset = defaultdict(list)
    for a in alerts:
        by_asset[a["asset_id"]].append(a)

    incidents = []
    for asset_id, asset_alerts in by_asset.items():
        asset_alerts.sort(key=lambda a: a["timestamp"])
        cluster = []
        for a in asset_alerts:
            if not cluster:
                cluster = [a]
                continue
            last_ts = _parse(cluster[-1]["timestamp"])
            cur_ts = _parse(a["timestamp"])
            if cur_ts - last_ts <= CORRELATION_WINDOW:
                cluster.append(a)
            else:
                incidents.append(_finalize_cluster(asset_id, cluster))
                cluster = [a]
        if cluster:
            incidents.append(_finalize_cluster(asset_id, cluster))

    return incidents


def group_alerts_graph(alerts):
    """Build connected components over alert entities without extra deps."""
    parent = list(range(len(alerts)))
    rank = [0] * len(alerts)

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        if rank[ra] < rank[rb]:
            ra, rb = rb, ra
        parent[rb] = ra
        if rank[ra] == rank[rb]:
            rank[ra] += 1

    by_entity = defaultdict(list)
    for i, alert in enumerate(alerts):
        ts = _parse(alert["timestamp"])
        # Asset is always a strong entity.  IPs are weaker, but connect
        # cross-asset activity such as lateral movement and C2 campaigns.
        entities = {
            f"asset:{alert.get('asset_id', '')}",
            # A complete connection tuple avoids merging unrelated alerts
            # that happen to reuse a common private source IP from the demo
            # pool while still catching cross-asset movement/C2 reuse.
            f"connection:{alert.get('src_ip', '')}->{alert.get('dst_ip', '')}",
        }
        for entity in entities:
            if entity.endswith(":"):
                continue
            by_entity[entity].append((ts, i))

    for members in by_entity.values():
        members.sort()
        for (previous_ts, previous_i), (current_ts, current_i) in zip(members, members[1:]):
            if current_ts - previous_ts <= CORRELATION_WINDOW:
                union(previous_i, current_i)

    components = defaultdict(list)
    for i, alert in enumerate(alerts):
        components[find(i)].append(alert)

    incidents = []
    for cluster in components.values():
        cluster.sort(key=lambda a: a["timestamp"])
        assets = sorted({a.get("asset_id", "UNKNOWN") for a in cluster})
        incidents.append(_finalize_cluster(assets[0], cluster, assets=assets))
    return incidents


def _finalize_cluster(asset_id, cluster, assets=None):
    techniques = sorted({a["technique_id"] for a in cluster})
    tactics = sorted({a["tactic"] for a in cluster})
    return {
        "incident_id": f"INC-{asset_id}-{cluster[0]['alert_id']}",
        "asset_id": asset_id,
        "assets": assets or [asset_id],
        "correlation_method": "entity_graph" if assets and len(assets) > 1 else "asset_time_graph",
        "alert_ids": [a["alert_id"] for a in cluster],
        "alert_count": len(cluster),
        "start_time": cluster[0]["timestamp"],
        "end_time": cluster[-1]["timestamp"],
        "techniques": techniques,
        "tactics": tactics,
        "alerts": cluster,
    }
