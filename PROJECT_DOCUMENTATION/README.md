# SOC Alert Triage Pipeline — "3,000 Alerts, One Analyst"

A tier-1 alert summarizer: ingest a noisy alert batch, correlate related alerts
into incidents, rank by **asset criticality** (not raw alert count), map to
**MITRE ATT&CK**, generate a shift-handover brief per incident, and route
everything through a **human-in-the-loop** review queue. Also measures the
**Mean-Time-To-Triage (MTTT)** reduction vs. manual per-alert triage.

## Architecture

```
alert_generator.py   synthetic 24h batch of alerts (noise + seeded attack chains)
        |
grouping.py           entity-graph correlation (asset + connection + time)
        |
scoring.py             risk_score = asset_criticality x max_severity x kill-chain span x confidence
        |
mitre_map.py           every alert type -> ATT&CK technique ID / tactic (used by scoring + briefs)
        |
rag.py / summarizer.py grounded ATT&CK context + optional local/free LLM rewrite
        |
human_loop.py           ranked review queue -- nothing auto-closes above LOW risk
        |
metrics.py               MTTT: baseline (manual per-alert) vs. pipeline (per-incident review)
        |
pipeline.py / main.py   orchestrates the above, writes outputs/
```

## Why asset criticality drives ranking, not alert count

`scoring.py` intentionally gives alert **count** very little weight (capped
multiplier of 1.3x). A domain controller with 3 alerts spanning credential
access + persistence + impact outranks a print server with 40 duplicate
low-severity alerts. See `_kill_chain_bonus()` and `TACTIC_STAGE_ORDER`.

## MITRE ATT&CK coverage

`mitre_map.py` maps every synthetic alert type to a real technique ID
(e.g. `T1003.001` LSASS Memory Access, `T1486` Data Encrypted for Impact).
Each incident brief lists the distinct techniques and tactics observed, so
the next-shift analyst immediately sees kill-chain stage, not just a label.

## Human-in-the-loop

`human_loop.py` builds a review queue where every incident starts as
`PENDING`. Only LOW-risk incidents with high historical false-positive
rates get an `auto_suggested_disposition` of `FALSE_POSITIVE` -- this is a
**suggestion for bulk review**, never an automatic close. `apply_disposition()`
records analyst name + timestamp + notes for audit purposes.

## MTTT measurement

`metrics.py` compares:
- **Baseline**: analyst manually triages every raw alert (time-per-alert
  varies by alert type, e.g. LSASS access = 8 min, USB insert = 2 min).
- **Pipeline**: analyst reviews one brief per *incident* (time varies by
  risk tier, e.g. CRITICAL = 12 min, LOW = 1.5 min bulk-scan).

On the seeded 3,000-alert batch this pipeline produced (your numbers will
vary slightly with different random seeds / chain counts):

| Metric | Baseline | Pipeline | Change |
|---|---|---|---|
| Items to review | 3,000 alerts | ~300 incidents | ~10x fewer |
| MTTT per alert | ~4.9 min | ~0.6 min | ~88% reduction |
| Total analyst time | ~244 hrs | ~29 hrs | ~88% reduction |

## Running it

```bash
cd soc_triage
python3 main.py
```

Outputs land in `outputs/`:
- `alerts.csv` — raw synthetic alert batch
- `incidents.json` — every scored/ranked incident with full detail
- `review_queue.csv` — human-in-the-loop disposition queue
- `shift_brief.md` — top-25 incidents, ready to hand to the next shift
- `mttt_metrics.md` — before/after MTTT table

## Free AI summaries

`summarizer.py` supports a local/free Ollama model using `OLLAMA_MODEL` and
`OLLAMA_HOST`, plus an optional Anthropic provider. Both receive retrieved
ATT&CK context. If no model is configured, deterministic grounded briefs are
generated offline; provider errors always fall back safely.

## Extending toward production

- **Grouping**: entity-graph correlation uses asset and complete connection
  entities; add user/session/process entities when those fields are available.
- **Asset registry**: `assets.py` is a static dict — point it at a real
  CMDB (ServiceNow, Lansweeper) via API for live criticality data.
- **MITRE mapping**: `mitre_map.py` covers 13 alert types as a
  demonstration set — extend with the full ATT&CK Enterprise matrix (or
  pull from MITRE's STIX/TAXII feed) for full technique coverage.
- **Human loop**: wire `human_loop.apply_disposition()` to a ticketing
  system (Jira, ServiceNow) so disposition is a UI action, not a script call.
