# Avantika — Member 3 — Frontend and SOC Dashboard

## Own

`dashboard.py`, Streamlit layout, Command Center, Incidents Explorer, Predict page, Review Queue UI, Analytics, and Assets & MITRE views.

## Study first

1. `PROJECT.md`
2. `FULL_ARCHITECTURE.md`
3. `CODEBASE_AND_RUNNING.md`
4. `dashboard.py`
5. `outputs/metrics.json`
6. `outputs/incidents.json`

## Concepts

- Streamlit reruns and caching
- pandas dataframes
- filter state
- KPI design
- evidence-first UX
- score explanation
- ATT&CK visualization
- analyst workflow
- safe output rendering

## Implementation responsibilities

- Read real values from `outputs/metrics.json`.
- Show alert count, incident count, reduction, MTTT, tiers, and cross-asset count.
- Show incident correlation method and impacted assets.
- Show brief, ATT&CK techniques, timeline, predicted stage, score parts, and investigation trace.
- Provide review disposition controls.
- Never hardcode performance claims.
- Verify the UI after every backend schema change.

## Must demonstrate

Start at Command Center, filter to a critical incident, open the detail, explain the score, show the graph correlation and trace, then save a review disposition.

## Handoffs

Use field contracts from Member 1, scoring explanations from Member 2, security wording from Member 4, and workflow language from Member 6.
