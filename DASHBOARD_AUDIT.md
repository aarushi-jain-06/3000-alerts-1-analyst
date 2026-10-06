# Dashboard Requirements Audit

## Overall verdict

The dashboard now covers the main hackathon requirements and the important backend capabilities are visible. It is demo-ready for the current batch pipeline.

It is not yet a full enterprise SOC console because the project still uses local generated files, static assets, offline reputation, and a review-level `MERGE` label rather than a complete interactive incident merge editor.

## Requirement coverage

| Requirement | Dashboard status | Where it appears |
|---|---|---|
| Alert volume | Implemented | Command Center |
| Incident reduction | Implemented | Command Center and Analytics |
| Asset criticality | Implemented | Assets & MITRE and incident score |
| Graph correlation | Implemented and visible | Cross-Asset KPI and incident correlation method |
| Cross-asset impacted assets | Implemented and visible | Incident Explorer detail |
| Risk tiers | Implemented | Command Center, Explorer, Review Queue |
| Risk score | Implemented | Explorer detail and tables |
| Score explanation | Implemented | Explorer detail score table |
| ML prediction | Implemented | Predict page and incident confidence |
| ML evaluation | Partially visible | Analytics model history; detailed artefacts are in `outputs/` |
| MITRE mapping | Implemented | Incident detail and Assets & MITRE |
| RAG context | Implemented indirectly | Included in the generated incident brief |
| Attack timeline | Implemented | Incident brief |
| Next-stage prediction | Implemented | Incident Explorer detail |
| Investigation trace | Implemented | Incident Explorer expandable trace |
| Human review | Implemented | Review Queue |
| Audit feedback | Implemented | Review Queue and `feedback_log.csv` |
| MTTT | Implemented | Command Center and Analytics |
| Shift handover | Implemented | Generated `shift_brief.md` |

## Current limitations

### 1. Merge is not a full dashboard merge workflow

The Review Queue can save `MERGE` as a disposition, but the dashboard does not yet select two incidents, call `merge_incidents()`, replace the originals, and rewrite all affected output files.

The backend merge function exists in `human_loop.py`; the UI integration is the remaining step.

### 2. RAG is visible through the brief, not a separate evidence panel

The generated brief contains ATT&CK evidence context. The dashboard does not currently display retrieved documents in a separate expandable panel with retrieval scores.

### 3. ML evaluation is not fully interactive

The detailed confusion matrix, ROC curve, CV results, and model report are generated under `outputs/`, but the dashboard mainly shows model history and summary metrics.

### 4. Data ingestion is batch/file-based

The dashboard reads generated CSV/JSON files. It does not yet connect directly to a live SIEM, EDR, CMDB, ticketing system, or streaming queue.

### 5. Analyst authentication is not implemented

The review form accepts an analyst name but does not use role-based authentication or authorization.

## Demo verification path

1. Open Command Center.
2. Confirm `3,000` alerts, incident count, MTTT reduction, and Cross-Asset count.
3. Open Incidents Explorer.
4. Select a critical/high incident with multiple impacted assets.
5. Show correlation method and impacted assets.
6. Show score explanation.
7. Show ATT&CK techniques, timeline, predicted stage, and brief.
8. Expand the investigation trace.
9. Open Review Queue.
10. Save a disposition and explain the audit feedback.
11. Open Analytics and show MTTT before/after.
12. Open Assets & MITRE and show business criticality plus technique coverage.

## Final assessment

For the Student Edition challenge, the dashboard covers the required product story. The remaining gaps are enterprise extensions, not blockers for the current demo.
