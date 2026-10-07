# 3,000 Alerts, One Analyst — Project Guide

## 1. What this project is

This project is an enterprise-style Security Operations Center (SOC) alert-triage system.

A tier-1 SOC analyst may receive thousands of alerts every day. Most alerts are duplicates, low risk, or false positives. Reviewing every alert independently creates alert fatigue and delays the investigation of real attacks.

The system solves this by transforming raw alerts into a small number of ranked, explainable incidents:

```text
3,000 raw alerts
        ↓
Correlated entity graph
        ↓
289 incidents
        ↓
Risk ranking using asset criticality and threat evidence
        ↓
MITRE ATT&CK context and attack timeline
        ↓
Human review queue and shift-handover brief
```

The central design principle is:

> A small number of serious alerts on a critical asset can be more dangerous than a large number of noisy alerts on a low-value asset.

## 2. The problem being solved

Traditional alert triage often behaves like this:

1. Open alert one.
2. Investigate it.
3. Close or escalate it.
4. Repeat thousands of times.

That approach has several weaknesses:

- Related alerts are reviewed separately.
- Alert count is confused with risk.
- The importance of the affected asset is ignored.
- Analysts lose the attack story across time.
- Knowledge of MITRE ATT&CK techniques is not always visible.
- Decisions are difficult to hand over between shifts.
- There is no clear measurement of time saved.

This project groups related alerts into incidents, scores those incidents, explains the evidence, and keeps the final decision with a human analyst.

## 3. What the finished system provides

### Alert ingestion

The current demo uses a deterministic synthetic alert generator. It creates a reproducible 24-hour batch containing:

- 3,000 alerts by default
- 18 assets
- 13 alert types
- benign/noisy alerts
- seeded multi-stage attack chains
- timestamps, source IPs, destination IPs, assets, severity, and false-positive priors

The generator can be replaced by a SIEM, EDR, firewall, identity provider, or cloud security connector.

### Incident correlation

The system builds an entity graph. Alerts are connected when they share an asset or the same source-to-destination connection within a 20-minute window.

Connected components become incidents. This allows one incident to contain multiple affected assets, which is important for lateral movement.

### Asset-aware prioritization

Assets are registered with business criticality:

| Criticality | Weight | Example |
|---|---:|---|
| CRITICAL | 10 | Domain controller, payment gateway, finance database |
| HIGH | 7 | VPN gateway, public server, executive laptop |
| MEDIUM | 4 | Employee workstation, internal application |
| LOW | 1 | Printer, kiosk, test VM |

For a cross-asset incident, the most critical impacted asset determines the incident's asset weight.

### Threat scoring

The risk score combines:

- highest alert severity
- asset criticality
- confidence that the incident is malicious
- number of distinct tactics
- small capped volume factor

Alert count intentionally has limited influence. This prevents duplicate low-risk alerts from overwhelming a serious multi-stage attack.

### MITRE ATT&CK mapping

Every supported alert type maps to a technique ID, technique name, and tactic. Examples:

- LSASS access → `T1003.001` → Credential Access
- Encoded PowerShell → `T1059.001` → Execution
- Scheduled task → `T1053.005` → Persistence
- Ransomware note → `T1486` → Impact
- DNS tunneling → `T1071.004` → Command and Control

### Grounded incident briefs

Each incident brief contains:

- incident ID
- risk tier and score
- impacted asset and criticality
- start and end time
- ATT&CK techniques
- observed tactics
- confidence source
- ordered attack timeline
- predicted next stage
- alert IDs used as evidence
- retrieved ATT&CK context
- recommended analyst action

The default brief is deterministic and offline-safe. Optional Ollama or Anthropic summarization can rewrite the brief while receiving the retrieved ATT&CK context.

### Human-in-the-loop review

The system never silently closes serious incidents. Every incident starts as `PENDING`.

Supported dispositions:

- `TRUE_POSITIVE`
- `FALSE_POSITIVE`
- `ESCALATED`
- `MERGE`
- `PENDING`

The analyst name, timestamp, notes, and disposition are written to an audit feedback log.

### Investigation traces

High and critical incidents receive a bounded investigation trace. The current offline tools inspect:

- asset inventory
- recent alerts belonging to the incident
- source and destination IP reputation status

The result is stored as an ordered trace. In production, these tools can call a CMDB, EDR, threat-intelligence platform, or ticketing system.

### MTTT measurement

The project compares two models:

- baseline: manually triage every raw alert
- pipeline: review one incident brief per correlated incident

The output reports total analyst time, average time per alert, number of items reviewed, and percentage reduction.

## 4. Main files

| File | Responsibility |
|---|---|
| `alert_generator.py` | Reproducible synthetic alert generation |
| `assets.py` | Asset registry and criticality weights |
| `mitre_map.py` | Alert-to-ATT&CK mapping and descriptions |
| `grouping.py` | Entity graph and fallback correlation |
| `scoring.py` | Confidence, risk score, tier, next-stage prediction |
| `ml_classifier.py` | Trained model loading and inference |
| `rag.py` | Local lexical ATT&CK retrieval |
| `summarizer.py` | Grounded deterministic/LLM incident briefs |
| `investigator.py` | High-risk bounded investigation tools |
| `human_loop.py` | Review queue, dispositions, merge, audit logging |
| `retrain.py` | Feedback readiness and incident-level calibration |
| `metrics.py` | MTTT and analyst-time calculations |
| `pipeline.py` | End-to-end orchestration |
| `main.py` | Standard executable entry point |
| `final_prediction.py` | Submission artefact generation |
| `dashboard.py` | Streamlit command center |
| `train_classifier.py` | CICIDS2017 model training |
| `model_eval.py` | Evaluation and visual reports |
| `tests/test_pipeline.py` | Automated regression tests |

## 5. Running the project

```powershell
pip install -r requirements.txt
python main.py
streamlit run dashboard.py
```

Optional local AI summaries:

```powershell
$env:OLLAMA_MODEL = "llama3.2:3b"
$env:OLLAMA_HOST = "http://localhost:11434"
python main.py
```

Optional Anthropic summaries:

```powershell
$env:ANTHROPIC_API_KEY = "your-key"
python main.py
```

The deterministic template remains available if no model is configured or if an external model fails.

## 6. Output files

The `outputs/` directory contains:

- `alerts.csv` — raw input alerts
- `incidents.json` — scored incidents and investigation traces
- `review_queue.csv` — human-review queue
- `shift_brief.md` — top incidents for the next shift
- `mttt_metrics.md` — MTTT comparison
- `metrics.json` — machine-readable metrics for the dashboard
- `final_predictions.csv` — flat incident prediction table
- `submission_summary.md` — presentation-ready summary
- model evaluation charts and CSVs

## 7. What is production-ready versus demo-specific

The architecture and interfaces are designed for production extension, but the current data sources are intentionally demo-safe.

Demo-specific:

- synthetic alerts
- static asset registry
- local ATT&CK descriptions
- offline reputation result of `UNKNOWN`
- estimated analyst handling times

Production replacements:

- SIEM/EDR ingestion
- live CMDB
- official ATT&CK STIX/TAXII data
- live threat intelligence
- real analyst timing telemetry
- ticketing and case-management integration

## 8. The pitch in one sentence

> This system turns thousands of noisy security alerts into a small, explainable, asset-aware incident queue so one analyst can focus on the attacks that matter most.

## 9. Team learning map

The complete team ownership and study plan is in [TEAM_ROLES.md](TEAM_ROLES.md) and [MEMBER_GUIDES.md](MEMBER_GUIDES.md).

- Bhoomika owns technical leadership, backend integration, and graph correlation.
- Ajasra owns ML, hybrid risk scoring, model evaluation, and RAG retrieval/grounding.
- Avantika owns the Streamlit frontend and analyst dashboard.
- Arushi owns ATT&CK content, summaries, and investigation experience.
- Aditi owns tests, data quality, dependencies, and reliability.
- Dev owns human workflow, MTTT, demo narrative, and documentation.

The operational codebase and running instructions are in [CODEBASE_AND_RUNNING.md](CODEBASE_AND_RUNNING.md). The detailed backend and model explanation is in [BACKEND_ML_PRACTICAL.md](BACKEND_ML_PRACTICAL.md), and the system-level design is in [FULL_ARCHITECTURE.md](FULL_ARCHITECTURE.md).
