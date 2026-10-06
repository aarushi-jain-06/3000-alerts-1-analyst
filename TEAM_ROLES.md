# Six-Member Team Plan — 3,000 Alerts, One Analyst

## Team structure

The team has two experienced members and four developing members. The experienced members should own architecture and model-risk decisions. The newer members should own complete, visible workstreams with clearly defined interfaces and regular review from an experienced partner.

```text
Experienced Member 1 → Architecture, Backend, Integration
Experienced Member 2 → ML, Risk Scoring, Model Evaluation, RAG

Member 3 → Frontend and Dashboard
Member 4 → MITRE Content, Summaries, Investigation UX
Member 5 → QA, Testing, Data Quality, DevOps
Member 6 → SOC Workflow, Human Loop, Demo, Documentation
```

## Role 1 — Technical Lead and Backend Architect

### Recommended person

Experienced Member 1.

### Mission

Own the technical design and make sure every component connects into one reliable pipeline.

### Owns

- `pipeline.py`
- `main.py`
- `grouping.py`
- backend data contracts
- entity-graph correlation
- incident object schema
- merge behavior
- performance and integration
- final code review

### Main responsibilities

1. Define the normalized alert schema.
2. Maintain the incident schema shared by backend, dashboard, and reports.
3. Own asset/time/connection graph correlation.
4. Ensure cross-asset incidents are scored correctly.
5. Integrate ML, summaries, investigation traces, feedback, and metrics.
6. Review pull requests from all other members.
7. Keep the pipeline runnable with one command.

### Deliverables

- stable `run_pipeline()` interface
- graph-correlation tests
- integration with every module
- error handling and graceful fallbacks
- final architecture decisions

### Pairing partners

- Pair with Member 5 for tests and reliability.
- Pair with Member 3 for dashboard data contracts.

## Role 2 — ML and Security Analytics Lead

### Recommended person

Experienced Member 2.

### Mission

Make risk scoring, model evaluation, and security reasoning technically credible.

### Owns

- `train_classifier.py`
- `ml_classifier.py`
- `scoring.py`
- `model_eval.py`
- `rag.py`
- `retrain.py`
- false-positive analysis
- model limitations and evaluation claims
- retrieval quality and grounding evaluation

### Main responsibilities

1. Maintain CICIDS2017 training and evaluation.
2. Review feature selection and class imbalance handling.
3. Explain the difference between network-flow classification and synthetic alert scoring.
4. Keep the ML model as a supporting signal rather than an unexplained decision maker.
5. Maintain confidence, risk-tier, and next-stage logic.
6. Review feedback calibration and retraining safety.
7. Own the RAG retrieval interface, corpus quality, relevance, and grounding tests.
8. Ensure retrieved context is passed safely into optional LLM summaries.
9. Prepare the ML/RAG explanation for judges.

### Deliverables

- reproducible model training
- evaluation report and charts
- model card describing limitations
- risk-score explanation
- false-positive/false-negative discussion
- safe fallback when the model is unavailable

### Pairing partners

- Pair with Member 4 on ATT&CK-based threat reasoning.
- Pair with Member 5 on evaluation and regression tests.

## Role 3 — Frontend and Dashboard Developer

### Recommended person

Developing Member 3.

### Mission

Turn the backend output into a clear SOC analyst experience.

### Owns

- `dashboard.py`
- dashboard layout and navigation
- Command Center
- Incidents Explorer
- Predict page
- Review Queue interface
- Analytics page
- Assets & MITRE page

### Main responsibilities

1. Display real values from `outputs/metrics.json`.
2. Show the number of alerts, incidents, critical/high incidents, and cross-asset incidents.
3. Make the graph correlation visible through:
   - correlation method
   - impacted assets
   - connection evidence
4. Add incident filtering and detail views.
5. Add analyst disposition controls.
6. Show investigation traces without overwhelming the analyst.
7. Ensure the interface works on the demo machine.

### Deliverables

- polished Command Center
- incident detail page
- visible ATT&CK evidence
- review action controls
- dynamic MTTT charts
- no hardcoded metrics
- screenshot-ready demo layout

### Pairing partners

- Pair with Member 1 for data contracts.
- Pair with Member 6 for analyst workflow and demo story.

## Role 4 — MITRE Content, Summaries, and Investigation Engineer

### Recommended person

Developing Member 4.

### Mission

Make every incident understandable, evidence-based, and connected to attacker behavior. Experienced Member 2 owns retrieval architecture; this member owns ATT&CK content, brief quality, and investigation experience built on top of it.

### Owns

- `mitre_map.py`
- `summarizer.py`
- `investigator.py`
- ATT&CK technique descriptions
- attack timeline language
- investigation trace presentation

### Main responsibilities

1. Maintain alert-to-ATT&CK mappings.
2. Add concise, accurate technique descriptions.
3. Supply accurate ATT&CK descriptions and example evidence for Member 2's retrieval layer.
4. Improve deterministic brief quality and prompt structure.
5. Test optional Ollama/local-model summaries.
6. Ensure summaries do not invent facts.
7. Make the attack timeline and predicted next stage easy to understand.
8. Create future integration notes for FAISS, STIX/TAXII, EDR, and threat intelligence.

### Deliverables

- complete mapping table
- grounded ATT&CK context
- high-quality incident briefs
- investigation trace format
- example attack stories for the demo
- source/evidence explanation for every summary

### Pairing partners

- Pair with Member 2 for threat-model accuracy.
- Pair with Member 3 for dashboard presentation.

## Role 5 — QA, Testing, Data Quality, and DevOps Engineer

### Recommended person

Developing Member 5.

### Mission

Make sure the project runs reliably, produces correct numbers, and can be demonstrated without surprises.

### Owns

- `tests/`
- `requirements.txt`
- reproducibility checks
- pipeline smoke tests
- output validation
- startup/run instructions
- performance timing
- environment troubleshooting

### Main responsibilities

1. Test every major module independently.
2. Test the full pipeline from a clean environment.
3. Validate output row counts and required columns.
4. Test model-present and model-missing behavior.
5. Test LLM-present and LLM-missing behavior.
6. Test empty inputs, malformed alerts, and unknown assets.
7. Check dashboard startup before every demo.
8. Maintain installation and troubleshooting instructions.

### Deliverables

- unit tests
- integration tests
- regression test for 3,000 alerts
- clean setup instructions
- performance report
- final pre-demo checklist

### Pairing partners

- Pair with Member 1 for integration tests.
- Pair with Member 2 for ML evaluation tests.

## Role 6 — SOC Workflow, Human Loop, Demo, and Documentation Lead

### Recommended person

Developing Member 6.

### Mission

Make the project useful to an analyst and easy for judges to understand.

### Owns

- `human_loop.py`
- `metrics.py`
- `PROJECT.md`
- `BACKEND_ML_PRACTICAL.md`
- `FULL_ARCHITECTURE.md`
- `TEAM_ROLES.md`
- demo script
- analyst workflow
- shift-handover story

### Main responsibilities

1. Define the analyst review workflow.
2. Maintain dispositions and audit notes.
3. Validate merge and escalation behavior.
4. Explain the human-in-the-loop safety model.
5. Maintain MTTT calculations and business-value narrative.
6. Prepare the five-minute demo.
7. Keep documentation aligned with actual code.
8. Prepare answers for likely judge questions.

### Deliverables

- analyst review journey
- human-loop audit demonstration
- accurate MTTT comparison
- shift handover example
- final pitch and demo script
- judge FAQ

### Pairing partners

- Pair with Member 3 for user experience.
- Pair with Member 5 for output and metric validation.

## Ownership matrix

| Workstream | Primary | Reviewer |
|---|---|---|
| Architecture | Member 1 | Member 2 |
| Pipeline integration | Member 1 | Member 5 |
| Graph correlation | Member 1 | Member 5 |
| ML training | Member 2 | Member 5 |
| Risk scoring | Member 2 | Member 1 |
| ATT&CK mapping | Member 4 | Member 2 |
| RAG retrieval and evaluation | Member 2 | Member 1 |
| ATT&CK content and summaries | Member 4 | Member 2 |
| Investigation traces | Member 4 | Member 1 |
| Streamlit frontend | Member 3 | Member 1 |
| Review queue UI | Member 3 | Member 6 |
| Human feedback | Member 6 | Member 1 |
| MTTT metrics | Member 6 | Member 5 |
| Automated tests | Member 5 | Member 1/2 |
| Dependencies and setup | Member 5 | Member 1 |
| Documentation | Member 6 | All members |
| Demo presentation | Member 6 | All members |

## How the team should work

### Daily workflow

1. Each member states what they completed, what they are doing next, and what is blocked.
2. Backend and ML changes are reviewed by an experienced member.
3. Every feature must include either a test, a screenshot, or a reproducible example.
4. Documentation is updated when behavior changes.
5. No one changes the shared incident schema without notifying Member 1.

### Definition of done

A feature is done only when:

- the code works
- the output is visible or testable
- failure behavior is understood
- documentation is updated
- another member can explain it

### Recommended branch/task pattern

Use small task branches or clearly named work items:

```text
feature/graph-correlation
feature/dashboard-cross-asset
feature/mitre-grounding
feature/feedback-audit
test/full-pipeline
docs/demo-script
```

## Demo speaking order

### Member 6 — Problem and outcome

Explain alert fatigue, the one-analyst problem, and the final reduction from raw alerts to incidents.

### Member 3 — Frontend walkthrough

Show the Command Center, cross-asset KPI, incident filters, and detail page.

### Member 1 — Backend and graph

Explain how shared entities create graph-connected incidents and why cross-asset correlation matters.

### Member 2 — ML and risk scoring

Explain CICIDS training, hybrid confidence, asset criticality, and model limitations.

### Member 4 — MITRE and investigation

Show ATT&CK mapping, grounded evidence, timeline, predicted next stage, and investigation trace.

### Member 5 — Reliability and metrics

Show tests, reproducibility, MTTT calculations, and output validation.

## Final team message

Every member should be able to explain this sentence:

> We correlate related alerts into evidence-based incidents, prioritize them by business impact and attack progression, give the analyst a grounded explanation, and prove how much triage time the workflow saves.
