# Final Team Flow and Study Plan

## 1. The complete project flow

All six members should understand this pipeline before specializing:

```text
Synthetic/SIEM alerts
        ↓
Normalized alert schema
        ↓
Entity graph correlation
  asset + connection + time
        ↓
Incident objects
        ↓
Asset criticality enrichment
        ↓
MITRE ATT&CK enrichment
        ↓
ML confidence + static SOC priors
        ↓
Risk score and tier
        ↓
High/critical investigation trace
        ↓
RAG retrieval of relevant ATT&CK context
        ↓
Deterministic or local-AI incident brief
        ↓
Human review and disposition
        ↓
Feedback audit log
        ↓
MTTT and analyst-time measurement
        ↓
Streamlit dashboard and shift handover
```

## 2. What everyone reads first

### First reading session

Every member reads these in order:

1. `PROJECT_DOCUMENTATION/PROJECT.md`
2. `PROJECT_DOCUMENTATION/CODEBASE_AND_RUNNING.md`
3. `PROJECT_DOCUMENTATION/FULL_ARCHITECTURE.md`
4. `PROJECT_DOCUMENTATION/DASHBOARD_AUDIT.md`
5. `PROJECT_DOCUMENTATION/MEMBER_GUIDES.md`
6. Their personal member file

### Everyone must run

```powershell
cd "D:\MICROSOFT HACKATHON"
python -m unittest discover -s tests -v
python main.py
streamlit run dashboard.py
```

### Everyone must understand

- what a raw alert is
- what an incident is
- why graph correlation is needed
- why business asset criticality changes priority
- how MITRE ATT&CK describes behavior
- what ML contributes and what it does not prove
- what RAG retrieves and why grounding matters
- why humans approve dispositions
- how MTTT proves business value

## 3. Bhoomika — experienced technical lead

### Main ownership

Backend architecture, pipeline integration, graph correlation, incident schema, and system reliability.

### Read deeply

- `grouping.py`
- `pipeline.py`
- `main.py`
- `alert_generator.py`
- `assets.py`
- `human_loop.py`
- `tests/test_pipeline.py`

### Topics to know

- dictionaries and data contracts
- graph entities and connected components
- union-find
- correlation windows
- cross-asset lateral movement
- fallback design
- integration testing
- deterministic seeds
- schema evolution
- performance and failure handling

### Must be able to explain

How two alerts become one incident, how a cross-asset incident is represented, and how the full pipeline passes that object to ML, RAG, investigation, dashboard, and metrics.

## 4. Ajasra — experienced ML, risk, and RAG lead

### Main ownership

Machine learning, hybrid risk scoring, model evaluation, feedback calibration, RAG retrieval, and grounding quality.

### Read deeply

- `train_classifier.py`
- `ml_classifier.py`
- `scoring.py`
- `model_eval.py`
- `rag.py`
- `retrain.py`
- `mitre_map.py`
- `summarizer.py`

### Topics to know

#### ML

- supervised binary classification
- CICIDS2017
- class imbalance
- train/test split and cross-validation
- RandomForest
- feature engineering
- scaling
- precision, recall, F1, ROC-AUC
- calibration
- distribution shift
- proxy feature limitations

#### Risk scoring

- asset weight
- maximum severity
- confidence
- kill-chain bonus
- volume cap
- risk thresholds
- score explainability

#### RAG

- knowledge corpus
- lexical retrieval
- embeddings
- vector databases
- top-k context
- grounding
- citations
- hallucination reduction
- retrieval evaluation
- local model fallback

### Must be able to explain

Why the model is not blindly trusted, how RAG finds ATT&CK context, why current retrieval is offline lexical retrieval, and how it can later become an embedding/FAISS system.

## 5. Avantika — frontend and dashboard

### Main ownership

Streamlit user experience and analyst-visible product behavior.

### Read deeply

- `dashboard.py`
- `outputs/metrics.json`
- `outputs/incidents.json`
- `outputs/review_queue.csv`
- `assets.py`
- `PROJECT_DOCUMENTATION/DASHBOARD_AUDIT.md`

### Topics to know

- Streamlit reruns and caching
- pandas dataframes
- filters and selection state
- KPI design
- evidence-first interface design
- displaying uncertainty
- score breakdowns
- ATT&CK presentation
- analyst review workflow

### Must be able to demonstrate

Open the Command Center, find a cross-asset incident, display its score explanation and trace, then save a review disposition.

## 6. Arushi — MITRE content, summaries, and investigation

### Main ownership

ATT&CK accuracy, incident-story quality, recommendations, and investigation usability.

### Read deeply

- `mitre_map.py`
- `summarizer.py`
- `investigator.py`
- `rag.py`
- `scoring.py`

### Topics to know

- ATT&CK tactics and techniques
- evidence versus inference
- timeline reconstruction
- kill-chain progression
- next-stage prediction
- deterministic summaries
- prompt safety
- tool traces
- false-positive language

### Must be able to explain

How an incident timeline is constructed, why a technique is mapped to a particular ATT&CK ID, and how the brief avoids inventing evidence.

## 7. Aditi — QA, data quality, and DevOps

### Main ownership

Testing, dependencies, reproducibility, output validation, and reliable startup.

### Read deeply

- `tests/test_pipeline.py`
- `requirements.txt`
- `HOW_TO_RUN.md`
- `main.py`
- `dashboard.py`
- `model_eval.py`

### Topics to know

- unit tests
- integration tests
- regression tests
- schema validation
- deterministic runs
- fallback testing
- dependency management
- process exit codes
- performance timing
- demo readiness

### Must be able to demonstrate

Run the tests, compile the code, execute the pipeline, validate output counts, and start the dashboard from a clean terminal.

## 8. Dev — human loop, metrics, demo, and documentation

### Main ownership

Analyst workflow, auditability, MTTT, shift handover, documentation, and presentation.

### Read deeply

- `human_loop.py`
- `metrics.py`
- `retrain.py`
- `outputs/submission_summary.md`
- all files in `PROJECT_DOCUMENTATION/`

### Topics to know

- human-in-the-loop safety
- true positives and false positives
- escalation
- merge semantics
- audit logs
- feedback calibration
- MTTT versus total analyst time
- operational handover
- demo storytelling

### Must be able to explain

Why the system does not silently close serious incidents, how analyst feedback is recorded, and how the project calculates the claimed time reduction.

## 9. Cross-review map

| Work | Owner | Required reviewer |
|---|---|---|
| Graph and backend | Bhoomika | Aditi |
| ML, scoring, RAG | Ajasra | Bhoomika |
| Dashboard | Avantika | Bhoomika and Dev |
| ATT&CK and summaries | Arushi | Ajasra |
| Tests and setup | Aditi | Bhoomika and Ajasra |
| Human workflow and demo | Dev | Avantika and Bhoomika |

## 10. Final mastery standard

The team is ready when:

- each person can explain the full pipeline in five minutes
- each person can explain their own code in depth
- Bhoomika can debug graph/pipeline issues
- Ajasra can defend ML/RAG decisions and limitations
- Avantika can operate the dashboard
- Arushi can defend ATT&CK mappings and brief content
- Aditi can reproduce and validate the run
- Dev can explain human review and business impact

The goal is specialization without silos: everyone knows the complete system, and each person is the expert for one part.
