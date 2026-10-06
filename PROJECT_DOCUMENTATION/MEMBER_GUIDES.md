# Member-by-Member Master Guide

This guide explains what each member owns, what they must study, which files they must understand, and how their work connects to the other roles.

## Shared foundation — every member must know this

```text
raw alert → graph relationship → incident → enrichment → risk score
          → investigation → grounded brief → human review → metrics
```

Everyone should study:

- `PROJECT.md`
- `FULL_ARCHITECTURE.md`
- `CODEBASE_AND_RUNNING.md`
- `pipeline.py`
- `main.py`
- `assets.py`
- `mitre_map.py`
- the incident schema in `grouping.py`
- `outputs/submission_summary.md`

Every member should be able to answer:

1. Why is an incident better than a raw alert?
2. Why does asset criticality matter?
3. How does graph correlation find cross-asset activity?
4. What does ML contribute?
5. Why does a human still approve dispositions?
6. How is MTTT measured?

## Experienced Member 1 — Technical Lead, Backend, Graph Correlation

### Mission

Own the system contract and ensure the entire pipeline works as one reliable product.

### Primary codebase

- `pipeline.py`
- `main.py`
- `grouping.py`
- `alert_generator.py`
- `assets.py`
- `human_loop.py` merge workflow
- `tests/test_pipeline.py`

### Concepts to master

- normalized event schemas
- graph entities and connected components
- union-find/disjoint-set data structures
- time-window correlation
- cross-asset lateral movement
- incident lifecycle
- data contracts between modules
- deterministic execution and graceful fallbacks
- integration testing and performance

### Responsibilities

1. Define the normalized alert and incident contracts.
2. Own entity graph behavior and the asset/time fallback.
3. Verify that graph correlation does not over-merge unrelated alerts.
4. Ensure cross-asset incidents use the most critical impacted asset.
5. Integrate scoring, investigation, summarization, human review, and metrics.
6. Review changes that modify shared schemas.
7. Keep `python main.py` reliable.

### Must understand in `grouping.py`

- `CORRELATION_WINDOW`
- `group_alerts_into_incidents()`
- `group_alerts_graph()`
- `group_by_asset_time()`
- entity keys
- connected components
- `correlation_method`
- `assets` versus primary `asset_id`

### Handoffs

- Member 2 receives stable incident objects for ML, scoring, and RAG.
- Member 3 receives stable fields for the dashboard.
- Member 5 receives testable pipeline entry points.
- Member 6 receives workflow and metric outputs.

### Demo explanation

“We connect alerts that share assets or connection evidence inside a time window, so a multi-host attack becomes one explainable incident.”

## Experienced Member 2 — ML, Risk Scoring, Model Evaluation, and RAG Lead

### Mission

Own the analytical intelligence layer: ML inference, risk prioritization, evaluation, and retrieval-grounded context.

### Primary codebase

- `train_classifier.py`
- `ml_classifier.py`
- `scoring.py`
- `model_eval.py`
- `rag.py`
- `retrain.py`
- `mitre_map.py` as retrieval source data
- `summarizer.py` integration points

### Concepts to master

#### Machine learning

- supervised binary classification
- malicious versus benign labels
- class imbalance
- stratified train/test splits
- feature engineering and scaling
- RandomForest and XGBoost
- precision, recall, F1, ROC-AUC
- false-positive and false-negative rates
- calibration and probability interpretation
- distribution shift
- proxy features and limitations

#### Risk scoring

- business impact versus technical severity
- criticality weighting
- confidence blending
- kill-chain diversity
- capped volume influence
- risk tiers
- score explainability

#### RAG

- corpus construction
- document chunking
- lexical retrieval
- embeddings and vector similarity
- top-k retrieval
- grounding and citations
- retrieval relevance
- hallucination control
- local versus hosted models
- safe fallback behavior

### Responsibilities

1. Maintain CICIDS2017 training and evaluation.
2. Explain why CICIDS metrics are not automatically production alert metrics.
3. Maintain the hybrid confidence strategy in `scoring.py`.
4. Review risk thresholds and tier distribution.
5. Own the RAG retrieval interface in `rag.py`.
6. Maintain corpus quality and retrieval relevance with Member 4.
7. Test that retrieved context is relevant to the incident.
8. Ensure summaries do not receive unsupported facts.
9. Own ML/RAG limitations in the judge presentation.

### Must understand

In `scoring.py`: `_confidence()`, `_kill_chain_bonus()`, `predict_next_stage()`, `score_incident()`, and `risk_tier()`.

In `rag.py`: `_tokens()`, `retrieve()`, `context_for_incident()`, and the replacement path for sentence-transformers/FAISS.

### Handoffs

- Member 1 supplies incident schema and graph outputs.
- Member 4 supplies accurate ATT&CK descriptions and brief requirements.
- Member 3 displays score explanations and retrieval evidence.
- Member 5 validates model and retrieval regressions.

### Demo explanation

“ML is a supporting signal, not a black-box verdict. We combine it with false-positive priors, asset criticality, severity, and attack-stage diversity. RAG adds relevant ATT&CK knowledge to the brief.”

## Member 3 — Frontend and SOC Dashboard

### Primary codebase

- `dashboard.py`
- `outputs/*.json`
- `outputs/*.csv`
- `outputs/*.md`
- `assets.py`

### Mission

Make the system usable by an analyst and visually convincing to judges.

### Concepts

- Streamlit execution and caching
- pandas dataframes
- filtering and selection state
- KPI design
- evidence-first UX
- uncertainty display
- safe HTML rendering
- analyst workflow design

### Responsibilities

1. Show current values from `outputs/metrics.json`.
2. Display graph correlation, correlation method, and impacted assets.
3. Show score decomposition, ATT&CK techniques, timeline, next stage, and traces.
4. Provide review disposition controls.
5. Keep all claims synchronized with generated output.
6. Test the dashboard from a clean start.

### Handoffs

- Member 1 defines field names.
- Member 2 defines score/model/RAG explanations.
- Member 4 defines security wording.
- Member 6 defines analyst workflow language.

## Member 4 — MITRE Content, Briefs, and Investigation Experience

### Primary codebase

- `mitre_map.py`
- `summarizer.py`
- `investigator.py`
- ATT&CK content supplied to `rag.py`

### Mission

Make security content accurate and understandable. Member 2 owns retrieval implementation; Member 4 owns the ATT&CK knowledge quality, brief design, and investigation experience.

### Concepts

- ATT&CK tactics and techniques
- evidence versus inference
- timeline reconstruction
- next-stage prediction
- prompt safety
- deterministic summarization
- tool traces
- false-positive language

### Responsibilities

1. Maintain alert-to-technique mappings.
2. Write concise ATT&CK descriptions and examples.
3. Supply accurate documents for Member 2's retrieval layer.
4. Design brief structure and recommendations.
5. Ensure summaries cite available evidence.
6. Create realistic attack-story examples.
7. Make investigation traces useful rather than decorative.

## Member 5 — QA, Testing, Data Quality, and DevOps

### Primary codebase

- `tests/test_pipeline.py`
- `requirements.txt`
- `HOW_TO_RUN.md`
- `model_eval.py`
- output writers in `main.py` and `final_prediction.py`

### Mission

Make the demo reproducible and prevent silent correctness failures.

### Concepts

- unit versus integration tests
- deterministic seeds
- schema validation
- regression testing
- dependency management
- startup diagnostics
- performance measurement
- model/RAG fallback testing

### Responsibilities

1. Run tests before every demo.
2. Validate output schemas and row counts.
3. Test graph over-merge and under-merge cases.
4. Test unknown assets and empty input.
5. Test ML, RAG, and LLM fallback paths.
6. Verify dashboard startup.
7. Maintain clean setup instructions.

## Member 6 — Human Loop, Metrics, Demo, and Documentation

### Primary codebase

- `human_loop.py`
- `metrics.py`
- `retrain.py`
- `PROJECT.md`
- `BACKEND_ML_PRACTICAL.md`
- `FULL_ARCHITECTURE.md`
- `TEAM_ROLES.md`
- `MEMBER_GUIDES.md`
- `CODEBASE_AND_RUNNING.md`

### Mission

Connect the engineering work to the analyst's workflow and the judge's evaluation criteria.

### Concepts

- triage workflow
- human-in-the-loop safety
- audit trails
- true/false positives
- escalation and merging
- MTTT versus total analyst time
- handover communication
- demo storytelling
- documentation accuracy

### Responsibilities

1. Own disposition semantics and audit requirements.
2. Maintain MTTT formulas and assumptions.
3. Create the shift-handover narrative.
4. Keep documentation synchronized with code.
5. Lead the five-minute presentation.
6. Prepare judge questions and answers.

## Final ownership rule

The role owner implements. The reviewer verifies. The entire team learns enough to explain the complete system.
