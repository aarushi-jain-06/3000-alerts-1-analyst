# Backend and ML — Practical Deep Guide

This document explains exactly what happens when the project runs, how each backend module behaves, and what the machine-learning model does and does not do.

## 1. Runtime entry point

The normal command is:

```powershell
python main.py
```

`main.py` calls:

```python
result = run_pipeline(total_alerts=3000, n_seeded_chains=6)
```

`run_pipeline()` performs these stages:

```text
generate_alerts()
    → group_alerts_into_incidents()
    → score_and_rank()
    → investigate(high/critical only)
    → generate_brief()
    → build_review_queue()
    → summarize_metrics()
```

The result is written into CSV, JSON, and Markdown files.

## 2. Alert generation

`alert_generator.py` creates alert dictionaries. A typical alert looks like this:

```python
{
    "alert_id": "A-00001",
    "timestamp": "2026-09-26T08:04:38",
    "asset_id": "DC01",
    "alert_type": "lsass_access",
    "src_ip": "10.20.1.5",
    "dst_ip": "10.20.0.1",
    "technique_id": "T1003.001",
    "technique_name": "LSASS Memory Access",
    "tactic": "Credential Access",
    "base_severity": 9,
    "false_positive_rate": 0.20
}
```

The generator uses a local random seed and resets an alert counter on every run. Therefore, the same seed produces the same alert content and IDs.

Six seeded attack chains are mixed into the noise. Examples include:

```text
impossible travel
    → failed logon spike
    → LSASS access
```

and:

```text
PowerShell
    → registry run key
    → scheduled task
    → ransomware note
```

These chains allow the demo to prove that correlation and scoring find multi-stage behavior.

## 3. Graph correlation in practice

`grouping.py` builds connected components using a union-find data structure.

Each alert contributes graph entities:

```text
asset:DC01
connection:10.20.1.5→10.20.0.1
```

For each entity, alerts are sorted by timestamp. Consecutive alerts within 20 minutes are joined. After all joins are complete, alerts with the same root node form one connected component.

This gives two useful behaviors:

1. Multiple alerts on the same asset become one incident.
2. Alerts on different assets can become one incident when they share a connection path.

Each incident stores:

- `assets`
- `alert_ids`
- `start_time`
- `end_time`
- `techniques`
- `tactics`
- `correlation_method`
- original `alerts`

The old asset/time method remains available as `group_by_asset_time()` and is used as a safe fallback if malformed data causes graph correlation to fail.

## 4. Asset criticality

`assets.py` is the business-context layer. Security severity alone is not enough.

For example:

```text
LSASS access on a printer:
    severity 9 × asset weight 1

LSASS access on a domain controller:
    severity 9 × asset weight 10
```

The domain-controller incident should be prioritized first because the business impact is much greater.

For cross-asset incidents, `scoring.py` uses the maximum criticality weight among all impacted assets.

## 5. Risk scoring formula

The implementation uses this conceptual formula:

```text
risk_score =
    asset_weight
    × maximum_alert_severity
    × confidence
    × kill_chain_bonus
    × volume_factor
```

### Confidence

The static confidence is:

```text
confidence = 1 − average(false_positive_rate)
```

The ML model may provide a boost when its average malicious probability is above 0.5. The boost is capped at 0.20 and the final confidence is capped at 0.99.

This is deliberately a hybrid design. Static SOC priors remain the safety floor because the synthetic alerts do not contain raw CICIDS network-flow fields.

### Kill-chain bonus

```text
one tactic       → 1.0×
two tactics      → 1.2×
three+ tactics   → 1.5×
```

This rewards multi-stage behavior without allowing alert volume alone to dominate.

### Volume factor

```python
min(1 + 0.02 * (alert_count - 1), 1.3)
```

Alert count can help slightly, but its maximum effect is only 1.3×.

### Risk tiers

The score is normalized against the maximum theoretical score:

```text
45% and above → CRITICAL
25% and above → HIGH
10% and above → MEDIUM
below 10%     → LOW
```

## 6. Machine learning training

`train_classifier.py` trains a RandomForest classifier using CICIDS2017.

The training flow is:

1. Download or load CICIDS2017.
2. Normalize column names.
3. Replace infinite values with nulls.
4. Remove invalid rows.
5. Convert the label into `is_malicious`.
6. Select up to 20 numeric flow features.
7. Balance the training sample for practical training time.
8. Perform a stratified 80/20 split.
9. Fit a `StandardScaler`.
10. Train RandomForest and optionally XGBoost.
11. Select the best model by malicious-class F1.
12. Save the model bundle to `severity_model.pkl`.

The bundle contains:

```python
{
    "model": trained_classifier,
    "scaler": fitted_scaler,
    "features": feature_names,
    "name": "RandomForest",
    "f1": 0.9567
}
```

## 7. Machine learning inference

`ml_classifier.py` loads the model once and keeps it in memory.

If raw CICIDS features are present, they can be used directly. For synthetic alerts, `_engineer_proxy_features()` derives approximate flow-like features from:

- base severity
- false-positive rate
- tactic stage

Examples of derived proxy behavior:

- higher severity increases packet and payload proxies
- lower false-positive rate increases maliciousness proxy
- later kill-chain tactics produce higher threat-stage values

This keeps the pipeline compatible with the trained model, but it is important to understand the limitation:

> CICIDS evaluation metrics describe network-flow classification, not a validated production classifier for synthetic SOC alert dictionaries.

The project therefore uses ML as a supplemental confidence signal and retains deterministic static priors as the main safety floor.

## 8. Model evaluation

`model_eval.py` produces:

- held-out classification report
- precision
- recall
- malicious-class F1
- ROC-AUC
- confusion matrix
- false-positive rate
- false-negative rate
- five-fold cross-validation
- learning curve
- feature importance

Current recorded model results include:

```text
F1:       0.9567
ROC-AUC:  0.9981
Recall:   0.9598
FNR:      4.02%
FPR:      0.66%
```

## 9. Retrieval and summaries

`rag.py` is a small offline retrieval layer. It tokenizes the incident's techniques and tactics, compares them against local ATT&CK descriptions, and returns the highest-overlap documents.

The interface is intentionally simple:

```python
retrieve(query, k=3)
context_for_incident(incident, k=3)
```

This can later be replaced with:

- sentence-transformers embeddings
- FAISS
- official ATT&CK STIX/TAXII data
- a historical incident corpus

The rest of the application does not need to change.

`summarizer.py` supports three modes:

1. deterministic template — always available
2. Ollama/local model — free and local
3. Anthropic API — optional external provider

All model failures fall back to the deterministic template.

## 10. Investigation backend

`investigator.py` is a bounded tool runner. It runs only for `HIGH` and `CRITICAL` incidents.

Current tools:

- `check_asset_inventory()`
- `get_recent_alerts_for_asset()`
- `check_ip_reputation()`

The reputation tool returns `UNKNOWN` in offline mode instead of inventing a threat verdict.

Every call is captured as:

```python
{
    "step": 1,
    "tool": "check_asset_inventory",
    "result": [...]
}
```

This trace makes the investigation explainable and auditable.

## 11. Human feedback and retraining

`human_loop.apply_disposition()` updates the review queue and appends a row to `feedback_log.csv`.

The feedback record includes:

- timestamp
- incident ID
- risk tier
- risk score
- asset ID
- disposition
- analyst
- notes

After enough labels exist, `retrain.py` can fit an incident-level logistic calibration model using risk score and analyst labels. It is kept separate from the CICIDS flow model because incident feedback does not contain raw network-flow features.

## 12. Testing

Run:

```powershell
python -m unittest discover -s tests -v
```

The tests validate:

- deterministic generation
- cross-asset graph correlation
- legacy fallback availability
- pipeline output creation
- merge re-scoring
- analyst disposition application

