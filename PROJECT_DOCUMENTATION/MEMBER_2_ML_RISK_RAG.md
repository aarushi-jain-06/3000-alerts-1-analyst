# Member 2 — ML, Risk Scoring, Model Evaluation, and RAG

## Own

`train_classifier.py`, `ml_classifier.py`, `scoring.py`, `model_eval.py`, `rag.py`, `retrain.py`, model claims, risk thresholds, retrieval quality, and grounding evaluation.

## Study first

1. `BACKEND_ML_PRACTICAL.md`
2. `FULL_ARCHITECTURE.md`
3. `ml_classifier.py`
4. `scoring.py`
5. `rag.py`
6. `train_classifier.py`
7. `model_eval.py`

## ML concepts

- supervised classification
- malicious/benign labels
- class imbalance
- stratified splits
- feature engineering
- scaling
- RandomForest and XGBoost
- precision, recall, F1, ROC-AUC
- false-positive and false-negative rates
- calibration
- distribution shift
- proxy features

## Risk concepts

- technical severity versus business impact
- asset criticality
- hybrid confidence
- kill-chain diversity
- capped alert volume
- score decomposition
- risk tiers

## RAG concepts

- corpus quality
- lexical retrieval
- embeddings and vector search
- top-k context
- grounding
- citations
- retrieval relevance
- hallucination prevention
- local model fallback

## Implementation responsibilities

- Maintain CICIDS training and evaluation.
- Keep ML as a supporting signal, not an unexplained verdict.
- Own `_confidence()`, kill-chain bonuses, tier thresholds, and next-stage prediction.
- Own `retrieve()` and `context_for_incident()` in `rag.py`.
- Test that retrieved ATT&CK context matches incident techniques/tactics.
- Explain that CICIDS metrics are not automatically production SOC-alert metrics.
- Review feedback calibration safety.

## Must demonstrate

Show one score breakdown, one evaluation chart, the ATT&CK retrieval context, and the model fallback behavior.

## Handoffs

Receive incident objects from Member 1, ATT&CK content from Member 4, display requirements from Member 3, and regression checks from Member 5.
