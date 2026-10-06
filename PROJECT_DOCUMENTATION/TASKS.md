# Tasks & Implementation Status

Status key: ✅ Done &nbsp; 🟡 Partial &nbsp; ⬜ Not started

## Feature Checklist (vs. original 10-feature brief)

| # | Feature | Status | File(s) | Note |
|---|---|---|---|---|
| 1 | Graph-based correlation (user/device/IP/time) | ✅ | `grouping.py` | Entity graph with asset + connection edges and legacy fallback |
| 2 | Asset criticality-based risk scoring | ✅ | `scoring.py` | criticality × severity × kill-chain-bonus × confidence, alert count capped low |
| 3 | MITRE ATT&CK mapping | ✅ | `mitre_map.py` | Every alert type → technique ID + tactic |
| 4 | AI incident brief | ✅ | `rag.py`, `summarizer.py` | Local ATT&CK retrieval plus optional Ollama/Anthropic rewrite |
| 5 | Evidence-linked reasoning (brief cites alert IDs) | ✅ | `summarizer.py` | Alert IDs, timeline, and ATT&CK context included |
| 6 | Human-in-the-loop (Confirm/Reject/Escalate/Merge/FP) | ✅ | `human_loop.py` | Dispositions, merge re-scoring, and feedback logging |
| 7 | False-positive intelligence (learns from repeat FPs) | ⬜ | — | Needs trained classifier + active-learning loop — **Phases 2 & 6** |
| 8 | Attack story reconstruction (ordered timeline) | ✅ | `summarizer.py` | Ordered alert/technique chain in every brief |
| 9 | Kill-chain gap / next-step prediction | ✅ | `scoring.py` | Canonical ATT&CK stage heuristic |
| 10 | Shift handover + metrics | ✅ | `main.py` → `shift_brief.md`, `mttt_metrics.md` | Incident reduction ratio + MTTT before/after both computed |

## What's Fully Implemented Right Now

- Synthetic alert generator: reproducible 3,000 alerts/24h window, 6 seeded multi-stage
  attack chains on CRITICAL/HIGH assets (`alert_generator.py`)
- Asset criticality registry, 18 assets across 4 tiers (`assets.py`)
- MITRE ATT&CK mapping for 13 alert types (`mitre_map.py`)
- Entity-graph correlation into incidents with asset/time fallback (`grouping.py`)
- Risk scoring with kill-chain-span bonus (`scoring.py`)
- Grounded ATT&CK retrieval and template/optional local LLM incident briefs
  (`rag.py`, `summarizer.py`)
- Human-in-the-loop review queue with merge, audit feedback, and PENDING,
  with auto-*suggested* (never automatic) close for low-risk/high-FP
  incidents (`human_loop.py`)
- MTTT before/after measurement comparing manual per-alert triage vs.
  per-incident review (`metrics.py`)
- End-to-end orchestration writing `alerts.csv`, `incidents.json`,
  `review_queue.csv`, `shift_brief.md`, `mttt_metrics.md`
  (`pipeline.py`, `main.py`)

Last full run: 3,000 alerts → 289 incidents (10.4x reduction), MTTT per-alert
4.88 min → 0.55 min (−88.8%).

## Build Phases — What's Left, In Order

### Phase 0 — Environment Setup
- [ ] venv + install `pandas numpy scikit-learn xgboost sentence-transformers faiss-cpu streamlit requests`
- [ ] Pick and provision an LLM API key
- [ ] Everyone runs `main.py` once as a sanity check

### Phase 1 — CICIDS2017 Data Prep
- [ ] Download CICIDS2017 (or Kaggle mirror)
- [ ] Select 2–3 days covering benign + 2–3 attack types (~50–80k rows)
- [ ] Clean column names, handle `Infinity`/`NaN` rows
- [ ] Collapse label to binary `is_malicious` + keep multi-class `attack_type`
- [ ] Select ~15–20 interpretable features
- [ ] Output `cicids_clean.csv`

### Phase 2 — Trained Classifier
- [ ] Stratified train/test split
- [ ] Train `RandomForestClassifier` (baseline), compare `XGBClassifier`
- [ ] Evaluate with `classification_report`, prioritize recall on malicious class
- [ ] Map CICIDS `attack_type` values to existing MITRE technique IDs in `mitre_map.py`
- [ ] Save model (`severity_model.pkl`)
- [ ] New file `ml_classifier.py`: `load_model()`, `predict_malicious_proba()`
- [ ] Wire into `scoring.py`'s `_confidence()`, with fallback to static table

### Phase 3 — Graph-Based Correlation
- [ ] Build alert graph with `networkx` (edges: shared asset, shared IP, same time window)
- [ ] Cluster via `connected_components()`, replacing per-asset loop
- [ ] Keep old function as documented fallback (`group_by_asset_time()`)
- [ ] Add one cross-asset seeded attack chain to prove the upgrade works

### Phase 4 — RAG Copilot
- [ ] Add `description` field to each MITRE technique in `mitre_map.py`
- [ ] Generate 50–100 synthetic past-incident write-ups (LLM, one-time)
- [ ] Embed both corpora with `sentence-transformers` (`all-MiniLM-L6-v2`)
- [ ] New file `rag.py`: `retrieve(query, k=3) -> List[str]`
- [ ] Update `summarizer.py` prompt to inject retrieved chunks + ask for citation

### Phase 5 — Agentic Investigator
- [ ] Define tool functions: `check_asset_inventory`, `check_ip_reputation`,
      `search_similar_incidents`, `get_recent_alerts_for_asset`
- [ ] New file `agent.py`: hand-rolled ReAct loop, cap 5 iterations
- [ ] Log every tool call + result as `investigation_trace` on the incident
- [ ] Gate: only run the full agent loop for HIGH/CRITICAL-tier incidents

### Phase 6 — Active-Learning Feedback Loop
- [ ] Log every analyst disposition to `feedback_log.csv` in `human_loop.py`
- [ ] New file `retrain.py`: `retrain_if_ready(threshold=20)`
- [ ] Track `(timestamp, n_samples, f1_score)` in `retrain_history.csv`
- [ ] Call retrain check at end of each `main.py` run

### Phase 7 — Attack Story + Next-Step Prediction
- [ ] Narrate `cluster["alerts"]` as an ordered arrow-chain in the brief
- [ ] Build tactic transition table (canonical kill-chain order or learned)
- [ ] New function `predict_next_stage()` in `scoring.py`
- [ ] Add hedged "possible next stage" line to brief

### Phase 8 — Evidence Citation + Merge Action
- [ ] Print `alert_ids` directly in the brief template
- [ ] Add `MERGE` to `VALID_DISPOSITIONS` in `human_loop.py`
- [ ] New function `merge_incidents()`: combine two incidents, re-score, mark originals `MERGED`

### Phase 9 — Dashboard + Demo Prep
- [ ] Streamlit app: sortable incident table, click-through to brief + trace
- [ ] Plot `retrain_history.csv` F1-over-time
- [ ] Display before/after MTTT panel from `metrics.py`
- [ ] Rehearse 5-minute demo script

### Phase 10 — Final Integration
- [ ] Merge order: graph correlation → ML scoring → agent/RAG briefing →
      next-step prediction → human-loop queue with merge
- [ ] Full-batch timing test; confirm agent gating is working (not running
      on all 300+ incidents)
- [ ] Freeze code 2 hours before submission; remaining time = demo rehearsal only

## Future Implementation (post-hackathon / stretch goals)

- Replace static IP-reputation blocklist with a live threat-intel API
- Extend MITRE mapping from 13 alert types to full ATT&CK Enterprise matrix
- Replace synthetic past-incident corpus with real historical ticket data
  (if deployed at an actual MSSP)
- Swap `RandomForestClassifier`/`XGBClassifier` for a fine-tuned DistilBERT
  on textified alert descriptions, if time/compute allows
- Multi-tenant asset registry pulled live from a real CMDB (ServiceNow,
  Lansweeper) instead of the static dict in `assets.py`
- Ticketing-system integration (Jira/ServiceNow) for `human_loop.py`
  dispositions instead of CSV-based logging
