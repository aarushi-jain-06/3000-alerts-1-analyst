# QA Report — SOC Alert Triage Pipeline
**Author:** Aditi (Member 5 — QA, Testing, Data Quality, DevOps)
**Project:** 3,000 Alerts, One Analyst — Microsoft Hackathon 2026
**Date:** 7 October 2026
**Environment:** macOS (Apple Silicon), Python 3.14, `.venv`

---

## 1. Verification Checklist

| # | Check | Status | Detail |
|---|---|---|---|
| 1 | All tests pass | ✅ PASS | 6 original + 40 new = **46 total — all pass** |
| 2 | No compile errors | ✅ PASS | `python -m compileall -q .` exit code 0 |
| 3 | 3,000 alerts generated | ✅ PASS | `alerts.csv` has exactly 3,000 rows |
| 4 | Incidents generated (far fewer than alerts) | ✅ PASS | 289 incidents — **10.4× noise reduction** |
| 5 | All output files created | ✅ PASS | All 6 required files present in `outputs/` |
| 6 | Metrics consistent across files | ✅ PASS | `metrics.json`, `alerts.csv`, `incidents.json`, `review_queue.csv` all agree |
| 7 | Dashboard loads | ✅ PASS | `streamlit run dashboard.py` starts without errors |
| 8 | Cross-asset incidents exist | ✅ PASS | **15 cross-asset incidents** confirmed |
| 9 | Re-run with same seed gives same results | ✅ PASS | Alert IDs, risk scores, metrics — all identical |
| 10 | Setup works on a clean machine | ✅ PASS | Clean `.venv` + `pip install -r requirements.txt` + `brew install libomp` |

---

## 2. Environment Setup

### Installation steps (macOS clean machine)
```bash
cd "MICROSOFT HACKATHON"
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
brew install libomp          # Required for XGBoost on macOS (Apple Silicon)
python main.py
streamlit run dashboard.py
```

### Dependency versions installed
| Package | Version |
|---|---|
| pandas | 3.0.6 |
| numpy | 2.5.3 |
| scikit-learn | 1.9.1 |
| streamlit | 1.65.0 |
| plotly | 7.1.0 |
| requests | 2.34.2 |
| matplotlib | 3.11.2 |
| seaborn | 0.13.2 |
| xgboost | 3.4.1 |
| kagglehub | 1.0.2 |

> **macOS note:** XGBoost requires the OpenMP runtime (`libomp`). Install via `brew install libomp`. This is a one-time machine-level step, not a Python package, and is not in `requirements.txt`.

---

## 3. Pipeline Run Results

```
=== Pipeline complete ===
Alerts:             3,000
Incidents:          289
Noise reduction:    10.4×
MTTT per-alert:     4.88 min → 0.55 min  (-88.8%)
Total analyst time: 244.1 hrs → 27.3 hrs (-88.8%)
Wall time:          ~4.8 seconds
```

### Risk Tier Breakdown

| Tier | Count |
|---|---|
| CRITICAL | 31 |
| HIGH | 58 |
| MEDIUM | 123 |
| LOW | 77 |
| **Total** | **289** |

### MITRE ATT&CK Coverage (12 techniques observed)

```
T1003.001  T1046  T1053.005  T1059.001  T1071.001  T1071.004
T1078      T1110  T1200      T1204.002  T1486      T1547.001
```

- **15 cross-asset incidents** (lateral movement / C2 correctly grouped)
- **All 89 HIGH/CRITICAL incidents** carry a full 3-step investigation trace
- **All 289 incidents** carry a MITRE-grounded brief (zero empty briefs)

---

## 4. Data Quality & Schema Validation

| File | Expected | Actual | Status |
|---|---|---|---|
| `alerts.csv` rows | 3,000 | 3,000 | ✅ |
| `alerts.csv` fields | 11 required | All 11 present | ✅ |
| `incidents.json` records | 289 | 289 | ✅ |
| `incidents.json` required keys | 12 keys each | All 12 present | ✅ |
| Empty briefs | 0 | 0 | ✅ |
| `review_queue.csv` rows | 289 | 289 | ✅ |
| All queue entries PENDING (fresh run) | Yes | Yes | ✅ |
| `metrics.json` ↔ `alerts.csv` n_alerts | Match | 3000 = 3000 | ✅ |
| `metrics.json` ↔ `incidents.json` n_incidents | Match | 289 = 289 | ✅ |
| `review_queue.csv` rows = incidents | Match | 289 = 289 | ✅ |

---

## 5. Reproducibility

| Test | Result |
|---|---|
| Two full runs (3,000 alerts), seed=42 — alert IDs identical | ✅ True |
| Two full runs, seed=42 — risk scores identical | ✅ True |
| Two full runs, seed=42 — metrics dict identical | ✅ True |
| Seed=42 vs Seed=99 — sequences differ | ✅ True (expected) |

The pipeline is **fully deterministic** given the same seed.

---

## 6. Resilience Testing

### 6a. ML Model Missing (`severity_model.pkl` absent)

| Behaviour | Expected | Actual | Type |
|---|---|---|---|
| `is_available()` returns `False` | Yes | ✅ Yes | — |
| Pipeline continues without crash | Yes | ✅ Yes | Silent degradation |
| Confidence falls back to `1 − avg_FP_rate` | Yes | ✅ Yes (e.g. 0.95) | Silent degradation |
| `ml_confidence` flag set to `False` | Yes | ✅ Yes | Silent degradation |

**Answer — ML model missing:** Falls back to static confidence from `mitre_map.py` FP priors. Every incident is still scored, ranked, and briefed. No exception raised. `ml_confidence=False` on each incident flags this in the dashboard.

### 6b. RAG Corpus

| Behaviour | Expected | Actual | Type |
|---|---|---|---|
| Known technique retrieval | ≥1 relevant doc | ✅ 2 docs | Normal |
| Unknown/garbage query | ≥1 fallback doc | ✅ 1 doc | Silent graceful |
| Empty incident | ≥1 fallback doc | ✅ 1 doc | Silent graceful |

**Answer — RAG corpus missing:** The corpus is compiled into `mitre_map.py` source code. It cannot go missing at runtime. Deleting `mitre_map.py` would cause a loud `ModuleNotFoundError` at startup.

### 6c. LLM Summarizer Fallback

| Condition | Result |
|---|---|
| No `ANTHROPIC_API_KEY` | ✅ Deterministic template used |
| No `OLLAMA_MODEL` | ✅ Deterministic template used |
| Template brief quality | ✅ 721+ chars, contains MITRE IDs, timeline, and recommendation |

---

## 7. Loud Failures vs Silent Failures

| Scenario | Type | How it manifests |
|---|---|---|
| Invalid disposition string passed to `apply_disposition()` | **LOUD** — `ValueError` | `"Invalid disposition: <value>"` |
| Unknown `incident_id` passed to `apply_disposition()` | **LOUD** — `KeyError` | `"Incident X not found in queue"` |
| Unknown alert type in `technique_for()` | **LOUD** — `KeyError` | Crashes at alert generation |
| `model_eval.py` run without `cicids_clean.csv` | **LOUD** — `FileNotFoundError` | Crashes at line 86 |
| ML model file missing | **SILENT** | Static FP-rate confidence used; `ml_confidence=False` |
| External LLM unreachable | **SILENT** | Falls back to deterministic template; no crash |
| Unknown asset ID in scoring | **SILENT** | Defaults to MEDIUM weight (4); no log |
| Graph correlation fails on malformed alert | **SILENT** | Falls back to `group_by_asset_time()` |
| Empty alert batch passed to pipeline | **SILENT** | Returns `[]` incidents; no crash |

> **Risk:** Unknown asset IDs are silently defaulted to MEDIUM. If a production asset is not in `assets.py`, it will be silently mis-scored. Add a `warnings.warn()` in `criticality_weight()`.

> **Risk:** `model_eval.py` crashes on missing `cicids_clean.csv` with no user-friendly message. Add an existence check at the top.

---

## 8. Test Coverage

### Original (`tests/test_pipeline.py`) — 6 tests

| Test | Covers |
|---|---|
| `test_generation_is_reproducible` | Alert generation determinism |
| `test_graph_catches_cross_asset_connection` | Cross-asset entity graph correlation |
| `test_fallback_grouping_remains_available` | Legacy `group_by_asset_time()` |
| `test_pipeline_has_investigation_and_metrics` | Full pipeline integration |
| `test_merge_rescores` | `merge_incidents()` re-scoring |
| `test_disposition_is_applied` | Disposition queue update |

### New (`tests/test_extended.py`) — 40 tests

| Class | Area | Count |
|---|---|---|
| `TestRiskTierBoundaries` | Tier boundary values (CRITICAL/HIGH/MEDIUM/LOW) | 4 |
| `TestScoreIncident` | Score formula components | 6 |
| `TestRAGRetrieval` | Retrieval correctness and fallback | 4 |
| `TestSummarizerOffline` | Deterministic brief quality | 5 |
| `TestMTTTMetrics` | MTTT calculation correctness | 5 |
| `TestMLModelFallback` | ML model absent → graceful degradation | 2 |
| `TestHumanLoopFailureModes` | Disposition errors and queue correctness | 4 |
| `TestOutputFilesAndSchema` | Output file existence and schema | 7 |
| `TestPipelinePerformance` | Full run < 30 seconds | 1 |
| `TestReproducibility` | Same seed → same output; different seed → different output | 2 |

### **Total: 46 tests — all pass ✅**

```
Ran 46 tests in 22.6s

OK
```

---

## 9. Known Issues and Recommendations

| # | Issue | Severity | Recommendation |
|---|---|---|---|
| 1 | `sklearn` version mismatch warning (`severity_model.pkl` saved with 1.7.2, running 1.9.1) | Low (non-breaking) | Re-run `python train_classifier.py` on target machine to regenerate pickle with current sklearn |
| 2 | Unknown asset ID silently defaults to MEDIUM weight with no log | Low | Add `warnings.warn()` in `assets.py:criticality_weight()` |
| 3 | `model_eval.py` crashes with unhandled `FileNotFoundError` if `cicids_clean.csv` absent | Medium | Add `if not os.path.exists("cicids_clean.csv"): sys.exit(1)` guard |
| 4 | `feedback_log.csv` writes to project root; fails silently in read-only environments | Low | Document `FEEDBACK_LOG_PATH` env var in setup guide |

---

## 10. Performance Benchmark

| Metric | Value |
|---|---|
| Full 3,000-alert pipeline wall time | **~4.8 seconds** |
| Test-enforced SLO | < 30 seconds |
| Result | ✅ **PASS — 6× faster than SLO** |
| CPU | ~79% single core |

---

## 11. Files Delivered

| File | Location | Purpose |
|---|---|---|
| `test_extended.py` | `tests/test_extended.py` | 40 new automated QA tests |
| `QA_REPORT.md` | `PROJECT_DOCUMENTATION/QA_REPORT.md` | This report |

These two files are Aditi's primary QA contributions. Both should be committed to the shared repository.
