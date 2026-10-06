# Codebase and Running Guide

This is the operational guide for understanding, running, testing, and presenting the project.

## 1. Repository map

```text
MICROSOFT HACKATHON/
├── alert_generator.py          synthetic alert source
├── assets.py                   asset registry and criticality
├── mitre_map.py                ATT&CK mappings and descriptions
├── grouping.py                 graph correlation and fallback
├── scoring.py                  risk formula and tiers
├── ml_classifier.py            model loading and inference
├── train_classifier.py         CICIDS2017 training
├── model_eval.py               ML evaluation
├── rag.py                      local ATT&CK retrieval
├── summarizer.py               grounded briefs and optional LLM
├── investigator.py             high-risk investigation tools
├── human_loop.py               review queue and feedback
├── retrain.py                  feedback calibration
├── metrics.py                  MTTT calculations
├── pipeline.py                 orchestration
├── main.py                     normal run command
├── final_prediction.py         submission package command
├── dashboard.py                Streamlit frontend
├── tests/                      automated tests
├── outputs/                    generated runtime artifacts
├── severity_model.pkl          trained model bundle
├── cicids_clean.csv            prepared training data
├── requirements.txt            Python dependencies
├── PROJECT.md                  project-level guide
├── BACKEND_ML_PRACTICAL.md     backend and ML guide
├── FULL_ARCHITECTURE.md        architecture guide
├── TEAM_ROLES.md               six-person team structure
└── MEMBER_GUIDES.md            study guide for every member
```

## 2. Installation

Use Python 3.9 or newer.

```powershell
cd "D:\MICROSOFT HACKATHON"
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, run the environment's Python directly:

```powershell
.venv\Scripts\python.exe main.py
```

## 3. Normal pipeline run

```powershell
python main.py
```

The command:

1. generates 3,000 reproducible alerts
2. creates the entity graph
3. creates connected-component incidents
4. scores and ranks incidents
5. investigates high and critical incidents
6. generates grounded briefs
7. creates the human review queue
8. calculates MTTT
9. writes `outputs/`

Expected output is approximately:

```text
Alerts: 3000
Incidents: 289
Noise reduction ratio: 10.4x
MTTT per-alert: 4.88 min -> 0.55 min (-88.8%)
Total analyst time: 244.1 hrs -> 27.3 hrs (-88.8%)
```

## 4. Dashboard

```powershell
streamlit run dashboard.py
```

Open `http://localhost:8501`.

The dashboard reads generated files from `outputs/`; run `python main.py` first for fresh data.

### Pages

- Command Center — totals, MTTT, tiers, and cross-asset incidents
- Incidents Explorer — filters, score, evidence, correlation method, impacted assets
- Predict — CSV or manual alert ML inference
- Review Queue — analyst dispositions and audit feedback
- Analytics — tiers, MTTT, frequency, asset heatmap, model history
- Assets & MITRE — asset criticality and ATT&CK coverage

## 5. Optional training

The pretrained model is included. Retraining is optional:

```powershell
python train_classifier.py
```

This may download CICIDS2017 through KaggleHub and requires more memory and time.

## 6. Model evaluation

```powershell
python model_eval.py
```

Outputs include the evaluation report, confusion matrix, ROC curve, cross-validation results, learning curve, and feature importance.

## 7. Submission package

```powershell
python final_prediction.py
```

This produces alerts, incidents, the review queue, shift brief, MTTT metrics, flat predictions, and submission summary.

## 8. Optional free/local AI summaries

The default template requires no external service. With Ollama:

```powershell
$env:OLLAMA_MODEL = "llama3.2:3b"
$env:OLLAMA_HOST = "http://localhost:11434"
python main.py
```

The system retrieves ATT&CK context first, sends it to the model, and falls back to a deterministic brief on any error.

## 9. Testing

```powershell
python -m unittest discover -s tests -v
python -m compileall -q .
```

Tests cover reproducibility, graph correlation, fallback grouping, pipeline output, merging, and analyst dispositions.

## 10. Code reading order

1. `PROJECT.md`
2. `FULL_ARCHITECTURE.md`
3. `alert_generator.py`
4. `mitre_map.py`
5. `assets.py`
6. `grouping.py`
7. `scoring.py`
8. `investigator.py`
9. `rag.py`
10. `summarizer.py`
11. `human_loop.py`
12. `metrics.py`
13. `pipeline.py`
14. `main.py`
15. `dashboard.py`

Then read the role-specific path in `MEMBER_GUIDES.md`.

## 11. Troubleshooting

### Missing module

```powershell
pip install -r requirements.txt
```

### Model unavailable

The pipeline falls back to static confidence. Confirm that `severity_model.pkl` exists in the project root.

### Dashboard shows old data

Run `python main.py`, reload the browser, and restart Streamlit if necessary because the dashboard caches loaded data.

### Port already in use

```powershell
streamlit run dashboard.py --server.port 8502
```

### Training is too slow

Use the included pretrained model. Training is not required for the normal demo.

### Ollama is unavailable

Unset `OLLAMA_MODEL`; deterministic summaries continue to work.

## 12. Final pre-demo checklist

```powershell
python -m unittest discover -s tests -v
python main.py
streamlit run dashboard.py
```

Verify:

- dashboard loads
- cross-asset KPI is visible
- a cross-asset incident can be opened
- ATT&CK context is shown
- high/critical traces exist
- a review disposition can be saved
- `outputs/submission_summary.md` matches the latest run
- every speaker can explain their assigned role and the full architecture
