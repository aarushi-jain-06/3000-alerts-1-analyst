# How to Run — 3,000 Alerts, One Analyst

This guide matches the current Windows implementation.

## 1. Requirements

- Windows 10/11
- Python 3.9 or newer
- 8 GB RAM minimum; 16 GB recommended for model training
- Internet is not required for the normal run because the pretrained model and offline summary path are included

## 2. Install

```powershell
cd "D:\MICROSOFT HACKATHON"
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, use `.venv\Scripts\python.exe` directly.

## 3. Run the full pipeline

```powershell
python main.py
```

The pipeline:

1. Generates 3,000 reproducible alerts.
2. Builds an entity graph from assets and connection relationships.
3. Creates connected-component incidents.
4. Scores incidents using asset criticality, severity, confidence, kill-chain diversity, and capped volume.
5. Investigates HIGH and CRITICAL incidents.
6. Retrieves local MITRE ATT&CK context.
7. Generates grounded incident briefs.
8. Creates the human-review queue.
9. Calculates MTTT and analyst-time reduction.
10. Writes the results into `outputs/`.

Expected output is approximately:

```text
Alerts: 3000
Incidents: 289
Noise reduction ratio: 10.4x
MTTT per-alert: 4.88 min -> 0.55 min (-88.8%)
Total analyst time: 244.1 hrs -> 27.3 hrs (-88.8%)
```

## 4. Start the dashboard

In a second terminal:

```powershell
cd "D:\MICROSOFT HACKATHON"
.venv\Scripts\Activate.ps1
streamlit run dashboard.py
```

Open `http://localhost:8501`.

The dashboard reads the latest files from `outputs/`. Run `python main.py` first for fresh data.

### Dashboard pages

- **Command Center** — totals, MTTT, tiers, and cross-asset incidents
- **Incidents Explorer** — filters, score, evidence, correlation method, impacted assets, and investigation traces
- **Predict** — CSV or manual alert ML inference
- **Review Queue** — analyst dispositions and audit feedback
- **Analytics** — tiers, MTTT, frequencies, asset heatmap, and model history
- **Assets & MITRE** — asset criticality and ATT&CK coverage

## 5. Run the submission package

```powershell
python final_prediction.py
```

This refreshes alerts, incidents, review queue, shift brief, MTTT metrics, machine-readable metrics, flat predictions, and submission summary under `outputs/`.

## 6. Test the project

```powershell
python -m unittest discover -s tests -v
python -m compileall -q .
```

Tests cover reproducibility, graph correlation, fallback grouping, pipeline output, merge re-scoring, and human dispositions.

## 7. Optional ML retraining and evaluation

The pretrained model is included. Retraining is optional:

```powershell
python train_classifier.py
python model_eval.py
```

Training may download CICIDS2017 through KaggleHub and requires more time and memory. Evaluation outputs are written to `outputs/`.

## 8. Optional free/local AI summaries

The default deterministic brief requires no external service. With Ollama:

```powershell
$env:OLLAMA_MODEL = "llama3.2:3b"
$env:OLLAMA_HOST = "http://localhost:11434"
python main.py
```

The system retrieves ATT&CK context first and falls back to a deterministic template if Ollama fails. An optional Anthropic path is available through `ANTHROPIC_API_KEY`; never commit API keys.

## 9. Output files

| File | Purpose |
|---|---|
| `alerts.csv` | Raw normalized alerts |
| `incidents.json` | Ranked incidents, evidence, and investigation traces |
| `review_queue.csv` | Human-review state |
| `feedback_log.csv` | Analyst feedback audit log |
| `metrics.json` | Dashboard metrics |
| `shift_brief.md` | Top incidents for the next shift |
| `mttt_metrics.md` | Before/after MTTT comparison |
| `final_predictions.csv` | Flat incident prediction table |
| `submission_summary.md` | Presentation-ready run summary |

## 10. Troubleshooting

### Missing module

```powershell
pip install -r requirements.txt
```

### Model unavailable

Confirm `severity_model.pkl` exists. The pipeline can still use static confidence fallback.

### Dashboard shows old numbers

Run `python main.py`, refresh the browser, and restart Streamlit if necessary because data is cached.

### Port 8501 is in use

```powershell
streamlit run dashboard.py --server.port 8502
```

### Training is too slow

Use the included pretrained model. Training is not needed for the normal demo.

### Ollama is unavailable

```powershell
Remove-Item Env:OLLAMA_MODEL -ErrorAction SilentlyContinue
Remove-Item Env:OLLAMA_HOST -ErrorAction SilentlyContinue
```

## 11. Final pre-demo checklist

```powershell
python -m unittest discover -s tests -v
python main.py
streamlit run dashboard.py
```

Verify that the dashboard shows the Cross-Asset KPI, correlation method, impacted assets, score explanation, ATT&CK context, investigation traces, and review disposition controls.
