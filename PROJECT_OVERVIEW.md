# Project Overview — "3,000 Alerts, One Analyst"

## Problem Statement

A tier-1 SOC analyst at a managed security provider faces thousands of
alerts a day, most of them false positives. The challenge: build a tool
that ingests a batch of alerts, groups related ones into incidents, ranks
them by risk / asset criticality (not just alert count), writes a short
brief per incident for the next shift, maps everything to MITRE ATT&CK,
keeps a human in the loop, and measurably reduces mean-time-to-triage (MTTT).

## Why This Approach

Most teams solving this problem will do one of two things: (a) a purely
rule-based pipeline with no real ML, or (b) a single LLM call per alert
with no grounding, no correlation logic, and no measurable improvement.
This project does neither — it combines:

- **Deterministic, auditable correlation and scoring** (so the ranking
  logic can be explained to a judge or a compliance auditor line by line)
- **Real trained ML** on a public labeled intrusion-detection dataset
  (CICIDS2017), not a hardcoded severity table
- **Retrieval-grounded GenAI** so the LLM-written brief cites actual
  evidence instead of free-generating
- **Agentic, multi-step investigation** for high-risk incidents instead
  of one-shot summarization
- **A closed feedback loop**: analyst dispositions retrain the model, so
  the system's false-positive detection measurably improves over the
  course of a shift/demo

## System Architecture

```
alert_generator.py        synthetic 24h batch (noise + seeded attack chains)
        |
grouping.py                correlates alerts -> incidents
                            (asset + connection entity graph with fallback)
        |
ml_classifier.py              trained severity/false-positive model (CICIDS2017)
        |
scoring.py                  risk_score = asset_criticality x severity x
                             kill-chain-span x confidence
        |
mitre_map.py                 alert/attack type -> ATT&CK technique ID + tactic
        |
rag.py                       local ATT&CK retrieval layer, replaceable by FAISS
        |
investigator.py              bounded investigator for HIGH/CRITICAL incidents
        |
summarizer.py                 grounded template or optional local/free LLM brief
        |
human_loop.py                  review queue, MERGE, audit feedback logging
        |
retrain.py                      feedback readiness/checkpoint tracking
        |
metrics.py                       MTTT before/after measurement
        |
pipeline.py / main.py              orchestration, writes outputs/
        |
dashboard (Streamlit)               incident table, predictions, analytics
```

## Core Design Decisions

- **Asset criticality drives ranking, not alert volume.** A domain
  controller with 3 alerts spanning credential access + persistence +
  impact outranks a printer with 40 duplicate low-severity alerts.
  Alert count is capped at a 1.3x multiplier max in `scoring.py`.
- **Nothing above LOW risk auto-closes.** The human-in-the-loop queue
  only ever *suggests* a disposition for low-risk, high-historical-FP
  incidents; a human still confirms everything else.
- **The LLM is grounded, not freewheeling.** Briefs retrieve real ATT&CK
  technique descriptions and similar past incidents before generating
  text, and can be asked to cite which past incident a new one resembles.
- **Every enhancement degrades gracefully.** The ML classifier falls back
  to the static lookup table if real features aren't available; the LLM
  brief falls back to the deterministic template on any API error. The
  pipeline never breaks in production or mid-demo.

## Data Sources

| Source | Used For |
|---|---|
| Synthetic generator (`alert_generator.py`) | Demo-able, reproducible 3,000-alert batch with seeded attack chains |
| CICIDS2017 (public, labeled) | Training the real severity/false-positive classifier |
| MITRE ATT&CK technique descriptions (public) | RAG corpus, grounds the LLM brief |
| Synthetic "past incident" write-ups (LLM-generated once) | RAG corpus, gives retrieval something concrete to cite |
| Public IP-reputation blocklists (AbuseIPDB / Spamhaus DROP) | Agent's `check_ip_reputation` tool |
| Analyst dispositions (generated during demo/use) | Active-learning feedback loop |

## Team

5-member team, split by experience:

| Role | Owns |
|---|---|
| ML Lead (experienced) | Classifier training + active-learning feedback loop |
| Agent/Systems Lead (experienced) | Graph correlation, agentic investigator, final integration |
| RAG/Data Engineer | Embedding corpus, FAISS retrieval |
| Pipeline/Backend Dev | Wiring classifier output into scoring, story reconstruction, next-step prediction, merge action |
| Demo/Data Prep | Dataset cleaning, Streamlit dashboard, demo rehearsal |

See `TASKS.md` for the full phase-by-phase build plan, current implementation
status, and what's still open.
