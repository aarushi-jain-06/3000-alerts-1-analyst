# Member 4 — MITRE Content, Summaries, and Investigation Experience

## Own

`mitre_map.py`, `summarizer.py`, `investigator.py`, ATT&CK descriptions, attack-story wording, recommendations, and investigation presentation. Member 2 owns the retrieval implementation in `rag.py`.

## Study first

1. `PROJECT.md`
2. `FULL_ARCHITECTURE.md`
3. `mitre_map.py`
4. `summarizer.py`
5. `investigator.py`
6. `rag.py`

## Concepts

- ATT&CK tactics and techniques
- evidence versus inference
- timeline reconstruction
- next-stage prediction
- deterministic summaries
- prompt safety
- tool traces
- false-positive language

## Implementation responsibilities

- Keep alert-to-technique mappings accurate.
- Write concise ATT&CK descriptions for the retrieval corpus.
- Design the brief structure and recommendations.
- Make alert IDs and timeline evidence visible.
- Ensure optional models receive only supported facts/context.
- Make investigation traces useful to an analyst.
- Review retrieval results with Member 2.

## Must demonstrate

Show a multi-stage incident and explain every technique, tactic, timeline step, recommendation, retrieved context, and investigation action.

## Handoffs

Supply corpus content to Member 2, display requirements to Member 3, and analyst wording to Member 6.
