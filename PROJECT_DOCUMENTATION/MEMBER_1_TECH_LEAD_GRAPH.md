# Member 1 — Technical Lead, Backend, and Graph Correlation

## Own

`pipeline.py`, `main.py`, `grouping.py`, `alert_generator.py`, `assets.py`, integration tests, incident schema, graph correlation, and final integration.

## Study first

1. `PROJECT.md`
2. `FULL_ARCHITECTURE.md`
3. `CODEBASE_AND_RUNNING.md`
4. `grouping.py`
5. `scoring.py`
6. `pipeline.py`

## Concepts

- normalized event schemas
- graph entities
- union-find connected components
- time-window correlation
- cross-asset lateral movement
- incident lifecycle
- data contracts
- deterministic execution
- graceful fallback
- integration testing

## Implementation responsibilities

- Define the alert and incident dictionaries.
- Maintain `group_alerts_graph()` and `group_by_asset_time()`.
- Prevent unrelated alerts from over-merging.
- Ensure cross-asset incidents use the most critical impacted asset.
- Integrate ML, RAG, investigation, summaries, human review, and metrics.
- Review all changes that modify shared schemas.

## Must demonstrate

Open a cross-asset incident and explain its `assets`, `alert_ids`, `correlation_method`, timestamps, and graph relationship.

## Handoffs

Give Member 2 stable incident objects, Member 3 stable dashboard fields, Member 5 testable interfaces, and Member 6 reliable metrics/workflow outputs.
