# Aditi — Member 5 — QA, Data Quality, and DevOps

## Own

`tests/`, `requirements.txt`, setup/run instructions, schema validation, regression testing, output validation, and demo reliability.

## Study first

1. `CODEBASE_AND_RUNNING.md`
2. `PROJECT.md`
3. `tests/test_pipeline.py`
4. `requirements.txt`
5. `main.py`
6. `dashboard.py`

## Concepts

- unit tests
- integration tests
- deterministic seeds
- schema validation
- failure-path testing
- dependency management
- startup diagnostics
- performance measurement
- model and LLM fallbacks

## Implementation responsibilities

- Run tests before each demo.
- Test graph over-merge and under-merge cases.
- Test empty data and unknown assets.
- Test model-present and model-missing paths.
- Test RAG and LLM fallback paths.
- Validate output columns and row counts.
- Verify dashboard startup and port behavior.
- Keep the installation guide correct.

## Must demonstrate

Run tests, compile the code, run `main.py`, verify output counts, and start the dashboard from a clean terminal.

## Handoffs

Work with Member 1 on integration, Member 2 on model checks, Member 3 on UI startup, and Member 6 on the pre-demo checklist.
