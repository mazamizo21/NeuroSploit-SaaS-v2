# Copilot cutoff fix — END_OF_RESPONSE sentinel + one-shot continuation

Date: 2026-02-17T07:05:00Z

## Symptom
Copilot answers occasionally stopped mid-structure (e.g., mid-table / mid-list).

## Likely causes
- Upstream LLM hit output token limit or response ended early.
- UI previously hard-truncated long messages (fixed separately), but this symptom also occurred on short partial completions.

## Fix
- Added an explicit `END_OF_RESPONSE` sentinel requirement in Copilot system prompt.
- If the returned answer lacks the sentinel, the server performs **one** continuation request:
  - appends the partial answer as an assistant message
  - asks the model to continue without repeating earlier sections
  - uses a capped continuation token budget (<=800)
- Removes the sentinel from the final response returned to the UI.
- Also forbids markdown tables to reduce partial table outputs.

Files:
- `control-plane/api/routers/jobs.py`

## Validation
- `python3 -m compileall control-plane/api/routers/jobs.py`
- `docker compose up -d --build api`
