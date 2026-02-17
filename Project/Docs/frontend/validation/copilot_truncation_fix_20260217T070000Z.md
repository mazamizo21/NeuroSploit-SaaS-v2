# Copilot truncation fix — chat chunking + token defaults

Date: 2026-02-17T07:00:00Z

## Symptom
Copilot answers sometimes appeared to stop mid-item (e.g., "**4"), caused by:
- frontend `ChatInterface` truncating message text at 8000 chars
- occasionally longer answers due to Evidence quoting

## Fix
1) Frontend: chunk long chat messages into multiple transcript entries instead of truncating.
   - File: `frontend/src/components/chat/ChatInterface.tsx`

2) Backend: increase default Copilot `max_tokens` from 700 → 1000.
   - File: `control-plane/api/routers/jobs.py`

3) Backend prompt: bound Evidence section to ~12 lines.

## Validation
- Docker build of `api` + `frontend` succeeded.
