# Frontend change — persist chat history across refresh

Date: 2026-02-17T06:37:00Z

## Change
- Persisted `ChatInterface` chat transcript to `localStorage` keyed by `jobId`.
- Hydrates on page load / job change.
- Clears persisted transcript when operator clicks **clear**.

Files:
- `frontend/src/components/chat/ChatInterface.tsx`

## Build/validation
Validated via Docker build (Next.js build stage).
