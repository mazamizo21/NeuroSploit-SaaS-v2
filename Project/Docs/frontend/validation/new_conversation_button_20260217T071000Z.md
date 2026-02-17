# Frontend change — New conversation button

Date: 2026-02-17T07:10:00Z

## Change
Added a **new conversation** button in the ChatInterface header. It:
- clears the current AI chat transcript
- clears persisted localStorage history for this job
- resets the input box

File:
- `frontend/src/components/chat/ChatInterface.tsx`

## Validation
Rebuilt/recreated frontend container via docker compose.
