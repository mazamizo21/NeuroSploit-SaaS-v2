# Sprint 0 Remainder TODO (Interactive Chat)

Date: 2026-02-15

## Backend
- [x] Stop/Resume: pause job mid-execution via Redis stop_signal; persist checkpoint; resume from checkpoint; ensure scheduler slot release.
- [x] Approval Gates: agent emits approval_request; waits for approval_response via WebSocket/Redis; supports approve/modify/abort.
- [x] Agent Questions (ask_user): agent emits question event; waits for user_answer; injects answer into conversation.
- [x] Main loop refactor: ensure ordering (stop -> approval -> question -> guidance -> phase gate -> thinking -> LLM -> tool events -> checkpoint).

## Execution Plane
- [x] Worker: detect stopped/paused jobs and mark status paused (not completed); set job:{id}:terminal=paused.
- [x] Scheduler: release slots on paused; allow resume when terminal key cleared.

## Control Plane
- [x] JobStatus: add paused; ensure DB enum updated automatically at startup.
- [x] Jobs API: allow resume from paused; clear stop_signal on resume.
- [x] WebSocket: resume requeues job + sets resume flag (not just delete stop).

## Frontend
- [x] ChatInterface component using /api/v1/ws/jobs/{job_id}/chat.
- [x] ToolExecutionCard (tool_start/output_chunk/tool_complete).
- [x] ThinkingIndicator (thinking/thinking_chunk).
- [x] PhaseProgressBar (phase_update).
- [x] ApprovalModal (approval_request -> send approval).
- [x] Question UI (question -> send answer).
- [x] StopResumeButton (stop/resume messages).
- [x] Resume button shows for paused jobs on pentest detail page.
