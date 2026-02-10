# Spec 005: Real-Time Dashboard Improvements

## Problem Statement

The current frontend dashboard (`frontend/src/app/pentests/[id]/page.tsx`) provides basic job monitoring but lacks:

1. **Live finding feed**: Findings appear only after job completion, not in real-time
2. **Supervisor event visibility**: Supervisor alerts, hints, and actions are invisible to the user
3. **Agent strategy visualization**: No visibility into what the agent is thinking or planning
4. **Progress granularity**: Progress bar jumps from 0 to 100 with no intermediate states
5. **Multi-target tracking**: No visual indication of which targets have been covered vs. remaining

### Current UI Components
- `LiveLogViewer.tsx` — Raw log stream via WebSocket (xterm.js console)
- `DopamineFeed.tsx` — Gamification feed (confetti on findings)
- `MitreHeatmap.tsx` — MITRE technique coverage visualization
- `ProgressRing.tsx` — Circular progress indicator

## Proposed Solution

### 1. Live Finding Feed

Add a `LiveFindingsFeed` component that subscribes to `job:<id>:live_stats` Redis channel:

```typescript
// frontend/src/components/LiveFindingsFeed.tsx
interface LiveFinding {
  timestamp: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  target: string;
  type: string;
}

// Subscribe to WebSocket events tagged "finding_update" or "[REMEMBER:vulnerability_found]"
```

Display as a scrolling timeline with severity-colored badges and confetti on critical/high.

### 2. Supervisor Events Panel

Add a `SupervisorPanel` component showing:
- Alert events (stalled, noop_loop, scan_loop, repeated_command)
- Audit decisions (action, severity, rationale from LLM)
- Action execution results (hint written, reset applied, etc.)
- Health status (supervisor connected, LLM mode)

Data source: Subscribe to `job:<id>:supervisor_events` Redis channel via WebSocket.

### 3. Agent Strategy Sidebar

Show the agent's current strategy context:
- Current target focus and commands-per-target breakdown
- Exploit readiness score (from Spec 004)
- Vuln tracker status (found / attempted / proven / not-exploitable)
- Enum vs. exploit command ratio (pie chart)
- Time spent per phase

Data source: Poll `job:<id>:live_stats` Redis hash.

### 4. Granular Progress Tracking

Replace the binary progress bar with phase-aware milestones:

```
[✓ Recon Baseline] → [✓ Service Fingerprint] → [● Vuln Discovery] → [○ Exploitation] → [○ Post-Exploit]
```

Calculate phase based on:
- Recon baseline: nmap top-ports completed
- Service fingerprint: whatweb/curl headers done
- Vuln discovery: at least one vuln in tracker
- Exploitation: at least one exploit attempt
- Post-exploit: privilege check or data access

### 5. Multi-Target Coverage Map

For multi-target jobs, show a target grid:

```
┌─────────────┬────────┬────────┬──────────┐
│ Target      │ Recon  │ Vulns  │ Exploits │
├─────────────┼────────┼────────┼──────────┤
│ juiceshop   │ ✓ 15   │ 3      │ 1 proven │
│ dvwa        │ ✓ 8    │ 2      │ 0        │
│ webgoat     │ ○ 0    │ 0      │ 0        │
└─────────────┴────────┴────────┴──────────┘
```

### 6. WebSocket API Enhancement

Extend the existing WebSocket router to proxy supervisor events:

```python
# control-plane/api/routers/websocket.py
# Add supervisor event subscription:
async def _forward_supervisor_events(ws, job_id):
    pubsub = redis.pubsub()
    await pubsub.subscribe(f"job:{job_id}:supervisor_events")
    async for msg in pubsub.listen():
        await ws.send_json({"type": "supervisor", "data": json.loads(msg["data"])})
```

## Acceptance Criteria
- [ ] Findings appear in the UI within 5 seconds of discovery (not after job completion)
- [ ] Supervisor alerts visible with severity coloring and action details
- [ ] Progress bar shows 5+ distinct milestone states
- [ ] Multi-target jobs show per-target coverage breakdown
- [ ] All new components work with existing dark theme

## Files to Modify
- `frontend/src/components/LiveFindingsFeed.tsx` — New component
- `frontend/src/components/SupervisorPanel.tsx` — New component
- `frontend/src/components/AgentStrategy.tsx` — New component
- `frontend/src/components/TargetCoverage.tsx` — New component
- `frontend/src/app/pentests/[id]/page.tsx` — Integrate new components
- `control-plane/api/routers/websocket.py` — Add supervisor event forwarding
- `frontend/src/lib/api.ts` — Add WebSocket subscription helpers

## Risk Assessment
- **Low**: All changes are additive UI components
- **Medium**: WebSocket message volume may be high for long jobs — implement throttling
