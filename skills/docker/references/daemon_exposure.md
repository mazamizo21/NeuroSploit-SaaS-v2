# Docker Daemon Exposure

## Goals
1. Identify exposed Docker API endpoints.
2. Capture TLS and authentication posture.
3. Record daemon socket exposure and access controls.

## Safe Checks
1. `nmap -p2375,2376`
2. `docker -H tcp://host:2375 version` (read-only)
3. `docker context ls` (local, read-only)

## Indicators to Record
1. API exposed on 2375 without TLS.
2. TLS enabled but client auth not required.
3. Docker socket exposed to non-root users.

## Evidence Checklist
1. Daemon endpoint list.
2. TLS and auth status.
3. Socket permissions and access notes.
