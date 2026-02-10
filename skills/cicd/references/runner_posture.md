# Runner and Agent Posture

## Goals
1. Inventory runners/agents and their scopes.
2. Identify shared or privileged runners.
3. Record runner labels, tags, and execution environments.

## Safe Checks
1. Use platform APIs to list runners/agents in read-only mode.
2. Capture labels, tags, and assigned projects.

## Indicators to Record
1. Shared runners with broad project access.
2. Privileged or docker-in-docker runners.
3. Agents running on internet-exposed hosts.
4. Runners with root or host mount access.

## Evidence Checklist
1. Runner list summary.
2. High-privilege runner notes.
3. Runner tags and scope evidence.
