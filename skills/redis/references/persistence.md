# Redis Persistence and Replication

## Goals
1. Identify persistence settings that could expose data.
2. Capture replication status without changes.
3. Record backup and snapshot posture.

## Safe Checks
1. `redis-cli INFO persistence`
2. `redis-cli INFO replication`
3. `redis-cli CONFIG GET dir` (authorized)

## Indicators to Record
1. RDB/AOF enabled on exposed instances.
2. Replicaof pointing to untrusted hosts.
3. Persistence directory on shared or world-writable paths.

## Evidence Checklist
1. Persistence settings.
2. Replication role and peers.
3. Snapshot directory and file permission notes.
