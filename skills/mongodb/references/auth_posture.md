# MongoDB Authentication Posture

## Goals
1. Identify whether authentication is enabled.
2. Capture build and wire protocol info safely.
3. Record network binding and cluster context.

## Safe Checks
1. `db.adminCommand({buildInfo:1})`
2. `db.adminCommand({getCmdLineOpts:1})` (authorized)
3. `db.adminCommand({isMaster:1})` or `hello` (metadata only)

## Indicators to Record
1. `authorization` disabled.
2. Bind IP set to `0.0.0.0`.
3. No access control but public exposure.

## Evidence Checklist
1. Build info summary.
2. Auth configuration state.
3. Bind IP and replica set evidence.
