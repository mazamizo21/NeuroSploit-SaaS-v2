# mongosh Toolcard

## Overview
- Summary: mongosh is the MongoDB shell for interacting with MongoDB deployments.

## Advanced Techniques
- Use `--eval` for read-only inventory commands.
- Capture server build info and auth mechanisms via `db.adminCommand`.

## Safe Defaults
- Prefer read-only queries; avoid writes unless explicitly authorized.
- Use least-privilege credentials.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://www.mongodb.com/docs/rapid/reference/mongo/
