# docker Toolcard

## Overview
- Summary: The Docker CLI manages Docker engines for container lifecycle and configuration queries.

## Advanced Techniques
- Use `-H` or `DOCKER_HOST` to query remote daemons.
- Prefer read-only commands (`version`, `info`, `ps`) for validation.

## Safe Defaults
- Read-only queries only unless explicitly authorized.
- Limit to in-scope hosts and sockets.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://docs.docker.com/reference/cli/docker/
