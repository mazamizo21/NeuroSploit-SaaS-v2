# redis-cli Toolcard

## Overview
- Summary: redis-cli is the official command-line interface for Redis.

## Advanced Techniques
- Use INFO and ACL commands for configuration and access validation.
- Use TLS or URI-based authentication where supported.

## Safe Defaults
- Rate limits: avoid repeated auth attempts on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: redis_info.json

## References
- https://redis.io/docs/latest/develop/tools/cli/
