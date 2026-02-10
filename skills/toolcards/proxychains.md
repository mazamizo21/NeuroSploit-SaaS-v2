# proxychains Toolcard

## Overview
- Summary: ProxyChains routes TCP traffic through one or more proxies for controlled egress and testing.

## Advanced Techniques
- Use `strict_chain` for deterministic routing or `dynamic_chain` for resilience.
- Validate DNS handling (`proxy_dns`) to avoid leaking hostnames.

## Safe Defaults
- Route only in-scope traffic through approved proxies.
- Avoid chaining to untrusted or public proxies unless explicitly authorized.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- Kali tool page: https://www.kali.org/tools/proxychains/
