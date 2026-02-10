# Advanced Techniques

## Chain Types
- Use `dynamic_chain` to skip dead proxies, `strict_chain` to enforce order, or `random_chain` with `chain_len`.
- Only one chain type should be active in the config at a time.

## DNS Handling
- Use `proxy_dns` to resolve DNS through the proxy chain; consider `proxy_dns_old` or `proxy_dns_daemon` for compatibility.
