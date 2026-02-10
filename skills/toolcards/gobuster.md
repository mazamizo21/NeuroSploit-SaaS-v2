# gobuster Toolcard

## Overview
- Summary: Gobuster is a multi-mode brute-forcing tool for directories, DNS, virtual hosts, and cloud storage.

## Advanced Techniques
- Choose the correct mode for the target (dir, dns, vhost).
- Tune extensions and wordlists to match the target stack.

## Safe Defaults
- Rate limits: keep thread counts conservative for external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: endpoints.json

## References
- https://github.com/OJ/gobuster
