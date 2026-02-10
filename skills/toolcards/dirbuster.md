# dirbuster Toolcard

## Overview
- Summary: DirBuster is a multi-threaded Java application designed to brute force directories and file names on web and application servers.

## Advanced Techniques
- Tune thread counts and wordlists to match target performance.
- Add file extensions relevant to the target stack.

## Safe Defaults
- Rate limits: keep thread counts conservative on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: endpoints.json, findings.json (as applicable)

## References
- https://www.kali.org/tools/dirbuster/
