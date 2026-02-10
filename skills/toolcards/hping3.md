# hping3 Toolcard

## Overview
- Summary: hping3 is a packet generator used for custom TCP/IP probes and network testing.

## Advanced Techniques
- Use low-count probes to validate firewall behavior.
- Prefer SYN or ACK probes for reachability checks when authorized.

## Safe Defaults
- Explicit authorization required for crafted packet tests.
- Keep packet counts low to avoid disruption.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- Kali tool page: https://www.kali.org/tools/hping3/
