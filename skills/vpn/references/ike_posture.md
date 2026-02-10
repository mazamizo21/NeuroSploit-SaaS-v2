# IKE/IPsec Posture

## Goals
1. Identify IKE version and vendor IDs.
2. Flag aggressive mode or weak transform sets when visible.
3. Record responder IDs and NAT-T support if visible.

## Safe Checks
1. Use `ike-scan` in discovery mode with low rate.
2. Avoid aggressive mode probing unless explicitly authorized.

## Indicators to Record
1. IKEv1 vs IKEv2 support.
2. Vendor IDs.
3. Aggressive mode detected.
4. NAT-T supported or required.

## Evidence Checklist
1. `ike-scan` output captured.
2. Parsed JSON summary of findings.
3. Notes on transforms and responder IDs.
