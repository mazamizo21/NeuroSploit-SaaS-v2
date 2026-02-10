# VPN Service Skill

## Overview
Service-first methodology for VPN discovery and safe configuration validation.

## Scope Rules
1. Only operate on explicitly in-scope VPN endpoints.
2. External targets: exploit or write actions require explicit authorization (external_exploit=explicit_only).
3. Avoid credential guessing unless explicitly authorized.
4. Use rate limits for active probing.

## Methodology

### 1. Discovery and Protocol Identification
- Identify VPN type (IPsec/IKE, SSL VPN, OpenVPN, WireGuard) by ports and banners.
- Record exposed endpoints and certificate details.

### 2. Access Validation
- Use provided credentials and client configuration only.
- Record authentication success or failure once per endpoint.

### 3. Safe Configuration Review
- Check cipher suites, certificate expiration, and weak protocol versions.
- Identify aggressive mode or legacy settings when visible.

### 4. Explicit-Only Actions
- Credential attacks, aggressive mode probing, or tunnel establishment beyond validation require explicit authorization.

## Service-First Workflow (Default)
1. Discovery: `nmap` to identify VPN ports and service banners.
2. Protocol checks: `ike-scan` for IPsec/IKE, `sslscan` for SSL VPN.
3. Access validation: `openvpn` with provided configuration.
4. Explicit-only: credential attacks or exploit workflows.

## Deep Dives
Load references when needed:
1. Protocol identification: `references/protocol_identification.md`
2. IKE/IPsec posture: `references/ike_posture.md`
3. SSL VPN TLS posture: `references/ssl_vpn_posture.md`

## Evidence Collection
1. `vpn_inventory.json` with endpoints, protocols, and cipher details (parsed from `ike-scan` output).
2. `evidence.json` with raw `ike-scan` and TLS scan outputs.
3. `findings.json` with weak configuration evidence.

## Evidence Consolidation
Use `parse_ikescan.py` to convert `ike-scan` output into `vpn_inventory.json`.

## Success Criteria
- VPN endpoints and protocols identified.
- Security posture documented with evidence.
- Actions constrained to authorized scope.

## Tool References
- ../toolcards/ike-scan.md
- ../toolcards/openvpn.md
- ../toolcards/sslscan.md
- ../toolcards/nmap.md
