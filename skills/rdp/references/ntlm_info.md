# NTLM Info Capture

## Goal
Use NTLM info to identify domain context, host naming, and OS hints.

## Safe Checks
- `nmap -p3389 --script rdp-ntlm-info target`

## Key Fields
- `Target_Name`
- `NetBIOS_Domain_Name`
- `NetBIOS_Computer_Name`
- `DNS_Domain_Name`
- `DNS_Computer_Name`
- `Product_Version`

## Evidence Checklist
1. Raw script output saved.
2. Parsed JSON summary with NTLM fields.
3. Notes on domain and host naming context.
