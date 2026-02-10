# Kerberos Realm Validation

## Goals
- Confirm realm naming and KDC reachability.
- Detect time skew issues that can block authentication.

## Safe Checks
- Validate DNS SRV records (if in scope): `_kerberos._tcp` and `_kpasswd._tcp`.
- Probe KDC port 88 reachability with `nmap`.
- Capture time skew errors from `kinit` output.

## Evidence Checklist
- Resolved realm and KDC hostnames
- Port 88 reachability evidence
- Time skew or pre-auth error messages

