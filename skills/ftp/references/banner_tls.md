# FTP Banner and FTPS Support

## Goals
1. Capture server banner and version hints.
2. Identify FTPS (explicit or implicit) support.
3. Record TLS requirements and certificate posture when present.

## Safe Checks
1. `nmap --script ftp-syst,ftp-banner`
2. Manual banner capture via `nc` or `socat`
3. `openssl s_client -starttls ftp` when authorized

## Indicators to Record
1. Legacy versions with known CVEs (record only).
2. FTPS supported or required.
3. TLS version and certificate metadata if available.

## Evidence Checklist
1. Banner output.
2. FTPS support signal.
3. TLS negotiation output and certificate details.
