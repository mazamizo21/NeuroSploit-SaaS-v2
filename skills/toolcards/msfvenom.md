# msfvenom Toolcard

## Overview
- Summary: msfvenom is the Metasploit Framework's payload generation and encoding utility (replaced msfpayload + msfencode). Generates payloads for all platforms in dozens of output formats with optional encoding, encryption, bad-char avoidance, and template injection.

## Advanced Techniques
- Common payloads: `windows/meterpreter/reverse_tcp`, `windows/x64/meterpreter/reverse_https`, `linux/x64/shell_reverse_tcp`, `php/meterpreter_reverse_tcp`, `java/jsp_shell_reverse_tcp`, `android/meterpreter/reverse_tcp`.
- Key encoders: `x86/shikata_ga_nai` (polymorphic XOR), `x64/xor`, `x86/countdown` (good for chaining), `cmd/powershell_base64`, `php/base64`.
- Multi-pass encoding: `-e x86/shikata_ga_nai -i 5` for 5 iterations of the same encoder.
- Chained encoding via pipes: `msfvenom -p X -f raw -e encoder1 -i 5 | msfvenom -a x86 --platform windows -e encoder2 -i 8 -f exe -o chained.exe`.
- Template injection: `-x /path/to/legit.exe -k` embeds payload as new thread while preserving original binary behavior.
- Bad character exclusion: `-b '\x00\x0a\x0d'` auto-selects compatible encoder.
- Architecture/platform: `-a x64 --platform windows` for explicit targeting.
- x64 templates require `-f exe-only` format instead of `-f exe`.
- Output formats: exe, elf, macho, dll, apk, war (executables); python, ruby, powershell, bash (scripts); asp, aspx, jsp, php (web); raw, c, csharp, hex (shellcode).
- Note: Encoding alone is NOT reliable AV evasion — modern AV uses behavioral analysis and emulation. Layer with other techniques.

## Safe Defaults
- Require explicit authorization before generating or deploying payloads (external_exploit=explicit_only).
- Never upload generated payloads to VirusTotal — use local AV, ThreatCheck, or isolated VM testing.
- Always record full generation command and SHA256 hash in evidence logs.
- Match LHOST/LPORT to actual listener configuration before deployment.

## Evidence Outputs
- outputs: evidence.json, findings.json, payload_hashes.txt, generation_log.txt

## References
- https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html
- https://www.kali.org/tools/msfvenom/
