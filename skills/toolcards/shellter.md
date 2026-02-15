# shellter Toolcard

## Overview
- Summary: Shellter is a dynamic shellcode injection tool and PE infector that injects payloads into legitimate 32-bit Windows executables by tracing execution flow and inserting at valid injection points without adding suspicious PE sections or modifying memory permissions.

## Advanced Techniques
- Auto mode traces the target PE and selects injection points automatically; Manual mode lets you pick exact injection addresses from disassembly.
- Stealth mode preserves original PE functionality — critical for social engineering (user sees the real app working).
- Built-in Metasploit payloads (meterpreter_reverse_tcp/http/https, shell_reverse_tcp, shell_bind_tcp, WinExec) require no external msfvenom.
- Custom payload option accepts raw shellcode files — generate with `msfvenom -p <payload> -f raw -o shellcode.bin`.
- Best carrier executables: putty.exe, 7z.exe, WinSCP, notepad++ — signed, commonly whitelisted 32-bit PEs.
- Community Edition is 32-bit PE only; breaks Authenticode signatures on signed binaries.
- Requires Wine on Linux/macOS: `dpkg --add-architecture i386 && apt install wine32`.
- Avoid packed/compressed input PEs — Shellter needs to trace execution and packed binaries will fail.

## Safe Defaults
- Require explicit authorization before injecting payloads into executables (external_exploit=explicit_only).
- Always use Stealth mode unless you specifically need the original app to not execute.
- Record SHA256 of clean PE before injection and backdoored PE after for evidence chain.

## Evidence Outputs
- outputs: evidence.json, findings.json, payload_hashes.txt, generation_log.txt

## References
- https://www.kali.org/tools/shellter/
- https://www.shellterproject.com/introducing-shellter/
