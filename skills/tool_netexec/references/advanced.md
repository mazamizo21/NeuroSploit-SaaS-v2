# Advanced Techniques

## Module-Driven Enumeration
- List available modules per protocol (`nxc <proto> -L`) and run only the scoped modules you need.
- Pass module parameters via `-o KEY=VALUE` to avoid global defaults and keep actions explicit.

## Protocol Focus
- Use the protocol-specific subcommands (e.g., `nxc smb`, `nxc ldap`, `nxc winrm`, `nxc rdp`, `nxc mssql`, `nxc ssh`) to keep options and evidence aligned with the target service.

## Evidence
- Capture per-module output and map it to host/service pairs so lateral movement claims are traceable.
