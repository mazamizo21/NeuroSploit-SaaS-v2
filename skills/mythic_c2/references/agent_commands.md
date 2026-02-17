# Mythic Agent Command Reference

## Apollo (Windows / .NET 4.0)

### Core Commands
| Command | Syntax | Description |
|---------|--------|-------------|
| `shell` | `shell [command]` | Execute via `cmd.exe /S /c` |
| `run` | `run -Executable [binary] -Arguments [args]` | Run arbitrary binary |
| `powershell` | `powershell -Command [cmd]` | PowerShell in current process |
| `powerpick` | `powerpick -Command [cmd]` | PowerShell in sacrificial process |
| `powershell_import` | `powershell_import` | Register .ps1 script |
| `exit` | `exit` | Kill callback |
| `sleep` | `sleep [seconds]` | Set callback interval |
| `jobs` | `jobs` | List running jobs |
| `jobkill` | `jobkill [jid]` | Kill a running job |

### File Operations
| Command | Syntax | Description |
|---------|--------|-------------|
| `ls` | `ls [-Path path]` | List directory contents (file browser integration) |
| `cd` | `cd -Path [dir]` | Change working directory |
| `pwd` | `pwd` | Print working directory |
| `cat` | `cat -Path [file]` | Read file contents |
| `download` | `download -Path [path]` | Download file from target |
| `upload` | `upload` | Upload file to target |
| `cp` | `cp -Path [src] -Destination [dst]` | Copy file |
| `mv` | `mv -Path [src] -Destination [dst]` | Move file |
| `rm` | `rm -Path [path]` | Delete file |
| `mkdir` | `mkdir -Path [dir]` | Create directory |

### Process & Token
| Command | Syntax | Description |
|---------|--------|-------------|
| `ps` | `ps` | List processes (process browser) |
| `kill` | `kill -PID [pid]` | Kill a process |
| `inject` | `inject` | Inject payload into remote process |
| `steal_token` | `steal_token [pid]` | Steal process token |
| `make_token` | `make_token` | Create token with creds (modal) |
| `rev2self` | `rev2self` | Revert to original token |
| `getprivs` | `getprivs` | Enable available privileges |
| `ppid` | `ppid -PID [pid]` | Set parent PID for sacrificial procs |
| `whoami` | `whoami` | Report access token info |

### Credential Access
| Command | Syntax | Description |
|---------|--------|-------------|
| `mimikatz` | `mimikatz -Command [args]` | Execute mimikatz |
| `dcsync` | `dcsync -Domain [dom] -User [user]` | DCSync credentials |
| `pth` | `pth -Domain [d] -User [u] -NTLM [h]` | Pass-the-hash |

### Assembly & BOF Execution
| Command | Syntax | Description |
|---------|--------|-------------|
| `execute_assembly` | `execute_assembly -Assembly [file] -Arguments [args]` | In-memory .NET assembly |
| `inline_assembly` | `inline_assembly -Assembly [file] -Arguments [args]` | Execute in current process |
| `assembly_inject` | `assembly_inject -PID [pid] -Assembly [file]` | Execute in remote process |
| `execute_coff` | `execute_coff -Coff [file] -Function [fn]` | Execute BOF/COFF |
| `execute_pe` | `execute_pe -PE [file] -Arguments [args]` | Execute static PE |
| `register_assembly` | `register_assembly` | Register .NET assembly |
| `register_file` | `register_file` | Cache file in agent |
| `load` | `load cmd1 cmd2 ...` | Load new commands |

### Surveillance
| Command | Syntax | Description |
|---------|--------|-------------|
| `screenshot` | `screenshot` | Capture current screen |
| `screenshot_inject` | `screenshot_inject -PID [pid] -Count [n]` | Screenshot via injection |
| `keylog_inject` | `keylog_inject -PID [pid]` | Keylogger via injection |

### Network
| Command | Syntax | Description |
|---------|--------|-------------|
| `ifconfig` | `ifconfig` | Network adapter info |
| `netstat` | `netstat` | TCP/UDP connections |
| `socks` | `socks -Port [port]` | Start SOCKS5 proxy |
| `link` | `link` | Link P2P agent (SMB/TCP modal) |
| `unlink` | `unlink` | Unlink P2P agent |
| `spawn` | `spawn` | Spawn new callback |
| `shinject` | `shinject` | Inject shellcode into PID |

### Lateral Movement
| Command | Syntax | Description |
|---------|--------|-------------|
| `net_dclist` | `net_dclist [domain]` | List domain controllers |
| `net_localgroup` | `net_localgroup [computer]` | List local groups |
| `net_localgroup_member` | `net_localgroup_member -Group [grp]` | Group membership |
| `net_shares` | `net_shares -Computer [host]` | List SMB shares |
| `sc` | `sc -Query\|-Start\|-Stop\|-Create\|-Delete` | Service control |

### Registry
| Command | Syntax | Description |
|---------|--------|-------------|
| `reg_query` | `reg_query -Hive HKLM:\ -Key [key]` | Query registry |
| `reg_write_value` | `reg_write_value -Hive HKLM:\ -Key [k] -Name [n] -Value [v]` | Write registry |

### Evasion
| Command | Syntax | Description |
|---------|--------|-------------|
| `blockdlls` | `blockdlls -EnableBlock true` | Block non-MS DLLs in post-ex |
| `set_injection_technique` | `set_injection_technique [tech]` | Change injection method |
| `get_injection_techniques` | `get_injection_techniques` | List available techniques |
| `spawnto_x64` | `spawnto_x64 -Application [path]` | Set 64-bit sacrificial proc |
| `spawnto_x86` | `spawnto_x86 -Application [path]` | Set 32-bit sacrificial proc |

### Privilege Escalation
| Command | Syntax | Description |
|---------|--------|-------------|
| `printspoofer` | `printspoofer -Command [cmd]` | Exploit SeImpersonate |

---

## Poseidon (Linux/macOS / Go)

### Core Commands
| Command | Syntax | Description |
|---------|--------|-------------|
| `shell` | `shell [command]` | Execute shell command |
| `pty` | `pty` | Start interactive PTY session |
| `ssh` | `ssh [user@host]` | SSH to another host |
| `sleep` | `sleep [seconds]` | Set callback interval |
| `exit` | `exit` | Kill callback |
| `jobs` | `jobs` | List running jobs |
| `jobkill` | `jobkill [jid]` | Kill a running job |

### File Operations
| Command | Syntax | Description |
|---------|--------|-------------|
| `ls` | `ls [path]` | List directory (file browser) |
| `cd` | `cd [dir]` | Change directory |
| `pwd` | `pwd` | Print working directory |
| `cat` | `cat [file]` | Read file |
| `download` | `download [path]` | Download file |
| `upload` | `upload` | Upload file |
| `cp` | `cp [src] [dst]` | Copy |
| `mv` | `mv [src] [dst]` | Move |
| `rm` | `rm [path]` | Delete |
| `mkdir` | `mkdir [dir]` | Create directory |
| `chmod` | `chmod [mode] [path]` | Change permissions |
| `head` | `head [file]` | Read first lines |
| `tail` | `tail [file]` | Read last lines |

### Process & System
| Command | Syntax | Description |
|---------|--------|-------------|
| `ps` | `ps` | List processes |
| `kill` | `kill [pid]` | Kill process |
| `getenv` | `getenv` | Environment variables |
| `setenv` | `setenv [key] [value]` | Set env variable |
| `ifconfig` | `ifconfig` | Network interfaces |

### Network
| Command | Syntax | Description |
|---------|--------|-------------|
| `socks` | `socks -Port [port]` | SOCKS5 proxy |
| `rpfwd` | `rpfwd` | Reverse port forward |
| `link` | `link` | P2P agent link |
| `unlink` | `unlink` | Unlink P2P agent |
| `portscan` | `portscan [hosts] [ports]` | TCP port scan |
| `curl` | `curl [url]` | HTTP request |

### Credential & Key
| Command | Syntax | Description |
|---------|--------|-------------|
| `keys` | `keys` | SSH key management |
| `triagedirectory` | `triagedirectory [path]` | Search for sensitive files |

---

## Medusa (Cross-Platform / Python)

### Core Commands
| Command | Syntax | Description |
|---------|--------|-------------|
| `shell` | `shell [command]` | Run via subprocess.Popen |
| `eval_code` | `eval_code [python_code]` | Execute arbitrary Python |
| `sleep` | `sleep [seconds] [jitter%]` | Set interval + jitter |
| `exit` | `exit` | Kill callback |
| `jobs` | `jobs` | List running jobs |
| `jobkill` | `jobkill [task_id]` | Kill a job |

### File Operations
| Command | Syntax | Description |
|---------|--------|-------------|
| `ls` | `ls [path]` | List files (file browser) |
| `cd` | `cd [dir]` | Change directory |
| `cwd` | `cwd` | Print working directory |
| `cat` | `cat [file]` | Read file |
| `download` | `download [path]` | Download file |
| `upload` | `upload` | Upload file |
| `cp` | `cp [src] [dst]` | Copy |
| `mv` | `mv [src] [dst]` | Move |
| `rm` | `rm [path]` | Delete |
| `env` | `env` | Print environment |

### Module System
| Command | Syntax | Description |
|---------|--------|-------------|
| `load` | `load [command]` | Load agent capability |
| `unload` | `unload [command]` | Unload capability |
| `load_module` | `load_module` | Load zipped Python module into memory |
| `unload_module` | `unload_module [name]` | Unload Python module |
| `load_script` | `load_script` | Load and execute Python script |
| `list_modules` | `list_modules` | List loaded modules |
| `pip_freeze` | `pip_freeze` | List installed packages |

### Network
| Command | Syntax | Description |
|---------|--------|-------------|
| `socks` | `socks start/stop [port]` | SOCKS5 proxy |
| `watch_dir` | `watch_dir [path] [seconds]` | Watch for file changes |

### macOS-Specific
| Command | Syntax | Description |
|---------|--------|-------------|
| `clipboard` | `clipboard` | Read clipboard (Py2.7, macOS) |
| `screenshot` | `screenshot` | Capture screen (Py2.7, macOS) |
| `list_apps` | `list_apps` | List installed apps |
| `list_tcc` | `list_tcc [path]` | Parse TCC database |
| `spawn_jxa` | `spawn_jxa` | Execute JXA script |
| `vscode_list_recent` | `vscode_list_recent` | VSCode recent files |
| `vscode_open_edits` | `vscode_open_edits` | VSCode unsaved edits |
| `vscode_watch_edits` | `vscode_watch_edits [path] [interval]` | Watch VSCode edits |

### Windows-Specific
| Command | Syntax | Description |
|---------|--------|-------------|
| `shinject` | `shinject` | Inject shellcode via CreateRemoteThread |
| `load_dll` | `load_dll [path] [export]` | Load and execute DLL |
| `list_dlls` | `list_dlls [pid]` | List loaded DLLs (Py3) |
| `ps` | `ps` | Process listing (Py3) |
| `ps_full` | `ps_full` | Full process info (Py3) |
| `kill` | `kill [pid]` | Terminate process (Py3) |
