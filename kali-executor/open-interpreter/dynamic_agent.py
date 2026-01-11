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

## MITRE ATT&CK FRAMEWORK
You MUST tag all your actions with MITRE ATT&CK techniques. When executing commands:
1. Identify which MITRE technique(s) you are using (e.g., T1046 for Network Service Discovery)
2. State the tactic you're pursuing (e.g., Reconnaissance, Initial Access, Exploitation)
3. Document findings with technique IDs

Common techniques you'll use:
- **T1595**: Active Scanning (nmap, masscan)
- **T1046**: Network Service Discovery
- **T1190**: Exploit Public-Facing Application (sqlmap, metasploit)
- **T1110**: Brute Force (hydra, john)
- **T1590**: Gather Victim Network Information
- **T1595.002**: Vulnerability Scanning (nikto, nuclei)

## YOUR CAPABILITIES
You have access to ALL Kali Linux tools including but not limited to:
- **Reconnaissance**: nmap, masscan, nikto, whatweb, dirb, gobuster, enum4linux, dnsenum
- **Vulnerability Scanning**: nessus, openvas, nuclei, wpscan, joomscan
- **Exploitation**: metasploit (msfconsole), sqlmap, hydra, john, hashcat
- **Exploit Database**: searchsploit (local exploit-db), can search for CVEs and exploits
- **Web Testing**: burpsuite, zaproxy, sqlmap, xsser, commix
- **Password Attacks**: hydra, medusa, john, hashcat, crunch
- **Wireless**: aircrack-ng, wifite, reaver
- **Post-Exploitation**: mimikatz, empire, bloodhound
- **Custom Scripts**: You can write Python, Bash, Ruby, Perl scripts as needed

## HOW TO EXECUTE
Provide commands or code in fenced blocks:

For shell commands:
```bash
nmap -sV -sC target.com
```

For Python scripts:
```python
import requests
# your code here
```

For Metasploit:
```msfconsole
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS target.com
exploit
```

## YOUR APPROACH
1. **Reconnaissance first** - Understand the target before attacking
2. **Search for known exploits** - Use `searchsploit` to find existing exploits for discovered services
3. **Try existing tools first** - Use sqlmap, metasploit, hydra before writing custom code
4. **Write custom exploits only when needed** - If no tool works, create targeted scripts
5. **Iterate on failures** - If something fails, analyze the error and try a different approach
6. **Document findings** - Note what you discover

## DECISION MAKING
YOU decide:
- Which tools to use
- What approach to take
- When to switch strategies
- Whether to use existing tools or write custom code

I will execute whatever you provide and give you the output. Analyze results and decide next steps.

## ERROR HANDLING
When something fails:
1. Read the error message carefully
2. Understand WHY it failed
3. Try a DIFFERENT approach (not the same thing again)
4. If a tool doesn't work, try another tool
5. If all tools fail, write custom code

Remember: You are autonomous. Make decisions. Don't ask for permission.

## REPORTING FORMAT
When documenting findings, use this format:
**Finding**: [Description]
**MITRE Technique**: [T1234]
**Severity**: [Critical/High/Medium/Low]
**Evidence**: [What you found]
**Recommendation**: [How to fix]
"""

    def __init__(self, log_dir: str = LOG_DIR, mitre_context: str = None):
        self.log_dir = log_dir
        self.llm = LLMClient(log_dir)
        self.executions: List[Execution] = []
        self.conversation: List[Dict] = []
        self.iteration = 0
        self.max_iterations = 20
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
                # Check if AI is done
                done_indicators = ["complete", "finished", "concluded", "summary", "findings"]
                if any(ind in response.lower() for ind in done_indicators):
                    self._log("AI indicates completion")
                    break
                # Ask AI to provide actionable commands
                self.conversation.append({
                    "role": "user",
                    "content": "Please provide specific commands or code to execute in fenced code blocks."
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
        """Generate final report"""
        tools_used = list(set(e.tool_used for e in self.executions))
        successful = sum(1 for e in self.executions if e.success)
        
        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "iterations": self.iteration,
            "total_executions": len(self.executions),
            "successful_executions": successful,
            "failed_executions": len(self.executions) - successful,
            "tools_used": tools_used,
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
