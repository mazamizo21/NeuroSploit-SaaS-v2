"""
TazoSploit  v2 - Agent Wrapper for Open Interpreter
Provides HTTP API and full transaction logging for  integration
"""

import os
import json
import uuid
import time
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import asyncio

from config import configure_interpreter, get_pentest_system_prompt

# =============================================================================
# LOGGING CONFIGURATION - Full visibility
# =============================================================================

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/pentest/logs/agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('tazosploit.agent')

# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class LLMTransaction:
    """Records every LLM interaction"""
    transaction_id: str
    timestamp: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    latency_ms: float
    messages: List[Dict]
    response: str
    cost_estimate_usd: float

@dataclass
class CommandTransaction:
    """Records every command execution"""
    transaction_id: str
    timestamp: str
    command: str
    working_directory: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    policy_decision: str

@dataclass
class JobTransaction:
    """Full job audit trail"""
    job_id: str
    tenant_id: str
    scope_id: str
    phase: str
    start_time: str
    end_time: Optional[str]
    status: str
    llm_transactions: List[LLMTransaction]
    command_transactions: List[CommandTransaction]
    findings: List[Dict]
    total_tokens: int
    total_cost_usd: float

class ExecuteRequest(BaseModel):
    job_id: str
    tenant_id: str
    scope_id: str
    target: str
    phase: str  # RECON, VULN_SCAN, EXPLOIT, POST_EXPLOIT, REPORT
    approved_tools: List[str]
    max_intensity: str  # low, medium, high
    timeout_seconds: int = 3600
    auto_run: bool = False

class ExecuteResponse(BaseModel):
    job_id: str
    status: str
    findings: List[Dict]
    transactions: Dict
    summary: str

# =============================================================================
# TRANSACTION LOGGER
# =============================================================================

class TransactionLogger:
    """Logs all transactions for audit and debugging"""
    
    def __init__(self, log_dir: str = "/pentest/logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
    def log_llm_transaction(self, transaction: LLMTransaction):
        """Log LLM interaction"""
        log_file = os.path.join(self.log_dir, "llm_transactions.jsonl")
        with open(log_file, 'a') as f:
            f.write(json.dumps(asdict(transaction)) + '\n')
        logger.debug(f"LLM Transaction: {transaction.transaction_id} - {transaction.total_tokens} tokens")
        
    def log_command_transaction(self, transaction: CommandTransaction):
        """Log command execution"""
        log_file = os.path.join(self.log_dir, "command_transactions.jsonl")
        with open(log_file, 'a') as f:
            f.write(json.dumps(asdict(transaction)) + '\n')
        logger.info(f"Command: {transaction.command[:100]}... - Exit: {transaction.exit_code}")
        
    def log_job_transaction(self, transaction: JobTransaction):
        """Log complete job"""
        log_file = os.path.join(self.log_dir, f"job_{transaction.job_id}.json")
        with open(log_file, 'w') as f:
            json.dump(asdict(transaction), f, indent=2)
        logger.info(f"Job {transaction.job_id} completed - {len(transaction.findings)} findings")

# =============================================================================
# POLICY ENGINE (Pre-execution checks)
# =============================================================================

class PolicyEngine:
    """Enforces security policies before command execution"""
    
    DANGEROUS_COMMANDS = [
        'rm -rf /',
        'mkfs',
        ':(){:|:&};:',  # Fork bomb
        'dd if=/dev/zero',
        '> /dev/sda',
    ]
    
    ALLOWED_TOOLS = {
        'recon': ['nmap', 'masscan', 'subfinder', 'amass', 'dnsrecon', 'whatweb', 'wafw00f'],
        'vuln_scan': ['nikto', 'nuclei', 'sqlmap', 'wpscan', 'gobuster', 'dirb', 'ffuf'],
        'exploit': ['metasploit', 'hydra', 'medusa', 'sqlmap', 'searchsploit'],
        'post_exploit': ['crackmapexec', 'impacket', 'mimikatz', 'linpeas', 'winpeas'],
    }
    
    def __init__(self, approved_tools: List[str], max_intensity: str, target_scope: str):
        self.approved_tools = approved_tools
        self.max_intensity = max_intensity
        self.target_scope = target_scope
        
    def validate_command(self, command: str) -> tuple[bool, str]:
        """
        Validate command against policy.
        Returns (allowed, reason)
        """
        # Check for dangerous patterns
        for dangerous in self.DANGEROUS_COMMANDS:
            if dangerous in command:
                return False, f"Dangerous command pattern detected: {dangerous}"
        
        # Check if tool is in approved list
        tool = command.split()[0] if command else ""
        if self.approved_tools and tool not in self.approved_tools:
            return False, f"Tool '{tool}' not in approved list"
        
        # Check target is in scope (basic check)
        # In production, this would be more sophisticated
        if self.target_scope and self.target_scope not in command:
            # Allow commands that don't target anything
            if any(x in command for x in ['ls', 'cat', 'grep', 'find', 'pwd']):
                return True, "Local command allowed"
            logger.warning(f"Target scope check: {self.target_scope} not in {command}")
        
        return True, "Policy check passed"

# =============================================================================
# AGENT EXECUTOR
# =============================================================================

class AgentExecutor:
    """Executes pentest jobs with full logging"""
    
    def __init__(self):
        self.interpreter = configure_interpreter()
        self.interpreter.system_message = get_pentest_system_prompt()
        self.transaction_logger = TransactionLogger()
        self.current_job: Optional[JobTransaction] = None
        
    async def execute_job(self, request: ExecuteRequest) -> ExecuteResponse:
        """Execute a pentest job with full transaction logging"""
        
        logger.info(f"Starting job {request.job_id} for tenant {request.tenant_id}")
        logger.info(f"Target: {request.target}, Phase: {request.phase}")
        
        # Initialize job transaction
        self.current_job = JobTransaction(
            job_id=request.job_id,
            tenant_id=request.tenant_id,
            scope_id=request.scope_id,
            phase=request.phase,
            start_time=datetime.utcnow().isoformat(),
            end_time=None,
            status="running",
            llm_transactions=[],
            command_transactions=[],
            findings=[],
            total_tokens=0,
            total_cost_usd=0.0
        )
        
        # Initialize policy engine
        policy = PolicyEngine(
            approved_tools=request.approved_tools,
            max_intensity=request.max_intensity,
            target_scope=request.target
        )
        
        # Configure interpreter
        self.interpreter.auto_run = request.auto_run
        
        # Build prompt based on phase
        prompt = self._build_phase_prompt(request)
        
        try:
            # Execute with timeout
            findings = await asyncio.wait_for(
                self._execute_with_logging(prompt, policy),
                timeout=request.timeout_seconds
            )
            
            self.current_job.status = "completed"
            self.current_job.findings = findings
            
        except asyncio.TimeoutError:
            self.current_job.status = "timeout"
            logger.error(f"Job {request.job_id} timed out after {request.timeout_seconds}s")
            
        except Exception as e:
            self.current_job.status = "error"
            logger.error(f"Job {request.job_id} failed: {str(e)}")
            
        finally:
            self.current_job.end_time = datetime.utcnow().isoformat()
            self.transaction_logger.log_job_transaction(self.current_job)
        
        return ExecuteResponse(
            job_id=request.job_id,
            status=self.current_job.status,
            findings=self.current_job.findings,
            transactions={
                "llm_count": len(self.current_job.llm_transactions),
                "command_count": len(self.current_job.command_transactions),
                "total_tokens": self.current_job.total_tokens,
                "total_cost_usd": self.current_job.total_cost_usd
            },
            summary=f"Phase {request.phase} completed with {len(self.current_job.findings)} findings"
        )
    
    @staticmethod
    def _estimate_cost(total_tokens: int, model: str) -> float:
        """Estimate cost in USD based on model and token count.
        Assumes ~50/50 input/output split. Uses average of input+output rate.
        Pricing per 1M tokens: (input, output). Last updated: 2026-02-12.
        """
        # Average cost per 1M tokens (input + output) / 2 — for rough estimates
        avg_rates = {
            "claude-opus-4-6": 15.0,      "claude-opus-4-5": 45.0,
            "claude-sonnet-4": 9.0,        "claude-3-5-haiku": 2.4,
            "gpt-5.2": 7.875,              "gpt-5.1": 5.625,
            "gpt-5-mini": 1.125,           "gpt-5": 5.625,
            "gpt-4.1-mini": 1.0,           "gpt-4.1": 5.0,
            "gpt-4o-mini": 0.375,          "gpt-4o": 6.25,
            "kimi-k2.5": 1.35,             "kimi-k2": 1.35,       "k2p5": 1.35,
            "glm-5": 2.1,                  "glm-4.7": 0.95,       "glm-4.7-flash": 0.23,
            "deepseek-r1": 1.37,           "deepseek-v3": 0.685,
            "qwen3-coder": 0.185,          "qwen3": 0.37,
            "gemini-3-pro": 5.625,         "gemini-3-flash": 1.75,
            "minimax-m2": 0.61,            "llama-3.3-70b": 0.2,
        }
        model_lower = model.lower()
        # Strip provider prefixes
        for prefix in ["anthropic/", "openai/", "openrouter/", "moonshot/", "zai/",
                       "venice/", "synthetic/", "cerebras/", "kimi-coding/", "openai-codex/",
                       "google/", "minimax/", "hf:", "moonshotai/", "zai-org/", "zai-org-",
                       "deepseek-ai/"]:
            if model_lower.startswith(prefix):
                model_lower = model_lower[len(prefix):]
                break
        
        rate = 0.0
        best_len = 0
        for key, r in avg_rates.items():
            if key in model_lower or model_lower in key:
                if len(key) > best_len:
                    rate = r
                    best_len = len(key)
        if rate == 0:
            rate = 9.0  # Conservative default (~Sonnet tier)
        
        return round(total_tokens * rate / 1_000_000, 6)

    def _build_phase_prompt(self, request: ExecuteRequest) -> str:
        """Build prompt for specific MITRE ATT&CK phase"""
        
        phase_prompts = {
            "RECON": f"""
Perform reconnaissance on target: {request.target}

Tasks:
1. Run nmap scan to discover open ports and services
2. Identify the technology stack (web server, frameworks, etc.)
3. Enumerate subdomains if applicable
4. Check for common misconfigurations

Report all findings with severity ratings.
""",
            "VULN_SCAN": f"""
Scan for vulnerabilities on target: {request.target}

Tasks:
1. Run nikto for web vulnerability scanning
2. Run nuclei with appropriate templates
3. Check for SQL injection with sqlmap (safe mode)
4. Check for common CVEs based on discovered services

Report all vulnerabilities with CVE IDs where applicable.
""",
            "EXPLOIT": f"""
Attempt exploitation on target: {request.target}
(Only approved vulnerabilities, intensity: {request.max_intensity})

Tasks:
1. Verify identified vulnerabilities are exploitable
2. Attempt to gain initial access
3. Document successful exploitation paths
4. Capture proof of exploitation (screenshots, hashes, etc.)

IMPORTANT: Only proceed with approved exploitation attempts.
""",
            "POST_EXPLOIT": f"""
Perform post-exploitation on target: {request.target}

Tasks:
1. Enumerate local system information
2. Check for privilege escalation paths
3. Identify lateral movement opportunities
4. Look for sensitive data and credentials

Document all findings for the report.
""",
            "REPORT": f"""
Generate a comprehensive report for target: {request.target}

Include:
1. Executive summary
2. All findings with severity ratings
3. Exploitation proof
4. Remediation recommendations
5. MITRE ATT&CK technique mapping
"""
        }
        
        return phase_prompts.get(request.phase, f"Execute phase {request.phase} on {request.target}")
    
    async def _execute_with_logging(self, prompt: str, policy: PolicyEngine) -> List[Dict]:
        """Execute interpreter with full transaction logging"""
        
        findings = []
        start_time = time.time()
        
        # Track messages for logging
        messages_log = []
        
        for chunk in self.interpreter.chat(prompt, display=False, stream=True):
            if chunk.get('type') == 'message':
                messages_log.append({
                    'role': chunk.get('role', 'unknown'),
                    'content': chunk.get('content', '')
                })
                
            elif chunk.get('type') == 'code':
                # Command being executed
                command = chunk.get('content', '')
                
                # Policy check
                allowed, reason = policy.validate_command(command)
                
                if not allowed:
                    logger.warning(f"Command blocked by policy: {command} - {reason}")
                    continue
                
                # Log command transaction
                cmd_transaction = CommandTransaction(
                    transaction_id=str(uuid.uuid4()),
                    timestamp=datetime.utcnow().isoformat(),
                    command=command,
                    working_directory=os.getcwd(),
                    exit_code=0,  # Will be updated
                    stdout="",
                    stderr="",
                    duration_ms=0,
                    policy_decision=reason
                )
                
                self.current_job.command_transactions.append(cmd_transaction)
                self.transaction_logger.log_command_transaction(cmd_transaction)
                
            elif chunk.get('type') == 'confirmation':
                # Tool execution result
                output = chunk.get('content', '')
                
                # Check for findings in output
                if any(keyword in output.lower() for keyword in ['vulnerability', 'cve-', 'critical', 'high', 'exploit']):
                    findings.append({
                        'type': 'potential_vulnerability',
                        'raw_output': output[:1000],
                        'timestamp': datetime.utcnow().isoformat()
                    })
        
        # Calculate token usage (estimate)
        total_chars = sum(len(m.get('content', '')) for m in messages_log)
        estimated_tokens = total_chars // 4  # Rough estimate
        
        # Log LLM transaction
        llm_transaction = LLMTransaction(
            transaction_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow().isoformat(),
            model=os.getenv('LLM_MODEL', 'unknown'),
            prompt_tokens=estimated_tokens // 2,
            completion_tokens=estimated_tokens // 2,
            total_tokens=estimated_tokens,
            latency_ms=(time.time() - start_time) * 1000,
            messages=messages_log,
            response=messages_log[-1].get('content', '') if messages_log else '',
            cost_estimate_usd=self._estimate_cost(estimated_tokens, os.getenv('LLM_MODEL', 'unknown'))
        )
        
        self.current_job.llm_transactions.append(llm_transaction)
        self.current_job.total_tokens += estimated_tokens
        self.current_job.total_cost_usd += llm_transaction.cost_estimate_usd
        self.transaction_logger.log_llm_transaction(llm_transaction)
        
        return findings

# =============================================================================
# FASTAPI APPLICATION
# =============================================================================

app = FastAPI(
    title="TazoSploit Kali Executor",
    description="AI-powered pentest execution engine",
    version="2.0.0"
)

executor = AgentExecutor()

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "kali-executor"}

@app.post("/execute", response_model=ExecuteResponse)
async def execute_job(request: ExecuteRequest):
    """Execute a pentest job"""
    logger.info(f"Received job request: {request.job_id}")
    return await executor.execute_job(request)

@app.get("/logs/{job_id}")
async def get_job_logs(job_id: str):
    """Get logs for a specific job"""
    log_file = f"/pentest/logs/job_{job_id}.json"
    if os.path.exists(log_file):
        with open(log_file) as f:
            return json.load(f)
    raise HTTPException(status_code=404, detail="Job logs not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)
