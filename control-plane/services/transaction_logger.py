"""
NeuroSploit SaaS v2 - Transaction Logger Service
Full transaction logging for audit and debugging
"""

import os
import json
from datetime import datetime
from typing import Dict, Any
import structlog

logger = structlog.get_logger()

class TransactionLogger:
    """Logs all transactions for audit and debugging visibility"""
    
    def __init__(self, log_dir: str = "/app/logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
    def log_api_request(self, request_id: str, method: str, path: str, 
                        tenant_id: str, user_id: str, body: Dict = None):
        """Log API request"""
        self._write_log("api_requests", {
            "request_id": request_id,
            "timestamp": datetime.utcnow().isoformat(),
            "method": method,
            "path": path,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "body": body
        })
        
    def log_job_event(self, job_id: str, event: str, details: Dict = None):
        """Log job lifecycle event"""
        self._write_log("job_events", {
            "job_id": job_id,
            "timestamp": datetime.utcnow().isoformat(),
            "event": event,
            "details": details
        })
        
    def log_llm_interaction(self, job_id: str, model: str, tokens: int, 
                           cost: float, messages: list):
        """Log LLM API interaction"""
        self._write_log("llm_interactions", {
            "job_id": job_id,
            "timestamp": datetime.utcnow().isoformat(),
            "model": model,
            "tokens": tokens,
            "cost_usd": cost,
            "message_count": len(messages)
        })
        
    def log_command_execution(self, job_id: str, command: str, 
                             exit_code: int, duration_ms: int):
        """Log command execution"""
        self._write_log("command_executions", {
            "job_id": job_id,
            "timestamp": datetime.utcnow().isoformat(),
            "command": command[:500],  # Truncate long commands
            "exit_code": exit_code,
            "duration_ms": duration_ms
        })
        
    def _write_log(self, log_type: str, data: Dict[str, Any]):
        """Write log entry to file"""
        log_file = os.path.join(self.log_dir, f"{log_type}.jsonl")
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(data) + '\n')
        except Exception as e:
            logger.error("log_write_failed", log_type=log_type, error=str(e))
