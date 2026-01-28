#!/usr/bin/env python3
"""
TazoSploit Natural Language Interface
Provides natural language parsing for pentest requests.

Features:
- Command parser for natural language pentest requests
- Intent recognition (scan, exploit, report, query)
- Response formatting for interactive use
"""

import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone


class Intent(Enum):
    """Recognized intents from natural language input"""
    UNKNOWN = "unknown"
    SCAN = "scan"
    EXPLOIT = "exploit"
    REPORT = "report"
    QUERY = "query"
    HELP = "help"
    STATUS = "status"
    STOP = "stop"
    PAUSE = "pause"
    RESUME = "resume"


@dataclass
class ParsedCommand:
    """Represents a parsed natural language command"""
    intent: Intent
    confidence: float  # 0.0 to 1.0
    target: Optional[str] = None
    action: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    raw_input: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "intent": self.intent.value,
            "confidence": self.confidence,
            "target": self.target,
            "action": self.action,
            "parameters": self.parameters,
            "raw_input": self.raw_input,
            "metadata": self.metadata
        }


@dataclass
class NLResponse:
    """Represents a natural language response"""
    message: str
    intent: Intent
    data: Optional[Dict[str, Any]] = None
    suggestions: List[str] = field(default_factory=list)
    follow_up_questions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "message": self.message,
            "intent": self.intent.value,
            "data": self.data,
            "suggestions": self.suggestions,
            "follow_up_questions": self.follow_up_questions,
            "metadata": self.metadata
        }


class NaturalLanguageParser:
    """
    Parses natural language pentest requests and extracts intent, targets, and parameters.
    """
    
    def __init__(self):
        # Intent patterns (regex-based for now, could use ML models)
        self.intent_patterns = {
            Intent.SCAN: [
                r"(?:scan|discover|recon|enumerate|map|probe|explore)\s+(?:the\s+)?(?:network|hosts|services|target)",
                r"run\s+(?:nmap|port\s*scan|service\s*discovery)",
                r"what\s+(?:services|hosts|ports)\s+are\s+(?:running|open|available)",
                r"find\s+(?:open\s+)?ports?"
            ],
            Intent.EXPLOIT: [
                r"(?:exploit|attack|hack|pwn|compromise|breach)",
                r"(?:test\s+for|check\s+for|find)\s+(?:vulnerabilities|vulns|bugs|weaknesses)",
                r"sql\s*inject(?:ion)?|xss|cross(?:-|\s*)site\s*scripting",
                r"(?:get\s+)?(?:root\s+)?access|privilege\s*escalat",
                r"(?:crack|brute\s*force|dump)\s+(?:passwords|creds|credentials|hashes)"
            ],
            Intent.REPORT: [
                r"(?:generate|create|show|get|display)\s+(?:a\s+)?(?:report|summary)",
                r"what\s+did\s+(?:you\s+)?find|what\s+(?:were\s+)?(?:the\s+)?(?:results|findings)",
                r"summarize|summary"
            ],
            Intent.QUERY: [
                r"(?:what|how|why|which|who|where|when|is|are|do|does|can)",
                r"(?:tell|show|list|display)\s+me",
                r"(?:explain|describe)"
            ],
            Intent.HELP: [
                r"(?:help|assist|guide|instruction)",
                r"what\s+can\s+(?:you\s+)?do",
                r"(?:how\s+do\s+I|how\s+to)"
            ],
            Intent.STATUS: [
                r"(?:status|progress|state|current)",
                r"(?:what'?s\s+happening|where\s+are\s+we|how\s+(?:are\s+)?(?:we\s+)?(?:doing|going))"
            ],
            Intent.STOP: [
                r"(?:stop|cancel|abort|halt|terminate|quit)",
                r"(?:no\s+more|that'?s\s+(?:enough|it|all))"
            ],
            Intent.PAUSE: [
                r"(?:pause|suspend|hold)",
                r"(?:wait|stop\s+(?:for\s+)?(?:a\s+)?moment)"
            ],
            Intent.RESUME: [
                r"(?:resume|continue|proceed|go\s+on)",
                r"(?:start\s+)?(?:back\s+(?:up|again)|keep\s+going)"
            ]
        }
        
        # Target extraction patterns
        self.target_patterns = [
            r"(?:target|host|network|server|site|url|ip|address)\s*(?::|=|is|at)?\s*[:=]?\s*([^\s,]+)",
            r"(?:http[s]?://|www\.)[^\s,]+",
            r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?",
            r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        ]
        
        # Parameter extraction patterns
        self.parameter_patterns = {
            "port": r"(?:port|p)\s*(?::|=)?\s*(\d+)",
            "ports": r"(?:ports?|p)\s*(?::|=)?\s*([\d,-]+)",
            "username": r"(?:username|user|u)\s*(?::|=)?\s*(\S+)",
            "password": r"(?:password|pass|pw)\s*(?::|=)?\s*(\S+)",
            "depth": r"(?:depth|level|l)\s*(?::|=)?\s*(\d+)",
            "tool": r"(?:using|with|tool)\s*[:=]?\s*(\w+)",
            "output": r"(?:output|o|file)\s*(?::|=)?\s*(\S+)",
            "timeout": r"(?:timeout|t)\s*(?::|=)?\s*(\d+)"
        }
    
    def parse(self, input_text: str) -> ParsedCommand:
        """
        Parse natural language input and extract intent and parameters.
        """
        input_text = input_text.strip()
        if not input_text:
            return ParsedCommand(
                intent=Intent.UNKNOWN,
                confidence=0.0,
                raw_input=input_text
            )
        
        # Detect intent
        intent, confidence = self._detect_intent(input_text)
        
        # Extract target
        target = self._extract_target(input_text)
        
        # Extract parameters
        parameters = self._extract_parameters(input_text)
        
        # Determine action based on intent and parameters
        action = self._determine_action(intent, input_text, parameters)
        
        # Create parsed command
        parsed = ParsedCommand(
            intent=intent,
            confidence=confidence,
            target=target,
            action=action,
            parameters=parameters,
            raw_input=input_text,
            metadata={
                "parsed_at": datetime.now(timezone.utc).isoformat()
            }
        )
        
        return parsed
    
    def _detect_intent(self, input_text: str) -> Tuple[Intent, float]:
        """Detect the primary intent from input text"""
        input_lower = input_text.lower()
        
        # Score each intent
        intent_scores = {}
        for intent, patterns in self.intent_patterns.items():
            score = 0.0
            for pattern in patterns:
                if re.search(pattern, input_lower):
                    # More specific patterns get higher scores
                    if len(pattern) > 30:
                        score += 0.4
                    elif len(pattern) > 20:
                        score += 0.3
                    else:
                        score += 0.2
            
            # Cap at 1.0
            intent_scores[intent] = min(score, 1.0)
        
        # Find highest scoring intent
        if not intent_scores:
            return Intent.UNKNOWN, 0.0
        
        best_intent = max(intent_scores, key=intent_scores.get)
        return best_intent, intent_scores[best_intent]
    
    def _extract_target(self, input_text: str) -> Optional[str]:
        """Extract target (IP, URL, hostname) from input"""
        for pattern in self.target_patterns:
            matches = re.findall(pattern, input_text, re.IGNORECASE)
            if matches:
                # Return the first match
                target = matches[0].strip()
                # Clean up
                target = target.rstrip(',.;')
                return target
        return None
    
    def _extract_parameters(self, input_text: str) -> Dict[str, Any]:
        """Extract key-value parameters from input"""
        parameters = {}
        
        for param_name, pattern in self.parameter_patterns.items():
            matches = re.findall(pattern, input_text, re.IGNORECASE)
            if matches:
                parameters[param_name] = matches[0]
        
        return parameters
    
    def _determine_action(self, intent: Intent, input_text: str, 
                          parameters: Dict[str, Any]) -> Optional[str]:
        """Determine the specific action based on intent and parameters"""
        if intent == Intent.SCAN:
            if "port" in parameters:
                return "scan_ports"
            elif "service" in input_text.lower():
                return "scan_services"
            else:
                return "network_scan"
        elif intent == Intent.EXPLOIT:
            if "sql" in input_text.lower():
                return "sql_injection"
            elif "xss" in input_text.lower():
                return "xss_exploit"
            elif "credential" in input_text.lower() or "password" in input_text.lower():
                return "credential_access"
            elif "privilege" in input_text.lower() or "escalate" in input_text.lower():
                return "privilege_escalation"
            else:
                return "vulnerability_scan"
        elif intent == Intent.REPORT:
            if "summary" in input_text.lower():
                return "summary_report"
            else:
                return "full_report"
        elif intent == Intent.QUERY:
            # Extract what's being queried
            if "finding" in input_text.lower() or "vulnerability" in input_text.lower():
                return "query_findings"
            elif "target" in input_text.lower() or "host" in input_text.lower():
                return "query_targets"
            else:
                return "general_query"
        else:
            return None
    
    def format_for_agent(self, parsed: ParsedCommand) -> str:
        """Format parsed command for agent execution"""
        if parsed.intent == Intent.UNKNOWN:
            return "I didn't understand your request. Could you rephrase it?"
        
        lines = [f"Executing: {parsed.action or parsed.intent.value}"]
        
        if parsed.target:
            lines.append(f"Target: {parsed.target}")
        
        if parsed.parameters:
            lines.append("Parameters:")
            for key, value in parsed.parameters.items():
                lines.append(f"  {key}: {value}")
        
        return "\n".join(lines)


class NaturalLanguageInterface:
    """
    Main interface for natural language interaction with TazoSploit.
    Handles parsing, execution, and response formatting.
    """
    
    def __init__(self):
        self.parser = NaturalLanguageParser()
        self.session_state: Dict[str, Any] = {
            "current_target": None,
            "current_objective": None,
            "last_action": None,
            "findings": [],
            "context": {}
        }
    
    def process_input(self, input_text: str, session_context: Dict[str, Any] = None) -> NLResponse:
        """
        Process natural language input and return response.
        """
        # Update session context
        if session_context:
            self.session_state.update(session_context)
        
        # Parse input
        parsed = self.parser.parse(input_text)
        
        # Generate response based on intent
        if parsed.intent == Intent.UNKNOWN:
            return self._handle_unknown(parsed)
        elif parsed.intent == Intent.HELP:
            return self._handle_help(parsed)
        elif parsed.intent == Intent.STATUS:
            return self._handle_status(parsed)
        elif parsed.intent == Intent.STOP:
            return self._handle_stop(parsed)
        elif parsed.intent == Intent.PAUSE:
            return self._handle_pause(parsed)
        elif parsed.intent == Intent.RESUME:
            return self._handle_resume(parsed)
        elif parsed.intent == Intent.SCAN:
            return self._handle_scan(parsed)
        elif parsed.intent == Intent.EXPLOIT:
            return self._handle_exploit(parsed)
        elif parsed.intent == Intent.REPORT:
            return self._handle_report(parsed)
        elif parsed.intent == Intent.QUERY:
            return self._handle_query(parsed)
        else:
            return self._handle_unknown(parsed)
    
    def _handle_unknown(self, parsed: ParsedCommand) -> NLResponse:
        """Handle unknown/ambiguous input"""
        suggestions = [
            "Scan the target",
            "Test for vulnerabilities",
            "Generate a report",
            "Get help"
        ]
        
        return NLResponse(
            message="I didn't understand your request. Could you be more specific?",
            intent=Intent.UNKNOWN,
            suggestions=suggestions,
            follow_up_questions=[
                "Do you want to scan a target?",
                "Are you looking to exploit a vulnerability?",
                "Would you like a report of findings?"
            ]
        )
    
    def _handle_help(self, parsed: ParsedCommand) -> NLResponse:
        """Handle help requests"""
        message = """I can help you with:

**Scanning & Reconnaissance**
- "Scan the network 192.168.1.0/24"
- "Find open ports on target"
- "Discover services on host"

**Exploitation**
- "Test for SQL injection vulnerabilities"
- "Exploit the target"
- "Check for XSS vulnerabilities"

**Reports**
- "Generate a report"
- "Show me the findings"
- "Summarize the results"

**Queries**
- "What vulnerabilities did you find?"
- "What's the current status?"
- "List all targets"

**Control**
- "Stop" or "Pause" the engagement
- "Resume" a paused session

Try asking me something specific!"""
        
        return NLResponse(
            message=message,
            intent=Intent.HELP,
            suggestions=[
                "Scan a target",
                "Exploit a vulnerability",
                "Generate a report"
            ]
        )
    
    def _handle_status(self, parsed: ParsedCommand) -> NLResponse:
        """Handle status requests"""
        message = f"""**Current Status:**
- Target: {self.session_state.get('current_target', 'Not set')}
- Objective: {self.session_state.get('current_objective', 'Not set')}
- Last Action: {self.session_state.get('last_action', 'None')}
- Findings: {len(self.session_state.get('findings', []))}"""
        
        return NLResponse(
            message=message,
            intent=Intent.STATUS,
            data=self.session_state
        )
    
    def _handle_stop(self, parsed: ParsedCommand) -> NLResponse:
        """Handle stop requests"""
        self.session_state["paused"] = False
        self.session_state["stopped"] = True
        
        return NLResponse(
            message="Stopping the pentest engagement. All findings have been saved.",
            intent=Intent.STOP,
            metadata={"action": "stop"}
        )
    
    def _handle_pause(self, parsed: ParsedCommand) -> NLResponse:
        """Handle pause requests"""
        self.session_state["paused"] = True
        
        return NLResponse(
            message="Pausing the pentest engagement. Say 'resume' to continue.",
            intent=Intent.PAUSE,
            metadata={"action": "pause"}
        )
    
    def _handle_resume(self, parsed: ParsedCommand) -> NLResponse:
        """Handle resume requests"""
        self.session_state["paused"] = False
        self.session_state["stopped"] = False
        
        return NLResponse(
            message="Resuming the pentest engagement.",
            intent=Intent.RESUME,
            metadata={"action": "resume"}
        )
    
    def _handle_scan(self, parsed: ParsedCommand) -> NLResponse:
        """Handle scan requests"""
        target = parsed.target
        
        if not target:
            return NLResponse(
                message="I need a target to scan. Please provide an IP address, hostname, or URL.",
                intent=Intent.SCAN,
                follow_up_questions=["What target would you like to scan?"]
            )
        
        self.session_state["current_target"] = target
        self.session_state["last_action"] = "scan"
        
        message = f"Starting scan of target: {target}\n\n"
        
        if parsed.action == "scan_ports":
            message += "Scanning for open ports..."
        elif parsed.action == "scan_services":
            message += "Scanning for services and versions..."
        else:
            message += "Performing comprehensive network scan..."
        
        if "port" in parsed.parameters:
            message += f"\nPort range: {parsed.parameters['port']}"
        
        return NLResponse(
            message=message,
            intent=Intent.SCAN,
            data={
                "action": "scan",
                "target": target,
                "parameters": parsed.parameters
            }
        )
    
    def _handle_exploit(self, parsed: ParsedCommand) -> NLResponse:
        """Handle exploitation requests"""
        target = parsed.target or self.session_state.get("current_target")
        
        if not target:
            return NLResponse(
                message="I need a target to test. Please provide an IP address or URL.",
                intent=Intent.EXPLOIT,
                follow_up_questions=["What target would you like to test?"]
            )
        
        self.session_state["current_target"] = target
        self.session_state["last_action"] = "exploit"
        
        message = f"Testing {target} for vulnerabilities...\n\n"
        
        if parsed.action == "sql_injection":
            message += "Testing for SQL injection vulnerabilities..."
        elif parsed.action == "xss_exploit":
            message += "Testing for XSS vulnerabilities..."
        elif parsed.action == "credential_access":
            message += "Attempting credential extraction..."
        elif parsed.action == "privilege_escalation":
            message += "Attempting privilege escalation..."
        else:
            message += "Running comprehensive vulnerability assessment..."
        
        return NLResponse(
            message=message,
            intent=Intent.EXPLOIT,
            data={
                "action": "exploit",
                "target": target,
                "vuln_type": parsed.action
            }
        )
    
    def _handle_report(self, parsed: ParsedCommand) -> NLResponse:
        """Handle report requests"""
        findings_count = len(self.session_state.get("findings", []))
        
        message = f"""**Pentest Report Summary**
- Target: {self.session_state.get('current_target', 'N/A')}
- Total Findings: {findings_count}
- High Severity: {len([f for f in self.session_state.get('findings', []) if f.get('severity') == 'high'])}
- Medium Severity: {len([f for f in self.session_state.get('findings', []) if f.get('severity') == 'medium'])}
- Low Severity: {len([f for f in self.session_state.get('findings', []) if f.get('severity') == 'low'])}"""
        
        return NLResponse(
            message=message,
            intent=Intent.REPORT,
            data={
                "action": "report",
                "findings": self.session_state.get("findings", [])
            }
        )
    
    def _handle_query(self, parsed: ParsedCommand) -> NLResponse:
        """Handle query requests"""
        if parsed.action == "query_findings":
            findings = self.session_state.get("findings", [])
            if not findings:
                return NLResponse(
                    message="No findings recorded yet.",
                    intent=Intent.QUERY,
                    data={"findings": []}
                )
            
            message = f"Found {len(findings)} security issues:\n\n"
            for i, finding in enumerate(findings[:10], 1):
                message += f"{i}. **{finding.get('severity', 'info').upper()}** - {finding.get('title', 'Unknown')}\n"
            
            if len(findings) > 10:
                message += f"\n... and {len(findings) - 10} more."
            
            return NLResponse(
                message=message,
                intent=Intent.QUERY,
                data={"findings": findings}
            )
        
        elif parsed.action == "query_targets":
            return NLResponse(
                message=f"Current target: {self.session_state.get('current_target', 'Not set')}",
                intent=Intent.QUERY,
                data={"target": self.session_state.get("current_target")}
            )
        
        else:
            return NLResponse(
                message="I'm not sure what you're asking for. Could you be more specific?",
                intent=Intent.QUERY,
                suggestions=[
                    "What findings do you have?",
                    "What's the target?",
                    "Generate a report"
                ]
            )


# Example usage and API integration
def create_nli_api_routes():
    """
    Return FastAPI route definitions for NLI integration.
    To be used in control-plane/api/routers/
    """
    routes_code = '''
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List

router = APIRouter(prefix="/api/v1/nli", tags=["natural-language"])

nli = NaturalLanguageInterface()

class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"

class ChatResponse(BaseModel):
    message: str
    intent: str
    data: Dict[str, Any] = None
    suggestions: List[str] = []

@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """Process natural language chat message"""
    try:
        response = nli.process_input(request.message)
        return ChatResponse(
            message=response.message,
            intent=response.intent.value,
            data=response.data,
            suggestions=response.suggestions
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/intents")
async def get_intents():
    """Get list of supported intents"""
    return {"intents": [intent.value for intent in Intent]}
'''
    return routes_code


if __name__ == "__main__":
    # Test NLI
    nli = NaturalLanguageInterface()
    
    test_queries = [
        "Scan the network 192.168.1.0/24",
        "Test for SQL injection vulnerabilities",
        "What did you find?",
        "Generate a report",
        "Help",
        "What's the status?"
    ]
    
    for query in test_queries:
        print(f"\nQuery: {query}")
        print("-" * 50)
        response = nli.process_input(query)
        print(f"Intent: {response.intent.value} (confidence: {nli.parser._detect_intent(query)[1]:.2f})")
        print(f"Response: {response.message[:200]}...")
