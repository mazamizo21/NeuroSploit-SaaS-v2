# Natural Language Interface Documentation

## Overview

The TazoSploit Natural Language Interface (NLI) enables human interaction with the pentesting system using natural language commands. Users can ask questions, give instructions, and receive responses in conversational format.

## Architecture

```
nli.py
├── NaturalLanguageParser     # Parses natural language input
├── NaturalLanguageInterface   # Main interaction interface
├── ParsedCommand            # Parsed command data structure
├── NLResponse              # Response data structure
└── Intent                  # Recognized intents
```

## Core Components

### NaturalLanguageParser

Extracts intent, targets, and parameters from natural language input:

```python
from nli import NaturalLanguageParser

parser = NaturalLanguageParser()

# Parse user input
parsed = parser.parse("Scan the network 192.168.1.0/24")

# Result:
# ParsedCommand(
#     intent=Intent.SCAN,
#     confidence=0.7,
#     target="192.168.1.0/24",
#     action="network_scan",
#     parameters={},
#     raw_input="Scan the network 192.168.1.0/24"
# )
```

### NaturalLanguageInterface

Main interface for processing natural language input:

```python
from nli import NaturalLanguageInterface

nli = NaturalLanguageInterface()

# Process input
response = nli.process_input("What did you find?")

# Result:
# NLResponse(
#     message="Found 15 security issues...",
#     intent=Intent.QUERY,
#     data={"findings": [...]},
#     suggestions=["Generate a report", "Continue scanning"],
#     follow_up_questions=[]
# )
```

## Supported Intents

### 1. SCAN

Commands related to scanning and reconnaissance:

```python
"Scan the network 192.168.1.0/24"
"Find open ports on target"
"Discover services on host 192.168.1.100"
"Run nmap scan on 10.0.0.0/8"
```

**Parameters**:
- `target`: IP address, hostname, or URL
- `port`/`ports`: Port range to scan
- `tool`: Specific tool to use
- `depth`: Scan depth/level

### 2. EXPLOIT

Commands related to vulnerability exploitation:

```python
"Test for SQL injection vulnerabilities"
"Exploit the target http://example.com"
"Check for XSS vulnerabilities"
"Attempt to get root access"
"Crack passwords on this system"
```

**Parameters**:
- `target`: IP address or URL
- `vuln_type`: Type of vulnerability (sql, xss, etc.)
- `username`: Username for attacks
- `password`: Password for attacks

### 3. REPORT

Commands for generating and viewing reports:

```python
"Generate a report"
"Show me a summary of findings"
"What did you find?"
"Summarize the pentest results"
"Create a detailed report"
```

**Parameters**:
- `format`: Report format (markdown, json, pdf)
- `include`: What to include (findings, recommendations, etc.)

### 4. QUERY

General questions about findings, targets, or status:

```python
"What vulnerabilities did you find?"
"What's the current status?"
"List all targets"
"Show me the findings"
"How many hosts were discovered?"
```

**Parameters**:
- `query_type`: Type of query (findings, targets, status, etc.)

### 5. HELP

Commands for getting help and guidance:

```python
"Help"
"What can you do?"
"How do I use this?"
"Show me instructions"
"Give me some examples"
```

### 6. STATUS

Commands for checking current status:

```python
"What's the status?"
"Where are we?"
"How are we doing?"
"Show current progress"
"What's happening now?"
```

### 7. STOP

Commands to stop the engagement:

```python
"Stop"
"That's enough"
"Quit"
"Cancel the test"
"I'm done"
```

### 8. PAUSE

Commands to pause the engagement:

```python
"Pause"
"Hold on a moment"
"Wait"
"Suspend"
```

### 9. RESUME

Commands to resume a paused engagement:

```python
"Resume"
"Continue"
"Go on"
"Start again"
"Keep going"
```

## Intent Recognition

The parser uses pattern matching to recognize intents:

```python
# Pattern examples for SCAN intent:
patterns = [
    r"(?:scan|discover|recon|enumerate|map|probe|explore)\s+(?:the\s+)?(?:network|hosts|services|target)",
    r"run\s+(?:nmap|port\s*scan|service\s*discovery)",
    r"what\s+(?:services|hosts|ports)\s+are\s+(?:running|open|available)",
    r"find\s+(?:open\s+)?ports?"
]
```

### Confidence Scoring

Each intent match contributes to a confidence score:

- Long, specific patterns: +0.4 points
- Medium patterns: +0.3 points
- Short patterns: +0.2 points
- Maximum score: 1.0

Example:
```
Input: "Scan the network 192.168.1.0/24"

Matches:
- "scan the network" (medium): +0.3
- "network" (short): +0.2

Total confidence: 0.5
```

## Parameter Extraction

The parser extracts parameters using regex patterns:

```python
# Target extraction
patterns = [
    r"(?:target|host|network|server|site|url|ip|address)\s*(?::|=|is|at)?\s*[:=]?\s*([^\s,]+)",
    r"(?:http[s]?://|www\.)[^\s,]+",
    r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?",
    r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
]

# Port extraction
r"(?:port|p)\s*(?::|=)?\s*(\d+)"

# Tool extraction
r"(?:using|with|tool)\s*[:=]?\s*(\w+)"
```

## Session State

The NLI maintains session state across interactions:

```python
session_state = {
    "current_target": "192.168.1.100",
    "current_objective": "Complete security assessment",
    "last_action": "scan",
    "findings": [
        {
            "severity": "high",
            "title": "SQL Injection",
            "description": "..."
        }
    ],
    "context": {...}
}
```

## API Integration

### FastAPI Endpoint

Add to `control-plane/api/routers/nli.py`:

```python
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from nli import NaturalLanguageInterface

router = APIRouter(prefix="/api/v1/nli", tags=["natural-language"])
nli = NaturalLanguageInterface()

class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"
    session_context: dict = None

class ChatResponse(BaseModel):
    message: str
    intent: str
    confidence: float
    data: dict = None
    suggestions: list
    follow_up_questions: list

@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """Process natural language chat message"""
    try:
        # Update session context
        if request.session_context:
            nli.session_state.update(request.session_context)
        
        # Process input
        response = nli.process_input(request.message)
        
        return ChatResponse(
            message=response.message,
            intent=response.intent.value,
            confidence=nli.parser._detect_intent(request.message)[1],
            data=response.data,
            suggestions=response.suggestions,
            follow_up_questions=response.follow_up_questions
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/intents")
async def get_intents():
    """Get list of supported intents"""
    return {
        "intents": [
            {"name": "scan", "description": "Scanning and reconnaissance"},
            {"name": "exploit", "description": "Vulnerability exploitation"},
            {"name": "report", "description": "Generate reports"},
            {"name": "query", "description": "Ask questions"},
            {"name": "help", "description": "Get help"},
            {"name": "status", "description": "Check status"},
            {"name": "stop", "description": "Stop engagement"},
            {"name": "pause", "description": "Pause engagement"},
            {"name": "resume", "description": "Resume engagement"}
        ]
    }

@router.get("/intents/examples")
async def get_intent_examples():
    """Get example queries for each intent"""
    return {
        "scan": [
            "Scan the network 192.168.1.0/24",
            "Find open ports on target"
        ],
        "exploit": [
            "Test for SQL injection vulnerabilities",
            "Exploit the target"
        ],
        # ... more intents
    }
```

## Usage Examples

### Example 1: Basic Conversation

```python
from nli import NaturalLanguageInterface

nli = NaturalLanguageInterface()

# User: Help
response = nli.process_input("Help")
print(response.message)
# Output: I can help you with: Scanning & Reconnaissance, Exploitation...

# User: Scan network
response = nli.process_input("Scan 192.168.1.0/24")
print(response.message)
# Output: Starting scan of target: 192.168.1.0/24
#         Scanning for open ports...

# User: What did you find?
response = nli.process_input("What did you find?")
print(response.message)
# Output: Found 15 security issues:
#         1. HIGH - SQL Injection in login.php
#         2. MEDIUM - Weak password policy...
```

### Example 2: Multi-step Engagement

```python
nli = NaturalLanguageInterface()

queries = [
    "Scan the network 192.168.1.0/24",
    "Test for SQL injection on http://192.168.1.100/login.php",
    "What's the status?",
    "Generate a report",
    "Stop"
]

for query in queries:
    print(f"User: {query}")
    response = nli.process_input(query)
    print(f"Bot: {response.message[:100]}...")
    print()
```

### Example 3: Error Recovery

```python
# User provides ambiguous input
response = nli.process_input("Do something")

# Response provides suggestions
print(response.message)
# Output: I didn't understand your request. Could you be more specific?

print(response.suggestions)
# Output: ["Scan a target", "Exploit a vulnerability", "Generate a report"]

print(response.follow_up_questions)
# Output: ["Do you want to scan a target?",
#          "Are you looking to exploit a vulnerability?",
#          "Would you like a report?"]
```

## Best Practices

1. **Be Specific**: Provide clear targets and objectives.
2. **Use Keywords**: Include key words like "scan", "exploit", "report".
3. **Provide Context**: Include targets in your commands.
4. **Check Confidence**: Review the confidence score of parsed commands.
5. **Use Follow-up Questions**: Act on follow-up questions when unsure.

## Examples

### Example 1: Simple Scanning

```python
parser = NaturalLanguageParser()

# Input
command = "Scan the network 192.168.1.0/24 for open ports"

# Parsed
parsed = parser.parse(command)
print(f"Intent: {parsed.intent.value}")
print(f"Target: {parsed.target}")
print(f"Action: {parsed.action}")
```

### Example 2: Vulnerability Testing

```python
command = "Test http://example.com/login for SQL injection vulnerabilities"

parsed = parser.parse(command)
print(f"Intent: {parsed.intent.value}")
print(f"Target: {parsed.target}")
print(f"Vulnerability Type: {parsed.parameters.get('vuln_type')}")
```

### Example 3: Getting Status

```python
command = "What's the current status?"

parsed = parser.parse(command)
response = nli.process_input(command)

print(response.message)
# Shows current target, objective, findings, etc.
```

## Troubleshooting

### Intent Not Recognized

**Problem**: Commands aren't being recognized correctly.

**Solution**:
1. Use key words: "scan", "exploit", "report"
2. Be specific about what you want
3. Provide targets in your commands
4. Check confidence score of parsed command

### Target Not Extracted

**Problem**: Targets aren't being extracted from commands.

**Solution**:
1. Use clear IP addresses (e.g., "192.168.1.100")
2. Use full URLs (e.g., "http://example.com")
3. Place target at the end of the command
4. Use "target" keyword (e.g., "target: 192.168.1.100")

### Ambiguous Commands

**Problem**: Bot asks for clarification.

**Solution**:
1. Be more specific in your command
2. Include the target
3. Use follow-up questions to guide the bot
4. Review suggestions provided by the bot

## Integration with DynamicAgent

NLI integrates with DynamicAgent for command execution:

```python
from nli import NaturalLanguageInterface
from dynamic_agent import DynamicAgent

nli = NaturalLanguageInterface()
agent = DynamicAgent()

# Process NLI command
response = nli.process_input("Scan 192.168.1.100")

# Extract data for agent
if response.intent == Intent.SCAN:
    target = response.data.get("target")
    objective = response.data.get("action")
    
    # Execute with agent
    report = agent.run(target, objective)
```

## Future Enhancements

- Machine learning for improved intent recognition
- Context-aware conversations
- Multi-turn dialogue support
- Voice input/output
- Multi-language support
- Custom intent training
- Integration with chatbots (ChatGPT, Claude, etc.)
