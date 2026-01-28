# MCP Integration Documentation

## Overview

The TazoSploit MCP (Model Context Protocol) Integration enables dynamic tool registration and capability extension through MCP servers. This allows TazoSploit to leverage external tools and services without hardcoding them into the core system.

## Architecture

```
mcp_integration.py
├── MCPIntegration           # MCP server manager
├── MCPServer              # MCP server connection
├── MCPTool                # Tool definition from MCP
├── MCPStatus              # Connection status
└── mcp_tools/            # Built-in tool definitions
    ├── nmap_scan.json
    ├── sqlmap_exploit.json
    └── ...
```

## Core Components

### MCPIntegration

Manages MCP server connections and tool registration:

```python
from mcp_integration import MCPIntegration

# Initialize MCP integration
mcp = MCPIntegration(mcp_tools_dir="/path/to/mcp_tools")

# Add a server
mcp.add_server(
    server_id="nmap_server",
    name="Nmap Scanner",
    connection_string="stdio:/usr/bin/nmap",
    server_type="stdio"
)

# Connect to server
await mcp.connect_server("nmap_server")

# Call a tool
result = await mcp.call_tool("nmap_server:nmap_scan", {
    "network": "192.168.1.0/24",
    "ports": "1-65535"
})
```

### MCPTool

Represents a tool exposed by an MCP server:

```python
@dataclass
class MCPTool:
    name: str                      # Tool name
    description: str               # Tool description
    server_id: str                # Server providing the tool
    input_schema: Dict[str, Any]   # JSON Schema for inputs
    category: str                  # Tool category
    requires_target: bool           # Whether tool needs target
    example_usage: Optional[str]    # Example usage
    metadata: Dict[str, Any]       # Additional metadata
```

### MCPServer

Represents an MCP server connection:

```python
@dataclass
class MCPServer:
    server_id: str                 # Unique server ID
    name: str                     # Human-readable name
    connection_string: str         # How to connect (stdio, http, websocket)
    server_type: str              # Connection type
    status: MCPStatus            # Connection status
    tools: List[MCPTool]         # Tools provided by server
    capabilities: List[str]        # Server capabilities
    config: Dict[str, Any]        # Server configuration
    metadata: Dict[str, Any]       # Additional metadata
```

## Server Types

### 1. Stdio Servers

Server communicates via stdin/stdout:

```python
mcp.add_server(
    server_id="nmap_stdio",
    name="Nmap (Stdio)",
    connection_string="/usr/bin/nmap --interactive",
    server_type="stdio"
)

# MCP will spawn subprocess and communicate via JSON-RPC
```

### 2. HTTP Servers

Server exposes HTTP endpoint:

```python
mcp.add_server(
    server_id="nmap_http",
    name="Nmap (HTTP)",
    connection_string="http://localhost:8080/mcp",
    server_type="http"
)

# MCP will make HTTP requests to interact
```

### 3. WebSocket Servers

Server communicates via WebSocket:

```python
mcp.add_server(
    server_id="nmap_ws",
    name="Nmap (WebSocket)",
    connection_string="ws://localhost:9000/mcp",
    server_type="websocket"
)

# MCP will establish WebSocket connection
```

## Tool Discovery

When a server is connected, MCP automatically discovers tools:

```python
# Connect to server
await mcp.connect_server("nmap_server")

# Tools are automatically discovered and registered
tools = mcp.get_tools_by_server("nmap_server")

for tool in tools:
    print(f"- {tool.name}: {tool.description}")
```

### Tool Registration Process

1. **Initialize Connection**: MCP sends initialize request
2. **Exchange Capabilities**: Server shares capabilities
3. **List Tools**: MCP requests tool list
4. **Register Tools**: Each tool is registered in MCPIntegration

## Built-in MCP Tools

Pre-defined tool definitions in `mcp_tools/` directory:

### nmap_scan.json

```json
{
  "name": "nmap_scan",
  "description": "Perform network scanning with nmap",
  "category": "reconnaissance",
  "requires_target": true,
  "input_schema": {
    "type": "object",
    "properties": {
      "network": {"type": "string"},
      "ports": {"type": "string"},
      "scan_type": {"type": "string"},
      "service_detection": {"type": "boolean"},
      "os_detection": {"type": "boolean"}
    },
    "required": ["network"]
  }
}
```

### sqlmap_exploit.json

```json
{
  "name": "sqlmap_exploit",
  "description": "Automated SQL injection exploitation",
  "category": "exploitation",
  "requires_target": true,
  "input_schema": {
    "type": "object",
    "properties": {
      "url": {"type": "string"},
      "action": {"type": "string"},
      "database": {"type": "string"},
      "level": {"type": "integer"},
      "risk": {"type": "integer"},
      "batch": {"type": "boolean"}
    },
    "required": ["url"]
  }
}
```

## Tool Execution

Execute tools through MCP integration:

```python
# Call tool
result = await mcp.call_tool("nmap_server:nmap_scan", {
    "network": "192.168.1.0/24",
    "ports": "1-65535",
    "service_detection": true,
    "os_detection": false
})

# Result structure:
{
    "tool": "nmap_scan",
    "success": true,
    "output": "...",
    "duration": 45.2,
    "artifacts": ["nmap_scan.xml"]
}
```

### Tool Call Flow

1. **Validate Input**: Validate against input_schema
2. **Route to Server**: Route to appropriate MCP server
3. **Execute on Server**: Server executes tool
4. **Return Result**: Result is returned to caller

## API Reference

### MCPIntegration

```python
class MCPIntegration:
    def __init__(self, mcp_tools_dir: str = None)
    def add_server(self, server_id: str, name: str, connection_string: str,
                   server_type: str = "stdio", config: Dict[str, Any] = None,
                   metadata: Dict[str, Any] = None) -> MCPServer
    async def connect_server(self, server_id: str) -> bool
    async def disconnect_server(self, server_id: str) -> bool
    async def call_tool(self, tool_id: str, arguments: Dict[str, Any]) -> Any
    def get_tools_by_category(self, category: str) -> List[MCPTool]
    def get_tools_by_server(self, server_id: str) -> List[MCPTool]
    def register_handler(self, tool_id: str, handler: Callable)
    def get_all_tools(self) -> List[MCPTool]
    def get_tool(self, tool_id: str) -> Optional[MCPTool]
    def get_server_status(self, server_id: str) -> Optional[MCPStatus]
    def list_servers(self) -> List[MCPServer]
```

## Adding Custom MCP Servers

### Step 1: Define Tool Schema

Create tool definition JSON in `mcp_tools/`:

```json
{
  "name": "my_custom_tool",
  "description": "Description of what tool does",
  "category": "custom",
  "requires_target": true,
  "example_usage": "my_custom_tool(target=\"192.168.1.100\", option=\"value\")",
  "input_schema": {
    "type": "object",
    "properties": {
      "target": {
        "type": "string",
        "description": "Target to scan/test"
      },
      "option": {
        "type": "string",
        "description": "Option for the tool"
      }
    },
    "required": ["target"]
  }
}
```

### Step 2: Add Server

```python
# Add MCP server
mcp.add_server(
    server_id="custom_server",
    name="Custom MCP Server",
    connection_string="http://localhost:9999/mcp",
    server_type="http"
)
```

### Step 3: Connect and Use

```python
# Connect to server
await mcp.connect_server("custom_server")

# Call tool
result = await mcp.call_tool("custom_server:my_custom_tool", {
    "target": "192.168.1.100",
    "option": "value"
})
```

## Tool Categories

Tools are organized by category for easy filtering:

```python
# Get all reconnaissance tools
recon_tools = mcp.get_tools_by_category("reconnaissance")

# Get all exploitation tools
exploit_tools = mcp.get_tools_by_category("exploitation")

# Get all credential access tools
cred_tools = mcp.get_tools_by_category("credential_access")
```

### Standard Categories

- `reconnaissance`: Network discovery and scanning
- `exploitation`: Vulnerability exploitation
- `credential_access`: Credential extraction
- `privilege_escalation`: Escalating privileges
- `lateral_movement`: Moving across networks
- `persistence`: Maintaining access
- `post_exploitation`: After exploitation
- `custom`: User-defined tools

## Examples

### Example 1: Basic MCP Setup

```python
import asyncio
from mcp_integration import MCPIntegration

async def main():
    # Initialize MCP
    mcp = MCPIntegration()
    
    # Add Nmap server
    mcp.add_server(
        server_id="nmap",
        name="Nmap Scanner",
        connection_string="/usr/bin/nmap --interactive",
        server_type="stdio"
    )
    
    # Connect
    await mcp.connect_server("nmap")
    
    # List tools
    tools = mcp.get_all_tools()
    for tool in tools:
        print(f"- {tool.name}: {tool.description}")
    
    # Call tool
    result = await mcp.call_tool("nmap:nmap_scan", {
        "network": "192.168.1.0/24",
        "ports": "1-65535"
    })
    
    print(result)

asyncio.run(main())
```

### Example 2: Multi-Server Setup

```python
# Add multiple servers
servers = [
    ("nmap", "Nmap Scanner", "/usr/bin/nmap --interactive", "stdio"),
    ("sqlmap", "SQLMap", "http://localhost:8080/mcp", "http"),
    ("metasploit", "Metasploit", "ws://localhost:9000/mcp", "websocket")
]

for server_id, name, conn, type in servers:
    mcp.add_server(server_id, name, conn, type)
    await mcp.connect_server(server_id)

# All tools are now available
all_tools = mcp.get_all_tools()
print(f"Total tools: {len(all_tools)}")
```

### Example 3: Creating Custom Tool

```python
from mcp_integration import create_mcp_tool_definition

# Define tool
tool_def = create_mcp_tool_definition(
    name="custom_scanner",
    description="Custom vulnerability scanner",
    server_id="custom_server",
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "scan_type": {"type": "string"}
        },
        "required": ["target"]
    },
    category="reconnaissance",
    requires_target=True,
    example_usage="custom_scanner(target=\"192.168.1.100\", scan_type=\"full\")"
)

# Write to file
import json
with open("/path/to/mcp_tools/custom_scanner.json", "w") as f:
    json.dump(tool_def, f, indent=2)

# Tool will be loaded on next MCPIntegration init
```

## Best Practices

1. **Define Clear Schemas**: Use JSON Schema for clear input validation.
2. **Categorize Tools**: Assign appropriate category for organization.
3. **Provide Examples**: Include example_usage for documentation.
4. **Handle Errors**: Gracefully handle tool execution errors.
5. **Track Performance**: Monitor tool performance and reliability.
6. **Document Tools**: Keep tool descriptions up-to-date.

## Troubleshooting

### Server Connection Fails

**Problem**: Can't connect to MCP server.

**Solution**:
1. Verify connection string is correct
2. Check server type matches (stdio/http/websocket)
3. Ensure server is running and accessible
4. Check network connectivity for HTTP/WebSocket
5. Review error logs for details

### Tools Not Discovered

**Problem**: Tools aren't being discovered after connection.

**Solution**:
1. Check server implements MCP protocol correctly
2. Verify tools/list endpoint returns valid response
3. Ensure tool JSON files are valid
4. Check MCP protocol version compatibility

### Tool Execution Fails

**Problem**: Tool calls fail with errors.

**Solution**:
1. Validate input matches input_schema
2. Check required parameters are provided
3. Verify tool is available on server
4. Review server logs for execution errors
5. Ensure server has necessary permissions

## Integration with Skills System

MCP tools integrate with Skills System:

```python
from skills.skill_loader import SkillLoader
from mcp_integration import MCPIntegration

# Initialize both systems
skill_loader = SkillLoader()
mcp = MCPIntegration()

# Map MCP tools to skills
for tool in mcp.get_all_tools():
    # Find corresponding skill
    matching_skills = skill_loader.get_skills_by_category(tool.category)
    
    # Add tool to skill's tool list
    for skill in matching_skills:
        print(f"MCP tool {tool.name} available for skill {skill.name}")
```

## Security Considerations

1. **Validate Inputs**: Always validate against input_schema.
2. **Sanitize Commands**: Prevent command injection in stdio servers.
3. **Rate Limit**: Don't overwhelm servers with requests.
4. **Authenticate Servers**: Verify server identity before connection.
5. **Audit Logs**: Log all tool executions for audit trail.

## Future Enhancements

- Tool marketplace/community sharing
- Automatic server discovery
- Tool versioning and updates
- Tool dependency management
- Performance monitoring and ranking
- Distributed tool execution across multiple servers
- Tool sandboxing for security
