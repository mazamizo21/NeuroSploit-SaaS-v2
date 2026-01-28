#!/usr/bin/env python3
"""
TazoSploit MCP Server Integration
Integrates Model Context Protocol servers to extend TazoSploit capabilities.

Features:
- MCP server connection/management
- Dynamic tool registration
- Capability extension via MCP
- MCP tools directory for common pentest MCP servers
"""

import asyncio
import json
import importlib
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import os


class MCPStatus(Enum):
    """Status of MCP server connection"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


@dataclass
class MCPTool:
    """Represents a tool exposed by an MCP server"""
    name: str
    description: str
    server_id: str
    input_schema: Dict[str, Any]
    category: str = "general"
    requires_target: bool = False
    example_usage: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert tool to dictionary"""
        return {
            "name": self.name,
            "description": self.description,
            "server_id": self.server_id,
            "input_schema": self.input_schema,
            "category": self.category,
            "requires_target": self.requires_target,
            "example_usage": self.example_usage,
            "metadata": self.metadata
        }


@dataclass
class MCPServer:
    """Represents an MCP server connection"""
    server_id: str
    name: str
    connection_string: str  # Could be stdio, HTTP, WebSocket, etc.
    server_type: str  # stdio, http, websocket
    status: MCPStatus = MCPStatus.DISCONNECTED
    tools: List[MCPTool] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class MCPIntegration:
    """
    Manages MCP server connections and tool registration.
    Extends TazoSploit capabilities through MCP protocol.
    """
    
    def __init__(self, mcp_tools_dir: str = None):
        self.mcp_tools_dir = mcp_tools_dir or os.path.join(os.path.dirname(__file__), "mcp_tools")
        self.servers: Dict[str, MCPServer] = {}
        self.tools: Dict[str, MCPTool] = {}
        self.registered_handlers: Dict[str, Callable] = {}
        
        # Create MCP tools directory
        os.makedirs(self.mcp_tools_dir, exist_ok=True)
        
        # Load built-in MCP tools
        self._load_builtin_tools()
    
    def _load_builtin_tools(self):
        """Load built-in MCP tool definitions"""
        # Look for .json files in mcp_tools directory
        mcp_dir = Path(self.mcp_tools_dir)
        if not mcp_dir.exists():
            return
        
        for tool_file in mcp_dir.glob("*.json"):
            try:
                with open(tool_file, 'r') as f:
                    tool_def = json.load(f)
                
                # Register tool
                tool = MCPTool(
                    name=tool_def.get("name"),
                    description=tool_def.get("description", ""),
                    server_id=tool_def.get("server_id", "builtin"),
                    input_schema=tool_def.get("input_schema", {}),
                    category=tool_def.get("category", "general"),
                    requires_target=tool_def.get("requires_target", False),
                    example_usage=tool_def.get("example_usage"),
                    metadata=tool_def.get("metadata", {})
                )
                
                self.tools[f"{tool.server_id}:{tool.name}"] = tool
                print(f"Loaded MCP tool: {tool.name}")
            
            except Exception as e:
                print(f"Error loading MCP tool {tool_file}: {e}")
    
    def add_server(self, server_id: str, name: str, connection_string: str,
                   server_type: str = "stdio", config: Dict[str, Any] = None,
                   metadata: Dict[str, Any] = None) -> MCPServer:
        """Add an MCP server configuration"""
        server = MCPServer(
            server_id=server_id,
            name=name,
            connection_string=connection_string,
            server_type=server_type,
            config=config or {},
            metadata=metadata or {}
        )
        
        self.servers[server_id] = server
        return server
    
    async def connect_server(self, server_id: str) -> bool:
        """Connect to an MCP server and discover tools"""
        server = self.servers.get(server_id)
        if not server:
            return False
        
        server.status = MCPStatus.CONNECTING
        
        try:
            if server.server_type == "stdio":
                await self._connect_stdio_server(server)
            elif server.server_type == "http":
                await self._connect_http_server(server)
            elif server.server_type == "websocket":
                await self._connect_websocket_server(server)
            else:
                raise ValueError(f"Unknown server type: {server.server_type}")
            
            server.status = MCPStatus.CONNECTED
            print(f"Connected to MCP server: {server.name}")
            return True
        
        except Exception as e:
            server.status = MCPStatus.ERROR
            print(f"Error connecting to MCP server {server_id}: {e}")
            return False
    
    async def _connect_stdio_server(self, server: MCPServer):
        """Connect to stdio-based MCP server"""
        # For stdio servers, we'd spawn a subprocess and communicate via JSON-RPC
        # This is a simplified implementation
        import subprocess
        
        # Parse connection string as command
        parts = server.connection_string.split()
        cmd = parts[0]
        args = parts[1:]
        
        # Spawn server process
        process = await asyncio.create_subprocess_exec(
            cmd, *args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Initialize MCP handshake
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "TazoSploit",
                    "version": "2.0"
                }
            }
        }
        
        # Send initialize request
        # In real implementation, we'd handle JSON-RPC properly
        # For now, this is a placeholder
        
        # Discover tools
        # In real implementation, we'd call tools/list
        
        # Example: Add some placeholder tools
        server.tools = [
            MCPTool(
                name="scan_network",
                description="Scan a network range for hosts and services",
                server_id=server.server_id,
                input_schema={
                    "type": "object",
                    "properties": {
                        "network": {"type": "string"},
                        "ports": {"type": "string"}
                    }
                },
                category="reconnaissance",
                requires_target=True
            )
        ]
        
        # Register tools
        for tool in server.tools:
            self.tools[f"{server.server_id}:{tool.name}"] = tool
    
    async def _connect_http_server(self, server: MCPServer):
        """Connect to HTTP-based MCP server"""
        import aiohttp
        
        async with aiohttp.ClientSession() as session:
            # Initialize connection
            url = f"{server.connection_string}/initialize"
            
            async with session.post(url, json={
                "protocolVersion": "2024-11-05",
                "capabilities": {}
            }) as response:
                if response.status != 200:
                    raise Exception(f"HTTP MCP server initialization failed: {response.status}")
                
                init_response = await response.json()
            
            # Get capabilities
            server.capabilities = init_response.get("capabilities", [])
            
            # List tools
            tools_url = f"{server.connection_string}/tools/list"
            async with session.get(tools_url) as response:
                tools_response = await response.json()
                
                for tool_def in tools_response.get("tools", []):
                    tool = MCPTool(
                        name=tool_def.get("name"),
                        description=tool_def.get("description", ""),
                        server_id=server.server_id,
                        input_schema=tool_def.get("inputSchema", {}),
                        category=tool_def.get("category", "general"),
                        requires_target=tool_def.get("requiresTarget", False),
                        metadata=tool_def
                    )
                    
                    server.tools.append(tool)
                    self.tools[f"{server.server_id}:{tool.name}"] = tool
    
    async def _connect_websocket_server(self, server: MCPServer):
        """Connect to WebSocket-based MCP server"""
        import websockets
        
        async with websockets.connect(server.connection_string) as ws:
            # Initialize connection
            init_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "TazoSploit",
                        "version": "2.0"
                    }
                }
            }
            
            await ws.send(json.dumps(init_request))
            response = json.loads(await ws.recv())
            
            # Get capabilities
            server.capabilities = response.get("result", {}).get("capabilities", [])
            
            # List tools
            tools_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }
            
            await ws.send(json.dumps(tools_request))
            tools_response = json.loads(await ws.recv())
            
            for tool_def in tools_response.get("result", {}).get("tools", []):
                tool = MCPTool(
                    name=tool_def.get("name"),
                    description=tool_def.get("description", ""),
                    server_id=server.server_id,
                    input_schema=tool_def.get("inputSchema", {}),
                    category=tool_def.get("category", "general"),
                    requires_target=tool_def.get("requiresTarget", False),
                    metadata=tool_def
                )
                
                server.tools.append(tool)
                self.tools[f"{server.server_id}:{tool.name}"] = tool
    
    async def disconnect_server(self, server_id: str) -> bool:
        """Disconnect from an MCP server"""
        server = self.servers.get(server_id)
        if not server:
            return False
        
        server.status = MCPStatus.DISCONNECTED
        
        # Unregister tools from this server
        tools_to_remove = [k for k in self.tools.keys() if k.startswith(f"{server_id}:")]
        for tool_key in tools_to_remove:
            del self.tools[tool_key]
        
        return True
    
    async def call_tool(self, tool_id: str, arguments: Dict[str, Any]) -> Any:
        """Call an MCP tool"""
        tool = self.tools.get(tool_id)
        if not tool:
            raise ValueError(f"Tool not found: {tool_id}")
        
        server = self.servers.get(tool.server_id)
        if not server or server.status != MCPStatus.CONNECTED:
            raise Exception(f"Server not connected: {tool.server_id}")
        
        # Call tool based on server type
        if server.server_type == "stdio":
            return await self._call_stdio_tool(server, tool, arguments)
        elif server.server_type == "http":
            return await self._call_http_tool(server, tool, arguments)
        elif server.server_type == "websocket":
            return await self._call_websocket_tool(server, tool, arguments)
        else:
            raise ValueError(f"Unknown server type: {server.server_type}")
    
    async def _call_stdio_tool(self, server: MCPServer, tool: MCPTool, 
                              arguments: Dict[str, Any]) -> Any:
        """Call tool on stdio server"""
        # Placeholder implementation
        return {"result": f"Called {tool.name} with {arguments}"}
    
    async def _call_http_tool(self, server: MCPServer, tool: MCPTool,
                             arguments: Dict[str, Any]) -> Any:
        """Call tool on HTTP server"""
        import aiohttp
        
        url = f"{server.connection_string}/tools/call"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json={
                "name": tool.name,
                "arguments": arguments
            }) as response:
                return await response.json()
    
    async def _call_websocket_tool(self, server: MCPServer, tool: MCPTool,
                                   arguments: Dict[str, Any]) -> Any:
        """Call tool on WebSocket server"""
        import websockets
        
        async with websockets.connect(server.connection_string) as ws:
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": tool.name,
                    "arguments": arguments
                }
            }
            
            await ws.send(json.dumps(request))
            response = json.loads(await ws.recv())
            
            return response.get("result")
    
    def get_tools_by_category(self, category: str) -> List[MCPTool]:
        """Get all tools in a specific category"""
        return [t for t in self.tools.values() if t.category == category]
    
    def get_tools_by_server(self, server_id: str) -> List[MCPTool]:
        """Get all tools from a specific server"""
        return [t for t in self.tools.values() if t.server_id == server_id]
    
    def register_handler(self, tool_id: str, handler: Callable):
        """Register a custom handler for a tool"""
        self.registered_handlers[tool_id] = handler
    
    def get_all_tools(self) -> List[MCPTool]:
        """Get all registered tools"""
        return list(self.tools.values())
    
    def get_tool(self, tool_id: str) -> Optional[MCPTool]:
        """Get a specific tool"""
        return self.tools.get(tool_id)
    
    def get_server_status(self, server_id: str) -> Optional[MCPStatus]:
        """Get connection status of a server"""
        server = self.servers.get(server_id)
        return server.status if server else None
    
    def list_servers(self) -> List[MCPServer]:
        """List all configured servers"""
        return list(self.servers.values())


def create_mcp_tool_definition(
    name: str,
    description: str,
    server_id: str = "builtin",
    input_schema: Dict[str, Any] = None,
    category: str = "general",
    requires_target: bool = False,
    example_usage: str = None
) -> Dict[str, Any]:
    """Create an MCP tool definition dictionary"""
    return {
        "name": name,
        "description": description,
        "server_id": server_id,
        "input_schema": input_schema or {},
        "category": category,
        "requires_target": requires_target,
        "example_usage": example_usage,
        "metadata": {}
    }


if __name__ == "__main__":
    async def test_mcp():
        # Create MCP integration
        mcp = MCPIntegration()
        
        # Add a test HTTP server
        mcp.add_server(
            server_id="test_server",
            name="Test MCP Server",
            connection_string="http://localhost:8080/mcp",
            server_type="http"
        )
        
        # Connect to server (will fail if not running)
        success = await mcp.connect_server("test_server")
        print(f"Connection result: {success}")
        
        # List all tools
        tools = mcp.get_all_tools()
        print(f"Available tools: {len(tools)}")
        for tool in tools:
            print(f"  - {tool.name}: {tool.description}")
    
    asyncio.run(test_mcp())
