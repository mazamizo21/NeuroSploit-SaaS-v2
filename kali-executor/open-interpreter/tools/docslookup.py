#!/usr/bin/env python3
"""
Documentation Lookup Tool for TazoSploit AI Agent
Helps AI find documentation for tools, commands, and security concepts.
"""

import os
import sys
import argparse
import requests
from typing import Optional

TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY", "")

def lookup_docs(tool_or_topic: str) -> str:
    """
    Look up documentation for a tool or topic.
    Searches security-focused sites and documentation.
    """
    # Construct a documentation-focused query
    query = f"{tool_or_topic} documentation syntax examples usage"
    
    # Add security context for common tools
    security_tools = ["nmap", "hydra", "sqlmap", "metasploit", "nikto", "gobuster", 
                      "burp", "wireshark", "john", "hashcat", "dirb", "wfuzz",
                      "searchsploit", "msfvenom", "netcat", "nc"]
    
    if any(tool in tool_or_topic.lower() for tool in security_tools):
        query = f"{tool_or_topic} penetration testing syntax examples kali linux"
    
    if not TAVILY_API_KEY:
        return f"Error: TAVILY_API_KEY not set. Cannot search documentation."
    
    try:
        response = requests.post(
            "https://api.tavily.com/search",
            json={
                "api_key": TAVILY_API_KEY,
                "query": query,
                "max_results": 5,
                "include_answer": True,
                "search_depth": "advanced",
                "include_domains": [
                    "kali.org", "exploit-db.com", "hacktricks.xyz",
                    "github.com", "man7.org", "linux.die.net",
                    "offensive-security.com", "portswigger.net"
                ]
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            output = f"Documentation for: {tool_or_topic}\n"
            output += "=" * 60 + "\n\n"
            
            # AI-generated summary
            if data.get("answer"):
                output += f"SUMMARY:\n{data['answer']}\n\n"
                output += "-" * 40 + "\n\n"
            
            # Detailed results
            for i, r in enumerate(data.get("results", []), 1):
                output += f"[{i}] {r.get('title', 'No title')}\n"
                output += f"    Source: {r.get('url', '')}\n"
                output += f"    {r.get('content', '')[:600]}\n\n"
            
            return output
        else:
            return f"Error searching documentation: HTTP {response.status_code}"
            
    except Exception as e:
        return f"Error: {e}"

def main():
    parser = argparse.ArgumentParser(
        description="Look up documentation for tools and commands",
        usage="docslookup <tool_or_topic>"
    )
    parser.add_argument("topic", nargs="+", help="Tool or topic to look up")
    
    args = parser.parse_args()
    topic = " ".join(args.topic)
    
    result = lookup_docs(topic)
    print(result)

if __name__ == "__main__":
    main()
