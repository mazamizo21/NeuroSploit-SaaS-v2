#!/usr/bin/env python3
"""
Live Log Monitor for TazoSploit
Watches LLM interaction logs and reports significant events
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path

class LogMonitor:
    def __init__(self, log_dir="./logs"):
        self.log_dir = Path(log_dir)
        self.llm_log = self.log_dir / "llm_interactions.jsonl"
        self.agent_log = self.log_dir / "agent_executions.jsonl"
        self.last_position = {}
        self.interaction_count = 0
        
    def tail_file(self, filepath):
        """Read new lines from file since last position"""
        if not filepath.exists():
            return []
        
        # Initialize position tracking
        if str(filepath) not in self.last_position:
            self.last_position[str(filepath)] = 0
        
        with open(filepath, 'r') as f:
            f.seek(self.last_position[str(filepath)])
            new_lines = f.readlines()
            self.last_position[str(filepath)] = f.tell()
        
        return new_lines
    
    def analyze_llm_interaction(self, data):
        """Analyze LLM interaction and determine if it's significant"""
        findings = []
        
        # Check for errors
        if data.get("error"):
            findings.append(f"🔴 ERROR: {data['error']}")
        
        # Check for high latency
        latency_ms = data.get("latency_ms", 0)
        if latency_ms > 30000:
            findings.append(f"⚠️  HIGH LATENCY: {latency_ms/1000:.1f}s")
        
        # Check for high token usage
        total_tokens = data.get("total_tokens", 0)
        if total_tokens > 5000:
            findings.append(f"📊 HIGH TOKEN USAGE: {total_tokens} tokens")
        
        # Extract interesting content from response
        response = data.get("response", "")
        
        # Check for commands
        if "```bash" in response or "```sh" in response:
            findings.append("💻 COMMAND GENERATED")
        
        # Check for security findings
        security_keywords = ["vulnerability", "exploit", "CVE-", "critical", "high severity", "SQL injection", "XSS", "RCE"]
        for keyword in security_keywords:
            if keyword.lower() in response.lower():
                findings.append(f"🔍 SECURITY FINDING: {keyword}")
                break
        
        # Check for tool mentions
        tools = ["nmap", "sqlmap", "metasploit", "hydra", "nikto", "gobuster", "burp", "searchsploit"]
        mentioned_tools = [tool for tool in tools if tool in response.lower()]
        if mentioned_tools:
            findings.append(f"🛠️  TOOLS: {', '.join(mentioned_tools)}")
        
        return findings
    
    def analyze_agent_execution(self, data):
        """Analyze agent command execution"""
        findings = []
        
        command = data.get("command", "")
        exit_code = data.get("exit_code", 0)
        output = data.get("output", "")
        
        # Check for failed commands
        if exit_code != 0:
            findings.append(f"❌ COMMAND FAILED (exit {exit_code}): {command[:60]}")
        else:
            findings.append(f"✅ COMMAND SUCCESS: {command[:60]}")
        
        # Check for interesting output patterns
        if "open port" in output.lower() or "open|" in output:
            findings.append("🔓 OPEN PORTS FOUND")
        
        if "vulnerable" in output.lower():
            findings.append("🎯 VULNERABILITY DETECTED")
        
        if "password" in output.lower() or "credentials" in output.lower():
            findings.append("🔑 CREDENTIALS FOUND")
        
        return findings
    
    def format_report(self, timestamp, source, findings):
        """Format findings as a report"""
        if not findings:
            return None
        
        report = f"\n{'='*70}\n"
        report += f"⏰ {timestamp}\n"
        report += f"📁 Source: {source}\n"
        report += f"{'-'*70}\n"
        for finding in findings:
            report += f"  {finding}\n"
        report += f"{'='*70}\n"
        return report
    
    def monitor(self, interval=2):
        """Monitor logs continuously"""
        print("🔍 TazoSploit Log Monitor Started")
        print(f"📂 Watching: {self.log_dir}")
        print(f"🔄 Refresh interval: {interval}s")
        print(f"{'='*70}\n")
        
        try:
            while True:
                # Check LLM interactions
                llm_lines = self.tail_file(self.llm_log)
                for line in llm_lines:
                    try:
                        data = json.loads(line.strip())
                        self.interaction_count += 1
                        
                        timestamp = data.get("timestamp", datetime.utcnow().isoformat())
                        findings = self.analyze_llm_interaction(data)
                        
                        # Always show interaction count
                        model = data.get("model", "unknown")
                        tokens = data.get("total_tokens", 0)
                        latency = data.get("latency_ms", 0) / 1000
                        
                        print(f"[{self.interaction_count}] LLM Call: {model} | {tokens} tokens | {latency:.1f}s")
                        
                        # Show detailed findings if significant
                        if findings:
                            report = self.format_report(timestamp, "LLM Interaction", findings)
                            if report:
                                print(report)
                    except json.JSONDecodeError:
                        pass
                
                # Check agent executions
                agent_lines = self.tail_file(self.agent_log)
                for line in agent_lines:
                    try:
                        data = json.loads(line.strip())
                        timestamp = data.get("timestamp", datetime.utcnow().isoformat())
                        findings = self.analyze_agent_execution(data)
                        
                        if findings:
                            report = self.format_report(timestamp, "Agent Execution", findings)
                            if report:
                                print(report)
                    except json.JSONDecodeError:
                        pass
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Monitor stopped")
            print(f"📊 Total interactions monitored: {self.interaction_count}")

if __name__ == "__main__":
    monitor = LogMonitor(log_dir="./logs")
    monitor.monitor(interval=2)
