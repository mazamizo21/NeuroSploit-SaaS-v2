#!/usr/bin/env python3
"""
TazoSploit Proactive Monitoring (Heartbeat System)
Continuously monitors for security issues and threat intelligence.

Features:
- New service discovery
- CVE checks on discovered tech stack
- Credential reuse pattern detection
- Daily threat summary generation
- Notification system (Slack, email, log alerts)
"""

import asyncio
import subprocess
import json
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from memory.memory_store import EnhancedMemoryStore, ThreatPattern


class AlertLevel(Enum):
    """Severity level for alerts"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    """Represents a security alert"""
    alert_id: str
    level: AlertLevel
    category: str  # service_discovery, cve, credential_reuse, etc.
    title: str
    description: str
    target: str
    timestamp: str
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ServiceInfo:
    """Information about a discovered service"""
    service_name: str
    host: str
    port: int
    version: Optional[str] = None
    protocol: Optional[str] = None
    discovered_at: str = None
    
    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.now(timezone.utc).isoformat()


class HeartbeatConfig:
    """Configuration for heartbeat system"""
    def __init__(self):
        self.check_interval_minutes = 60
        self.cve_check_interval_hours = 24
        self.daily_summary_time = "08:00"  # Local time
        self.scan_networks: List[str] = []
        self.notification_channels: List[str] = []
        self.smtp_server: Optional[str] = None
        self.smtp_port: int = 587
        self.smtp_username: Optional[str] = None
        self.smtp_password: Optional[str] = None
        self.smtp_from: Optional[str] = None
        self.smtp_to: List[str] = []
        self.slack_webhook_url: Optional[str] = None
        self.log_file = "/pentest/logs/heartbeat.log"


class HeartbeatSystem:
    """
    Proactive monitoring system for continuous security checks.
    Monitors for new services, CVEs, credential patterns, and generates alerts.
    """
    
    def __init__(self, config: HeartbeatConfig = None, memory_store: EnhancedMemoryStore = None):
        self.config = config or HeartbeatConfig()
        self.memory_store = memory_store
        self.alerts: List[Alert] = []
        self.known_services: List[ServiceInfo] = []
        self.running = False
        
        # Ensure log directory exists
        os.makedirs(os.path.dirname(self.config.log_file), exist_ok=True)
    
    def _log(self, message: str, level: str = "INFO"):
        """Log message to file and console"""
        timestamp = datetime.now(timezone.utc).isoformat()
        log_line = f"[{timestamp}] [{level}] {message}"
        print(log_line)
        
        with open(self.config.log_file, 'a') as f:
            f.write(log_line + '\n')
    
    async def start(self):
        """Start the heartbeat monitoring loop"""
        self.running = True
        self._log("Heartbeat monitoring started")
        
        while self.running:
            try:
                await self._run_checks()
                await asyncio.sleep(self.config.check_interval_minutes * 60)
            except Exception as e:
                self._log(f"Error in heartbeat loop: {e}", "ERROR")
                await asyncio.sleep(60)
    
    def stop(self):
        """Stop the heartbeat monitoring"""
        self.running = False
        self._log("Heartbeat monitoring stopped")
    
    async def _run_checks(self):
        """Run all configured security checks"""
        self._log("Running heartbeat checks...")
        
        # 1. Service discovery
        await self._check_new_services()
        
        # 2. CVE checks (less frequent)
        await self._check_cves()
        
        # 3. Credential reuse detection
        await self._check_credential_reuse()
        
        # 4. Daily summary (if time)
        await self._generate_daily_summary()
    
    async def _check_new_services(self):
        """Check for newly discovered services"""
        self._log("Checking for new services...")
        
        if not self.config.scan_networks:
            return
        
        for network in self.config.scan_networks:
            try:
                # Run nmap scan
                result = await asyncio.create_subprocess_exec(
                    "nmap", "-sS", "-p1-65535", "-T4", network,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = await result.communicate()
                
                if result.returncode == 0:
                    services = self._parse_nmap_output(stdout.decode())
                    new_services = self._identify_new_services(services)
                    
                    if new_services:
                        for service in new_services:
                            alert = Alert(
                                alert_id=self._generate_id(),
                                level=AlertLevel.INFO,
                                category="service_discovery",
                                title=f"New Service Discovered: {service.service_name}",
                                description=f"Service {service.service_name} discovered on {service.host}:{service.port}",
                                target=f"{service.host}:{service.port}",
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                evidence=[f"{service.host}:{service.port}"],
                                recommendations=["Verify service is authorized", "Scan for vulnerabilities"]
                            )
                            self.alerts.append(alert)
                            self._send_alert(alert)
                            self._log(f"New service discovered: {service.service_name} on {service.host}:{service.port}")
                    
                    self.known_services.extend(services)
            
            except Exception as e:
                self._log(f"Error scanning network {network}: {e}", "ERROR")
    
    def _parse_nmap_output(self, output: str) -> List[ServiceInfo]:
        """Parse nmap output to extract service information"""
        services = []
        
        # Parse nmap grepable output format
        lines = output.split('\n')
        for line in lines:
            if 'Host:' in line and 'Ports:' in line:
                # Extract host
                host_match = re.search(r'Host:\s*(\S+)', line)
                if not host_match:
                    continue
                host = host_match.group(1)
                
                # Extract ports
                ports_match = re.search(r'Ports:\s*(.+?)(?:\t|OS:|Seq:)', line)
                if not ports_match:
                    continue
                
                ports_str = ports_match.group(1)
                port_entries = ports_str.split(',')
                
                for entry in port_entries:
                    if '/' not in entry:
                        continue
                    
                    parts = entry.strip().split('/')
                    if len(parts) < 3:
                        continue
                    
                    port = int(parts[0])
                    state = parts[1]
                    if state != 'open':
                        continue
                    
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = None
                    
                    # Extract version if present
                    version_match = re.search(r'([0-9.]+)', entry)
                    if version_match:
                        version = version_match.group(1)
                    
                    services.append(ServiceInfo(
                        service_name=service,
                        host=host,
                        port=port,
                        version=version
                    ))
        
        return services
    
    def _identify_new_services(self, services: List[ServiceInfo]) -> List[ServiceInfo]:
        """Identify services that weren't seen before"""
        new_services = []
        
        # Create set of known service identifiers
        known_identifiers = {
            f"{s.host}:{s.port}:{s.service_name}"
            for s in self.known_services
        }
        
        for service in services:
            identifier = f"{service.host}:{service.port}:{s.service_name}"
            if identifier not in known_identifiers:
                new_services.append(service)
        
        return new_services
    
    async def _check_cves(self):
        """Check for CVEs in discovered tech stack"""
        self._log("Checking for CVEs...")
        
        # Get last check time from memory or use default
        last_check = self.memory_store.get_target_knowledge("last_cve_check") if self.memory_store else None
        if last_check:
            last_check_time = datetime.fromisoformat(last_check)
            if datetime.now(timezone.utc) - last_check_time < timedelta(hours=self.config.cve_check_interval_hours):
                return
        
        # Check services for known CVEs
        for service in self.known_services:
            if service.version:
                # Use cve_lookup if available
                try:
                    # In real implementation, this would use CVE database
                    # For now, we'll use a placeholder
                    pass
                except Exception as e:
                    self._log(f"Error checking CVE for {service.service_name}: {e}", "ERROR")
        
        # Update last check time
        if self.memory_store:
            self.memory_store.update_target_knowledge(
                "last_cve_check",
                datetime.now(timezone.utc).isoformat()
            )
    
    async def _check_credential_reuse(self):
        """Check for credential reuse patterns"""
        self._log("Checking credential reuse patterns...")
        
        if not self.memory_store:
            return
        
        # Get credential patterns from memory
        # Look for patterns that appear multiple times across targets
        reused_patterns = []
        
        for cred_pattern in self.memory_store.credential_patterns:
            if cred_pattern.count > 1:
                reused_patterns.append(cred_pattern)
        
        # Generate alerts for reused credentials
        for pattern in reused_patterns:
            alert = Alert(
                alert_id=self._generate_id(),
                level=AlertLevel.HIGH if pattern.count >= 3 else AlertLevel.MEDIUM,
                category="credential_reuse",
                title=f"Credential Pattern Reused {pattern.count} Times",
                description=f"Credential pattern '{pattern.pattern}' reused across {pattern.count} targets",
                target=", ".join(pattern.targets[:5]),
                timestamp=datetime.now(timezone.utc).isoformat(),
                evidence=[f"Pattern: {pattern.pattern}"],
                recommendations=[
                    "Implement unique credentials per system",
                    "Use credential management system",
                    "Rotate compromised credentials immediately"
                ],
                metadata={"pattern_type": pattern.category, "count": pattern.count}
            )
            
            # Check if we already sent a similar alert recently
            recent_similar = [
                a for a in self.alerts 
                if a.category == "credential_reuse" 
                and a.metadata.get("pattern") == pattern.pattern
                and datetime.fromisoformat(a.timestamp) > datetime.now(timezone.utc) - timedelta(hours=24)
            ]
            
            if not recent_similar:
                self.alerts.append(alert)
                self._send_alert(alert)
                self._log(f"Credential reuse detected: {pattern.pattern}")
    
    async def _generate_daily_summary(self):
        """Generate daily threat summary if it's time"""
        now = datetime.now()
        
        # Check if it's the right time for daily summary
        if now.strftime("%H:%M") != self.config.daily_summary_time:
            return
        
        # Check if we already generated a summary today
        last_summary = self.memory_store.get_target_knowledge("last_daily_summary") if self.memory_store else None
        if last_summary:
            last_summary_date = datetime.fromisoformat(last_summary).date()
            if last_summary_date == now.date():
                return
        
        # Generate summary
        summary = self._create_threat_summary()
        
        # Send as alert
        alert = Alert(
            alert_id=self._generate_id(),
            level=AlertLevel.INFO,
            category="daily_summary",
            title="Daily Threat Summary",
            description=summary,
            target="global",
            timestamp=datetime.now(timezone.utc).isoformat(),
            recommendations=[]
        )
        
        self.alerts.append(alert)
        self._send_alert(alert)
        
        # Update last summary time
        if self.memory_store:
            self.memory_store.update_target_knowledge(
                "last_daily_summary",
                now.isoformat()
            )
        
        self._log("Daily threat summary generated")
    
    def _create_threat_summary(self) -> str:
        """Create a summary of recent threats and patterns"""
        # Get alerts from last 24 hours
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        recent_alerts = [
            a for a in self.alerts 
            if datetime.fromisoformat(a.timestamp) > cutoff
        ]
        
        # Count by category
        category_counts = {}
        for alert in recent_alerts:
            category_counts[alert.category] = category_counts.get(alert.category, 0) + 1
        
        # Generate summary
        lines = [
            "## Daily Threat Summary",
            f"**Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            "",
            f"**Total Alerts (24h)**: {len(recent_alerts)}",
            ""
        ]
        
        if category_counts:
            lines.append("**Alerts by Category:**")
            for category, count in category_counts.items():
                lines.append(f"- {category}: {count}")
            lines.append("")
        
        if recent_alerts:
            lines.append("**Recent Critical/High Alerts:**")
            critical_high = [a for a in recent_alerts if a.level in [AlertLevel.CRITICAL, AlertLevel.HIGH]]
            for alert in critical_high[:5]:
                lines.append(f"- **[{alert.level.value.upper()}]** {alert.title}")
                lines.append(f"  {alert.description[:100]}...")
                lines.append("")
        
        return "\n".join(lines)
    
    def _send_alert(self, alert: Alert):
        """Send alert through configured notification channels"""
        for channel in self.config.notification_channels:
            try:
                if channel == "slack" and self.config.slack_webhook_url:
                    self._send_slack_alert(alert)
                elif channel == "email" and self.config.smtp_server:
                    self._send_email_alert(alert)
                elif channel == "log":
                    self._log(f"ALERT [{alert.level.value}] {alert.title}: {alert.description}")
            except Exception as e:
                self._log(f"Error sending alert via {channel}: {e}", "ERROR")
    
    def _send_slack_alert(self, alert: Alert):
        """Send alert to Slack webhook"""
        import urllib.request
        
        # Format message for Slack
        color = {
            AlertLevel.INFO: "good",
            AlertLevel.LOW: "good",
            AlertLevel.MEDIUM: "warning",
            AlertLevel.HIGH: "danger",
            AlertLevel.CRITICAL: "danger"
        }.get(alert.level, "good")
        
        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"[{alert.level.value.upper()}] {alert.title}",
                    "text": alert.description,
                    "fields": [
                        {"title": "Category", "value": alert.category},
                        {"title": "Target", "value": alert.target},
                        {"title": "Time", "value": alert.timestamp}
                    ],
                    "footer": "TazoSploit Heartbeat"
                }
            ]
        }
        
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            self.config.slack_webhook_url,
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        
        with urllib.request.urlopen(req) as response:
            response.read()
    
    def _send_email_alert(self, alert: Alert):
        """Send alert via email"""
        msg = MIMEMultipart()
        msg['From'] = self.config.smtp_from
        msg['To'] = ', '.join(self.config.smtp_to)
        msg['Subject'] = f"[{alert.level.value.upper()}] {alert.title}"
        
        body = f"""
Alert Details:
- Category: {alert.category}
- Level: {alert.level.value}
- Target: {alert.target}
- Time: {alert.timestamp}

Description:
{alert.description}

Recommendations:
{chr(10).join(f"- {r}" for r in alert.recommendations)}

Evidence:
{chr(10).join(f"- {e}" for e in alert.evidence)}
"""
        
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
            server.starttls()
            if self.config.smtp_username and self.config.smtp_password:
                server.login(self.config.smtp_username, self.config.smtp_password)
            server.send_message(msg)
    
    def _generate_id(self) -> str:
        """Generate unique alert ID"""
        import uuid
        return str(uuid.uuid4())
    
    def get_recent_alerts(self, hours: int = 24) -> List[Alert]:
        """Get alerts from the last N hours"""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return [
            a for a in self.alerts 
            if datetime.fromisoformat(a.timestamp) > cutoff
        ]
    
    def get_alerts_by_level(self, level: AlertLevel) -> List[Alert]:
        """Get alerts filtered by level"""
        return [a for a in self.alerts if a.level == level]
    
    def get_alerts_by_category(self, category: str) -> List[Alert]:
        """Get alerts filtered by category"""
        return [a for a in self.alerts if a.category == category]


def generate_cron_config(heartbeat_config: HeartbeatConfig) -> str:
    """Generate crontab configuration for heartbeat system"""
    cron_entries = [
        f"# TazoSploit Heartbeat Monitoring",
        f"# Run heartbeat checks every {heartbeat_config.check_interval_minutes} minutes",
        f"*/{heartbeat_config.check_interval_minutes} * * * * cd /pentest && python3 heartbeat.py >> /pentest/logs/heartbeat.log 2>&1",
        f"",
        f"# Daily threat summary at {heartbeat_config.daily_summary_time}",
        f"{heartbeat_config.daily_summary_time.split(':')[0]} {heartbeat_config.daily_summary_time.split(':')[1]} * * * cd /pentest && python3 -c 'from heartbeat import HeartbeatSystem; import asyncio; asyncio.run(HeartbeatSystem()._generate_daily_summary())' >> /pentest/logs/heartbeat.log 2>&1",
        f"",
        f"# CVE check every {heartbeat_config.cve_check_interval_hours} hours",
        f"0 */{heartbeat_config.cve_check_interval_hours} * * * cd /pentest && python3 -c 'from heartbeat import HeartbeatSystem; import asyncio; asyncio.run(HeartbeatSystem()._check_cves())' >> /pentest/logs/heartbeat.log 2>&1"
    ]
    
    return '\n'.join(cron_entries)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--cron":
        # Generate cron configuration
        config = HeartbeatConfig()
        print(generate_cron_config(config))
    else:
        # Run heartbeat system
        async def run_heartbeat():
            config = HeartbeatConfig()
            config.notification_channels = ["log"]
            config.scan_networks = ["192.168.1.0/24"]  # Example network
            
            heartbeat = HeartbeatSystem(config)
            await heartbeat.start()
        
        asyncio.run(run_heartbeat())
