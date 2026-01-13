#!/usr/bin/env python3
"""
Comprehensive Exploitation Report Generator
Extracts and structures ALL obtained data from pentest
"""

import json
import re
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from datetime import datetime

@dataclass
class Vulnerability:
    """Represents an exploited vulnerability"""
    type: str  # SQLi, RCE, LFI, etc.
    service: str
    endpoint: str
    payload: str
    impact: str
    evidence: str

@dataclass
class Credential:
    """Represents obtained credentials"""
    username: str
    password: str
    service: str
    source: str  # config file, database, brute force, etc.
    access_level: str

@dataclass
class DatabaseAccess:
    """Represents database access and dumps"""
    db_type: str  # MySQL, PostgreSQL, MongoDB
    host: str
    credentials: str
    databases: List[str]
    tables_dumped: List[str]
    records_count: int
    sensitive_data: List[str]

@dataclass
class ShellAccess:
    """Represents shell/RCE access"""
    type: str  # webshell, reverse shell, SSH
    host: str
    user: str
    method: str
    persistence: bool

@dataclass
class LateralMovement:
    """Represents lateral movement between hosts"""
    from_host: str
    to_host: str
    method: str
    credentials_used: str
    services_accessed: List[str]

@dataclass
class DataExfiltration:
    """Represents exfiltrated data"""
    type: str  # database dump, config files, /etc/passwd, etc.
    source: str
    size: str
    location: str
    content_preview: str

class ComprehensiveReport:
    """Generate detailed exploitation report"""
    
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.credentials: List[Credential] = []
        self.database_access: List[DatabaseAccess] = []
        self.shell_access: List[ShellAccess] = []
        self.lateral_movement: List[LateralMovement] = []
        self.data_exfiltration: List[DataExfiltration] = []
        
    def parse_executions(self, executions: List[Dict]):
        """Parse execution logs to extract exploitation data"""
        
        for exec in executions:
            content = exec.get('content', '')
            stdout = exec.get('stdout', '')
            stderr = exec.get('stderr', '')
            combined = f"{content}\n{stdout}\n{stderr}".lower()
            
            # Detect SQLi exploitation
            if 'sqlmap' in content and exec.get('success'):
                self._extract_sqli(content, stdout)
            
            # Detect database access
            if any(db in content for db in ['mysql', 'psql', 'mongo', 'redis-cli']):
                self._extract_database_access(content, stdout)
            
            # Detect credentials
            if any(pattern in combined for pattern in ['password:', 'user:', 'username:', 'login:']):
                self._extract_credentials(content, stdout)
            
            # Detect shell access
            if any(cmd in content for cmd in ['nc -e', 'bash -i', 'php -r', 'python -c']):
                self._extract_shell_access(content, stdout)
            
            # Detect file access
            if any(cmd in content for cmd in ['cat /etc/', 'cat /var/', 'find /', 'grep -r']):
                self._extract_file_access(content, stdout)
            
            # Detect lateral movement
            if any(cmd in content for cmd in ['ssh ', 'smbclient', 'psexec', 'wmiexec']):
                self._extract_lateral_movement(content, stdout)
    
    def _extract_sqli(self, content: str, stdout: str):
        """Extract SQLi vulnerability details"""
        # Parse sqlmap output
        if 'parameter' in stdout.lower() and 'vulnerable' in stdout.lower():
            # Extract parameter name
            param_match = re.search(r"Parameter: (\w+)", stdout)
            param = param_match.group(1) if param_match else "unknown"
            
            # Extract URL
            url_match = re.search(r"-u [\"']?([^\"'\s]+)", content)
            url = url_match.group(1) if url_match else "unknown"
            
            self.vulnerabilities.append(Vulnerability(
                type="SQL Injection",
                service=url.split('/')[2] if '/' in url else "unknown",
                endpoint=url,
                payload=f"Parameter: {param}",
                impact="Database access, data extraction",
                evidence=stdout[:500]
            ))
    
    def _extract_database_access(self, content: str, stdout: str):
        """Extract database access details"""
        db_type = None
        if 'mysql' in content:
            db_type = 'MySQL'
        elif 'psql' in content or 'postgres' in content:
            db_type = 'PostgreSQL'
        elif 'mongo' in content:
            db_type = 'MongoDB'
        
        if db_type and stdout:
            # Extract databases
            databases = re.findall(r"Database: (\w+)", stdout)
            tables = re.findall(r"Table: (\w+)", stdout)
            
            # Extract credentials from command
            cred_match = re.search(r"-u\s+(\w+)\s+-p['\"]?([^'\">\s]+)", content)
            creds = f"{cred_match.group(1)}:{cred_match.group(2)}" if cred_match else "unknown"
            
            # Extract host
            host_match = re.search(r"-h\s+([^\s]+)", content)
            host = host_match.group(1) if host_match else "localhost"
            
            # Check for sensitive data
            sensitive = []
            if any(word in stdout.lower() for word in ['password', 'credit', 'ssn', 'secret', 'token']):
                sensitive.append("Sensitive data found")
            
            self.database_access.append(DatabaseAccess(
                db_type=db_type,
                host=host,
                credentials=creds,
                databases=databases or ["unknown"],
                tables_dumped=tables or [],
                records_count=len(stdout.split('\n')),
                sensitive_data=sensitive
            ))
    
    def _extract_credentials(self, content: str, stdout: str):
        """Extract credentials from output"""
        # Pattern: username:password
        cred_pattern = r"(\w+):([^\s:]+)"
        matches = re.findall(cred_pattern, stdout)
        
        # Also extract from grep/config patterns
        config_patterns = [
            r"password['\"]?\s*[:=]\s*['\"]?([^'\">\s]+)",
            r"user['\"]?\s*[:=]\s*['\"]?(\w+)",
            r"MYSQL_ROOT_PASSWORD['\"]?\s*[:=]\s*['\"]?([^'\">\s]+)",
            r"DB_PASSWORD['\"]?\s*[:=]\s*['\"]?([^'\">\s]+)"
        ]
        
        for pattern in config_patterns:
            config_matches = re.findall(pattern, stdout + content, re.IGNORECASE)
            for match in config_matches:
                if len(match) > 2:
                    self.credentials.append(Credential(
                        username="extracted",
                        password=match,
                        service="config file",
                        source=content[:100],
                        access_level="unknown"
                    ))
        
        for username, password in matches:
            if len(password) > 3 and password not in ['root', 'bin', 'daemon']:
                self.credentials.append(Credential(
                    username=username,
                    password=password,
                    service="extracted from output",
                    source=content[:100],
                    access_level="unknown"
                ))
    
    def _extract_shell_access(self, content: str, stdout: str):
        """Extract shell access details"""
        shell_type = "unknown"
        if 'nc -e' in content or 'bash -i' in content:
            shell_type = "reverse shell"
        elif '.php' in content and 'system' in content:
            shell_type = "webshell"
        elif 'ssh' in content:
            shell_type = "SSH"
        
        if shell_type != "unknown":
            self.shell_access.append(ShellAccess(
                type=shell_type,
                host="target",
                user="unknown",
                method=content[:200],
                persistence=False
            ))
    
    def _extract_file_access(self, content: str, stdout: str):
        """Extract file access and exfiltration"""
        if stdout and len(stdout) > 50:
            file_type = "unknown"
            if '/etc/passwd' in content:
                file_type = "System users (/etc/passwd)"
            elif '/etc/shadow' in content:
                file_type = "Password hashes (/etc/shadow)"
            elif 'config' in content.lower():
                file_type = "Configuration files"
            
            self.data_exfiltration.append(DataExfiltration(
                type=file_type,
                source=content[:100],
                size=f"{len(stdout)} bytes",
                location="/tmp/extracted",
                content_preview=stdout[:300]
            ))
    
    def _extract_lateral_movement(self, content: str, stdout: str):
        """Extract lateral movement details"""
        if 'ssh' in content and '@' in content:
            # Extract user@host
            match = re.search(r"(\w+)@([\d\.]+)", content)
            if match:
                self.lateral_movement.append(LateralMovement(
                    from_host="attacker",
                    to_host=match.group(2),
                    method="SSH",
                    credentials_used=match.group(1),
                    services_accessed=["SSH"]
                ))
    
    def generate_markdown_report(self) -> str:
        """Generate comprehensive markdown report"""
        report = []
        report.append("# 🎯 NeuroSploit Comprehensive Exploitation Report")
        report.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Executive Summary
        report.append("## 📊 Executive Summary\n")
        report.append(f"- **Vulnerabilities Exploited:** {len(self.vulnerabilities)}")
        report.append(f"- **Credentials Obtained:** {len(self.credentials)}")
        report.append(f"- **Database Access:** {len(self.database_access)}")
        report.append(f"- **Shell Access:** {len(self.shell_access)}")
        report.append(f"- **Lateral Movement:** {len(self.lateral_movement)}")
        report.append(f"- **Data Exfiltrated:** {len(self.data_exfiltration)}\n")
        
        # Vulnerabilities
        if self.vulnerabilities:
            report.append("## 🔓 Exploited Vulnerabilities\n")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report.append(f"### {i}. {vuln.type}")
                report.append(f"- **Service:** {vuln.service}")
                report.append(f"- **Endpoint:** `{vuln.endpoint}`")
                report.append(f"- **Payload:** `{vuln.payload}`")
                report.append(f"- **Impact:** {vuln.impact}")
                report.append(f"- **Evidence:**\n```\n{vuln.evidence[:200]}\n```\n")
        
        # Credentials
        if self.credentials:
            report.append("## 🔑 Obtained Credentials\n")
            report.append("| Username | Password | Service | Source |")
            report.append("|----------|----------|---------|--------|")
            for cred in self.credentials:
                report.append(f"| {cred.username} | {cred.password} | {cred.service} | {cred.source[:50]} |")
            report.append("")
        
        # Database Access
        if self.database_access:
            report.append("## 💾 Database Access\n")
            for i, db in enumerate(self.database_access, 1):
                report.append(f"### {i}. {db.db_type} @ {db.host}")
                report.append(f"- **Credentials:** `{db.credentials}`")
                report.append(f"- **Databases:** {', '.join(db.databases)}")
                report.append(f"- **Tables Dumped:** {len(db.tables_dumped)}")
                report.append(f"- **Records:** ~{db.records_count}")
                if db.sensitive_data:
                    report.append(f"- **⚠️ Sensitive Data:** {', '.join(db.sensitive_data)}")
                report.append("")
        
        # Shell Access
        if self.shell_access:
            report.append("## 🐚 Shell Access\n")
            for i, shell in enumerate(self.shell_access, 1):
                report.append(f"### {i}. {shell.type}")
                report.append(f"- **Host:** {shell.host}")
                report.append(f"- **User:** {shell.user}")
                report.append(f"- **Method:** `{shell.method[:100]}`")
                report.append(f"- **Persistent:** {'Yes' if shell.persistence else 'No'}\n")
        
        # Lateral Movement
        if self.lateral_movement:
            report.append("## 🔀 Lateral Movement\n")
            for i, move in enumerate(self.lateral_movement, 1):
                report.append(f"### {i}. {move.from_host} → {move.to_host}")
                report.append(f"- **Method:** {move.method}")
                report.append(f"- **Credentials:** {move.credentials_used}")
                report.append(f"- **Services:** {', '.join(move.services_accessed)}\n")
        
        # Data Exfiltration
        if self.data_exfiltration:
            report.append("## 📦 Data Exfiltration\n")
            for i, data in enumerate(self.data_exfiltration, 1):
                report.append(f"### {i}. {data.type}")
                report.append(f"- **Source:** `{data.source[:80]}`")
                report.append(f"- **Size:** {data.size}")
                report.append(f"- **Preview:**\n```\n{data.content_preview}\n```\n")
        
        return "\n".join(report)
    
    def generate_json_report(self) -> Dict:
        """Generate JSON report"""
        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "vulnerabilities": len(self.vulnerabilities),
                "credentials": len(self.credentials),
                "database_access": len(self.database_access),
                "shell_access": len(self.shell_access),
                "lateral_movement": len(self.lateral_movement),
                "data_exfiltration": len(self.data_exfiltration)
            },
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "credentials": [asdict(c) for c in self.credentials],
            "database_access": [asdict(d) for d in self.database_access],
            "shell_access": [asdict(s) for s in self.shell_access],
            "lateral_movement": [asdict(l) for l in self.lateral_movement],
            "data_exfiltration": [asdict(d) for d in self.data_exfiltration]
        }
