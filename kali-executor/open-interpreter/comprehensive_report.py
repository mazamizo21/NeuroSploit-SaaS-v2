#!/usr/bin/env python3
"""
Comprehensive Exploitation Report Generator v2
Extracts, deduplicates, and enriches ALL obtained data from pentest.
Each finding includes the exact extraction method/command for traceability.
"""

import json
import os
import re
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime
from html import escape as html_escape


@dataclass
class Vulnerability:
    """Represents an exploited vulnerability"""
    type: str  # SQLi, RCE, LFI, etc.
    service: str
    endpoint: str
    payload: str
    impact: str
    evidence: str
    extraction_command: str = ""  # The exact command that found this
    iteration: int = 0           # Which iteration discovered it
    mitre_id: str = ""           # MITRE ATT&CK technique ID


@dataclass
class Credential:
    """Represents obtained credentials"""
    username: str
    password: str
    service: str
    source: str                    # config file, database, brute force, etc.
    access_level: str
    extraction_command: str = ""   # The exact command that extracted this
    extraction_method: str = ""    # Human-readable method description
    iteration: int = 0            # Which iteration discovered it
    verified: bool = False        # Was the credential tested/verified?


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
    extraction_command: str = ""
    iteration: int = 0


@dataclass
class ShellAccess:
    """Represents shell/RCE access"""
    type: str  # webshell, reverse shell, SSH
    host: str
    user: str
    method: str
    persistence: bool
    extraction_command: str = ""
    iteration: int = 0


@dataclass
class LateralMovement:
    """Represents lateral movement between hosts"""
    from_host: str
    to_host: str
    method: str
    credentials_used: str
    services_accessed: List[str]
    extraction_command: str = ""
    iteration: int = 0


@dataclass
class DataExfiltration:
    """Represents exfiltrated data"""
    type: str  # database dump, config files, /etc/passwd, etc.
    source: str
    size: str
    location: str
    content_preview: str
    extraction_command: str = ""
    iteration: int = 0


@dataclass
class AttackChain:
    """Groups related findings into an attack narrative"""
    chain_id: str
    title: str
    steps: List[Dict]  # Ordered list of findings that form the chain
    severity: str
    summary: str


class ComprehensiveReport:
    """Generate detailed exploitation report with dedup and enrichment"""
    
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.credentials: List[Credential] = []
        self.database_access: List[DatabaseAccess] = []
        self.shell_access: List[ShellAccess] = []
        self.lateral_movement: List[LateralMovement] = []
        self.data_exfiltration: List[DataExfiltration] = []
        self.attack_chains: List[AttackChain] = []
        self.security_controls: List[Dict[str, Any]] = []
        # Dedup sets — track what we've already seen
        self._seen_creds: set = set()       # hash(user+pass+service)
        self._seen_userpass: set = set()    # hash(user+pass) (strong dedup across services)
        self._seen_vulns: set = set()       # hash(type+endpoint)
        self._seen_db: set = set()          # hash(type+host+creds)
        self._seen_shells: set = set()      # hash(type+host+method)
        self._seen_files: set = set()       # hash(type+source)
        self._executed_commands: set = set()
        self.strict_evidence_only: bool = str(
            (os.getenv("STRICT_EVIDENCE_ONLY", "false") or "false")
        ).lower() in ("1", "true", "yes")
        self.metadata: Dict[str, Any] = {}

    def _has_exec_cmd(self, cmd: str) -> bool:
        if not cmd:
            return False
        return cmd.strip() in self._executed_commands

    def _is_vuln_proven(self, vuln: Vulnerability) -> bool:
        if not vuln:
            return False
        if not vuln.type or vuln.type.lower() == "unknown":
            return False
        if not vuln.endpoint or vuln.endpoint.lower() == "unknown":
            return False
        if not vuln.evidence or self._is_junk(vuln.evidence):
            return False
        if not vuln.extraction_command:
            return False
        if not self._has_exec_cmd(vuln.extraction_command):
            return False
        return True

    def _is_access_proven(self, cmd: str, evidence: str) -> bool:
        if not cmd or not evidence:
            return False
        if self._is_junk(evidence):
            return False
        return self._has_exec_cmd(cmd)

    def load_security_controls_file(self, path: str, max_events: int = 200) -> None:
        """Load security-control trigger evidence produced by the agent (jsonl)."""
        if not path:
            return
        try:
            with open(path, "r") as f:
                lines = [ln.strip() for ln in f.readlines() if ln.strip()]
        except Exception:
            return
        events: List[Dict[str, Any]] = []
        for ln in lines[-max_events:]:
            try:
                obj = json.loads(ln)
                if isinstance(obj, dict):
                    events.append(obj)
            except Exception:
                continue
        self.security_controls = events

    def _cred_key(self, username: str, password: str, service: str) -> str:
        return hashlib.md5(f"{username}:{password}:{service}".lower().encode()).hexdigest()

    def _userpass_key(self, username: str, password: str) -> str:
        return hashlib.md5(f"{username}:{password}".lower().encode()).hexdigest()
    
    def _vuln_key(self, vuln_type: str, endpoint: str) -> str:
        return hashlib.md5(f"{vuln_type}:{endpoint}".lower().encode()).hexdigest()
    
    def _db_key(self, db_type: str, host: str, creds: str) -> str:
        return hashlib.md5(f"{db_type}:{host}:{creds}".lower().encode()).hexdigest()
    
    def _is_junk(self, text: str) -> bool:
        """Detect HTML/XML junk that regex might accidentally match"""
        junk_indicators = ['<em', '//www.', '.dtd', '.org/', '.com/', 'github',
                           '<!doctype', '<html', 'xmlns', 'charset=', 'viewport']
        return any(j in text.lower() for j in junk_indicators)

    def _looks_like_ip(self, text: str) -> bool:
        if not text:
            return False
        return bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', text.strip()))

    def _is_cred_placeholder(self, text: str) -> bool:
        """Filter common placeholder tokens that show up in logs/reports."""
        if not text:
            return True
        t = text.strip().lower()
        bad = {
            "unknown", "extracted", "email", "user", "username", "password",
            "found", "discovered", "obtained", "dumped", "tables", "table",
            "records", "record", "data", "jwt", "token",
            # Common false positives from LLM output / arsenal parsing
            "evidence", "proof", "cat", "prefix", "dump", "passwords",
            "assignment", "id", "access", "output", "result", "response",
            "admin", "test", "true", "false", "null", "none", "undefined",
            "credential", "credentials", "finding", "findings", "vuln",
            "vulnerability", "exploit", "shell", "command", "query",
            "select", "insert", "update", "delete", "from", "where",
            "curl", "wget", "echo", "grep", "awk", "sed", "type",
            "hash", "key", "value", "string", "object", "array",
            "iteration", "target", "service", "source", "method",
        }
        if t in bad:
            return True
        if t.isdigit():
            return True
        if self._looks_like_ip(t):
            return True
        # Single common words (< 4 chars, not email-like)
        if len(t) <= 2 and "@" not in t:
            return True
        return False

    def _is_password_plausible(self, password: str) -> bool:
        if not password:
            return False
        p = password.strip()
        if len(p) < 2:
            return False
        if self._is_junk(p):
            return False
        # Reject "passwords" that are clearly ports when paired with an IP/host token.
        if p.isdigit() and 1 <= len(p) <= 5:
            return False
        return True

    def _is_username_plausible(self, username: str) -> bool:
        if not username:
            return False
        u = username.strip()
        if len(u) < 2:
            return False
        if self._is_junk(u) or self._is_cred_placeholder(u):
            return False
        # Avoid treating host:port as a username.
        if ":" in u and any(part.isdigit() for part in u.split(":")[1:]):
            return False
        # Heuristic: real usernames look like identifiers (emails, handles, service accounts)
        # NOT like random English words from LLM output parsing
        # Valid: admin@example.com, test_user1, john.doe, root
        # Invalid: Evidence, proof, dump, assignment, passwords
        has_identifier_chars = "@" in u or "." in u or "_" in u or "-" in u
        has_digits = any(c.isdigit() for c in u)
        if not has_identifier_chars and not has_digits and u.isalpha():
            # Pure alpha string — only allow known service account names
            typical_usernames = {
                "root", "admin", "postgres", "mysql", "redis", "www",
                "apache", "nginx", "ubuntu", "centos", "guest", "ftp",
                "ssh", "git", "jenkins", "tomcat", "oracle", "sa",
                "nobody", "daemon", "bin", "sys", "sync", "backup",
                # Note: app-specific default users should be discovered dynamically
            }
            if u.lower() not in typical_usernames:
                return False
        return True

    @staticmethod
    def _strip_llm_reasoning(text: str) -> str:
        """Strip LLM internal monologue/reasoning from text, keeping only factual content.
        
        Removes patterns like:
        - "Wait, the user *provided* that output..."
        - "Okay, so I have two things happening..."
        - "Let me think about this..."
        """
        if not text:
            return ""
        
        # First pass: strip reasoning PREFIXES from text (even within single lines)
        prefix_patterns = [
            re.compile(r"(?i)^(?:wait|okay|ok|so|let me|hmm|alright|right|now|well|actually|thinking)[,.]?\s+.*?[.!?]\s+", re.DOTALL),
            re.compile(r"(?i)^(?:I (?:need to|should|will|can|have to|notice|see|think|found|believe|realize))\s+.*?[.!?]\s+", re.DOTALL),
            re.compile(r"(?i)^the user (?:\*?provided\*?|asked|wants|said)\s+.*?[.!?]\s+", re.DOTALL),
        ]
        
        result = text
        for pattern in prefix_patterns:
            for _ in range(3):
                match = pattern.match(result)
                if match:
                    remainder = result[match.end():].strip()
                    if remainder and len(remainder) >= 10:
                        result = remainder
                    else:
                        break
                else:
                    break
        
        # Remove italicized internal thoughts
        result = re.sub(r'\*[^*]{3,}\*', '', result).strip()
        
        # Multi-line: remove lines that are purely reasoning
        line_reasoning_patterns = [
            re.compile(r"(?i)^(?:wait|okay|ok|so|let me|hmm|alright|right|now|well|actually|thinking)[,.]?\s+"),
            re.compile(r"(?i)^(?:I (?:need to|should|will|can|have to|notice|see|think|found|believe|realize))\s+"),
            re.compile(r"(?i)^the user (?:\*?provided\*?|asked|wants|said)\s+"),
        ]
        
        if '\n' in result:
            lines = result.split('\n')
            clean_lines = []
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                is_pure_reasoning = False
                for pattern in line_reasoning_patterns:
                    if pattern.match(stripped):
                        cleaned = pattern.sub('', stripped).strip()
                        if not cleaned or len(cleaned) < 10:
                            is_pure_reasoning = True
                            break
                if not is_pure_reasoning:
                    clean_lines.append(stripped)
            if clean_lines:
                result = '\n'.join(clean_lines)
        
        return result.strip() if result.strip() else text.strip()

    def _is_local_artifact_command(self, command: str) -> bool:
        """Detect commands that only enumerate local artifacts, not target data."""
        if not command:
            return False
        cmd = command.lower()
        local_markers = [
            "/pentest/output",
            "/pentest/logs",
            "/pentest/memory",
            "/pentest/artifacts",
            "/root/.local/share/sqlmap",
            "/root/.cache",
        ]
        return any(marker in cmd for marker in local_markers)
    
    # ── Memory-based extraction (primary source) ──────────────────────
    
    def parse_memories(self, memories: List[Any]):
        """
        Parse the agent's memory store entries for findings.
        This is the PRIMARY source — the agent tags discoveries with
        [REMEMBER: category] and the memory system stores them.
        """
        if self.strict_evidence_only:
            return
        for mem in memories:
            if hasattr(mem, 'category'):
                category = mem.category
                content = mem.content
                context = mem.context if hasattr(mem, 'context') else {}
            elif isinstance(mem, dict):
                category = mem.get('category', '')
                content = mem.get('content', '')
                context = mem.get('context', {})
            else:
                continue
            
            if category == 'credential_found':
                self._extract_credential_from_memory(content, context)
            elif category == 'vulnerability_found':
                self._extract_vulnerability_from_memory(content, context)
            elif category == 'access_gained':
                self._extract_access_from_memory(content, context)
            elif category == 'target_info':
                self._extract_target_info_from_memory(content, context)
            elif category == 'technique_worked':
                self._extract_technique_from_memory(content, context)
    
    def _extract_credential_from_memory(self, content: str, context: dict):
        """Extract credential details from a memory entry"""
        username = "unknown"
        password = "unknown"
        service = "unknown"

        # Prefer email/username patterns over generic token extraction.
        # Examples: "admin@example.com / secret", "user:pass"
        email_match = re.search(
            r'([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*(?:/|:)\s*([^\s,;]+)',
            content,
        )
        if email_match:
            username = email_match.group(1)
            password = email_match.group(2)
        else:
            # Explicit user/pass fields if present.
            u_match = re.search(r'\b(?:user|username|email)\s*[:=]\s*["\']?([^\s,"\']+)["\']?', content, re.IGNORECASE)
            p_match = re.search(r'\b(?:pass|password)\s*[:=]\s*["\']?([^\s,"\']+)["\']?', content, re.IGNORECASE)
            if u_match and p_match:
                username = u_match.group(1)
                password = p_match.group(1)
            else:
                # Fallback: basic "user:pass" / "user/pass".
                cred_match = re.search(r'(\w[\w.-]*)\s*[:\/]\s*(\S+)', content)
                if cred_match:
                    username = cred_match.group(1)
                    password = cred_match.group(2)
        
        service_keywords = {
            'mysql': 'MySQL', 'database': 'Database', 'db': 'Database',
            'ssh': 'SSH', 'ftp': 'FTP', 'http': 'HTTP', 'web': 'Web',
            'admin': 'Admin Panel', 'postgres': 'PostgreSQL',
            'redis': 'Redis', 'mongo': 'MongoDB', 'login': 'Login'
        }
        content_lower = content.lower()
        for kw, svc in service_keywords.items():
            if kw in content_lower:
                service = svc
                break
        
        if username in ('unknown', 'http', 'https', 'the', 'and', 'for'):
            return
        # Reject bogus username/password pairs (common false positives: IP:port, "email: extracted", etc.)
        if not self._is_username_plausible(username):
            return
        if not self._is_password_plausible(password):
            return

        # Strong dedup across services (avoid same cred 5x with different "service" labels).
        up_key = self._userpass_key(username, password)
        if up_key in self._seen_userpass:
            return
        self._seen_userpass.add(up_key)

        key = self._cred_key(username, password, service)
        if key in self._seen_creds:
            return
        self._seen_creds.add(key)
        
        # Try to extract the command from context
        extraction_cmd = context.get('command', '') or context.get('extraction_command', '')
        iteration = context.get('iteration', 0)
        
        self.credentials.append(Credential(
            username=username,
            password=password,
            service=service,
            source=f"Agent memory: {content[:100]}",
            access_level="unknown",
            extraction_command=extraction_cmd,
            extraction_method=self._classify_extraction_method(content, extraction_cmd),
            iteration=iteration,
        ))
    
    def _classify_extraction_method(self, content: str, command: str) -> str:
        """Classify HOW a credential was obtained for human-readable display"""
        text = f"{content} {command}".lower()
        
        if 'config' in text or '.inc' in text or '.conf' in text or '.env' in text:
            return "Configuration File Disclosure"
        elif 'sqlmap' in text or 'sql injection' in text or 'sqli' in text:
            return "SQL Injection → Database Dump"
        elif 'hydra' in text or 'brute' in text or 'medusa' in text or 'patator' in text:
            return "Brute Force Attack"
        elif '/etc/shadow' in text or '/etc/passwd' in text:
            return "System File Access"
        elif 'curl' in text and ('config' in text or 'setup' in text):
            return "Web Configuration File Access"
        elif 'phpmyadmin' in text:
            return "phpMyAdmin Access"
        elif 'default' in text:
            return "Default Credentials"
        elif 'dump' in text:
            return "Database Dump"
        elif 'grep' in text or 'cat' in text or 'find' in text:
            return "File System Enumeration"
        return "Extracted During Reconnaissance"
    
    def _extract_vulnerability_from_memory(self, content: str, context: dict):
        """Extract vulnerability details from a memory entry"""
        vuln_type = "Unknown"
        severity = "medium"
        mitre_id = ""
        
        vuln_patterns = {
            'sql injection': ('SQL Injection', 'high'),
            'sqli': ('SQL Injection', 'high'),
            'xss': ('Cross-Site Scripting', 'medium'),
            'cross-site scripting': ('Cross-Site Scripting', 'medium'),
            'rfi': ('Remote File Inclusion', 'critical'),
            'remote file inclusion': ('Remote File Inclusion', 'critical'),
            'lfi': ('Local File Inclusion', 'high'),
            'local file inclusion': ('Local File Inclusion', 'high'),
            'command injection': ('Command Injection', 'critical'),
            'rce': ('Remote Code Execution', 'critical'),
            'file upload': ('File Upload', 'high'),
            'csrf': ('Cross-Site Request Forgery', 'medium'),
            'ssrf': ('Server-Side Request Forgery', 'high'),
            'xxe': ('XML External Entity', 'high'),
            'directory traversal': ('Directory Traversal', 'high'),
            'url include': ('Remote File Inclusion', 'critical'),
            'url fopen': ('Remote File Inclusion', 'critical'),
            'open redirect': ('Open Redirect', 'low'),
            'information disclosure': ('Information Disclosure', 'low'),
            'default credentials': ('Default Credentials', 'high'),
            'weak password': ('Weak Password', 'medium'),
            'idor': ('Insecure Direct Object Reference', 'high'),
            'insecure direct object': ('Insecure Direct Object Reference', 'high'),
            'broken access control': ('Broken Access Control', 'high'),
            'mass assignment': ('Mass Assignment', 'high'),
            'path traversal': ('Path Traversal', 'high'),
            'directory traversal': ('Directory Traversal', 'high'),
        }
        
        content_lower = content.lower()
        for pattern, (vtype, sev) in vuln_patterns.items():
            if pattern in content_lower:
                vuln_type = vtype
                severity = sev
                break
        
        target = context.get('target', 'unknown')
        endpoint = context.get('endpoint', target)
        
        key = self._vuln_key(vuln_type, endpoint)
        if key in self._seen_vulns:
            return
        self._seen_vulns.add(key)
        
        extraction_cmd = context.get('command', '') or context.get('extraction_command', '')
        # MITRE ATT&CK technique ID (Txxxx) if provided in memory content/context
        if context:
            mitre_id = context.get('mitre_id', '') or context.get('mitre', '') or ""
        if not mitre_id:
            mitre_match = re.search(r"\bT\d{4}\b", content)
            if mitre_match:
                mitre_id = mitre_match.group(0)
        
        # Strip LLM reasoning/internal monologue from evidence to keep only factual content
        clean_evidence = self._strip_llm_reasoning(content[:500])
        
        self.vulnerabilities.append(Vulnerability(
            type=vuln_type,
            service=target,
            endpoint=endpoint,
            payload="See evidence",
            impact=f"{severity} severity - {vuln_type}",
            evidence=clean_evidence,
            extraction_command=extraction_cmd,
            iteration=context.get('iteration', 0),
            mitre_id=mitre_id,
        ))
    
    def _extract_access_from_memory(self, content: str, context: dict):
        content_lower = content.lower()
        extraction_cmd = context.get('command', '')
        
        if any(kw in content_lower for kw in ['shell', 'rce', 'command execution', 'reverse shell']):
            method_str = content[:200]
            key = hashlib.md5(f"shell:{method_str}".encode()).hexdigest()
            if key not in self._seen_shells:
                self._seen_shells.add(key)
                self.shell_access.append(ShellAccess(
                    type="command execution",
                    host=context.get('target', 'unknown'),
                    user="unknown",
                    method=method_str,
                    persistence=False,
                    extraction_command=extraction_cmd,
                    iteration=context.get('iteration', 0),
                ))
        
        if any(kw in content_lower for kw in ['database', 'mysql', 'postgres', 'db access']):
            db_type = "MySQL" if 'mysql' in content_lower else "PostgreSQL" if 'postgres' in content_lower else "Unknown"
            host = context.get('target', 'unknown')
            key = self._db_key(db_type, host, "from memory")
            if key not in self._seen_db:
                self._seen_db.add(key)
                self.database_access.append(DatabaseAccess(
                    db_type=db_type,
                    host=host,
                    credentials="from memory",
                    databases=["unknown"],
                    tables_dumped=[],
                    records_count=0,
                    sensitive_data=[content[:200]],
                    extraction_command=extraction_cmd,
                    iteration=context.get('iteration', 0),
                ))
    
    def _extract_target_info_from_memory(self, content: str, context: dict):
        pass  # Reserved for future enrichment
    
    def _extract_technique_from_memory(self, content: str, context: dict):
        content_lower = content.lower()
        if any(kw in content_lower for kw in ['exploit', 'inject', 'bypass', 'dump', 'extract']):
            self._extract_vulnerability_from_memory(content, context)
    
    # ── Conversation-based extraction (secondary) ─────────────────────
    
    def parse_conversation(self, conversation: List[Dict]):
        """Parse the AI conversation for findings the agent mentioned but didn't [REMEMBER]."""
        if self.strict_evidence_only:
            return
        for msg in conversation:
            if msg.get("role") != "assistant":
                continue
            content = msg.get("content", "")
            
            cred_patterns = [
                r'(?:found|discovered|obtained|extracted)\s+(?:credentials?|password|login).*?(\w+)\s*[:\/]\s*(\S+)',
                r'(?:username|user)\s*[:=]\s*["\']?(\w+)["\']?\s*(?:and\s+)?(?:password|pass)\s*[:=]\s*["\']?(\S+?)["\']?(?:\s|$|,)',
                r'credentials?\s+(?:are|is)\s+(\w+)\s*[:\/]\s*(\S+)',
            ]
            
            for pattern in cred_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for username, password in matches:
                    if len(password) > 2 and username not in ('the', 'a', 'an', 'http', 'https'):
                        if not self._is_username_plausible(username) or not self._is_password_plausible(password):
                            continue
                        up_key = self._userpass_key(username, password)
                        if up_key in self._seen_userpass:
                            continue
                        self._seen_userpass.add(up_key)
                        key = self._cred_key(username, password, "conversation")
                        if key not in self._seen_creds:
                            self._seen_creds.add(key)
                            self.credentials.append(Credential(
                                username=username,
                                password=password,
                                service="extracted from conversation",
                                source="AI conversation analysis",
                                access_level="unknown",
                                extraction_method="AI Conversation Analysis",
                            ))
    
    # ── Execution-based extraction (tertiary) ─────────────────────────
    
    def parse_executions(self, executions: List[Dict]):
        """Parse execution logs to extract exploitation data"""
        for i, ex in enumerate(executions):
            content = ex.get('content', '')
            stdout = ex.get('stdout', '')
            stderr = ex.get('stderr', '')
            iteration = ex.get('iteration', i + 1)
            combined = f"{content}\n{stdout}\n{stderr}".lower()

            if content:
                self._executed_commands.add(content.strip())

            if self.strict_evidence_only and self._is_local_artifact_command(content):
                continue
            
            if 'sqlmap' in content and ex.get('success'):
                self._extract_sqli(content, stdout, iteration)
            
            if any(db in content for db in ['mysql', 'psql', 'mongo', 'redis-cli']):
                self._extract_database_access(content, stdout, iteration)
            
            if any(pattern in combined for pattern in ['password:', 'user:', 'username:', 'login:']):
                self._extract_credentials(content, stdout, iteration)
            
            if any(cmd in content for cmd in ['nc -e', 'bash -i', 'php -r', 'python -c']):
                self._extract_shell_access(content, stdout, iteration)
            
            if any(cmd in content for cmd in ['cat /etc/', 'cat /var/', 'find /', 'grep -r']):
                self._extract_file_access(content, stdout, iteration)
            
            if any(cmd in content for cmd in ['ssh ', 'smbclient', 'psexec', 'wmiexec']):
                self._extract_lateral_movement(content, stdout, iteration)
    
    def _extract_sqli(self, content: str, stdout: str, iteration: int = 0):
        if 'parameter' in stdout.lower() and 'vulnerable' in stdout.lower():
            param_match = re.search(r"Parameter: (\w+)", stdout)
            param = param_match.group(1) if param_match else "unknown"
            
            url_match = re.search(r"-u [\"']?([^\"'\s]+)", content)
            url = url_match.group(1) if url_match else "unknown"
            
            key = self._vuln_key("SQL Injection", url)
            if key in self._seen_vulns:
                return
            self._seen_vulns.add(key)
            
            self.vulnerabilities.append(Vulnerability(
                type="SQL Injection",
                service=url.split('/')[2] if '/' in url else "unknown",
                endpoint=url,
                payload=f"Parameter: {param}",
                impact="Database access, data extraction",
                evidence=stdout[:500],
                extraction_command=content.strip(),
                iteration=iteration,
            ))
    
    def _extract_database_access(self, content: str, stdout: str, iteration: int = 0):
        db_type = None
        if 'mysql' in content:
            db_type = 'MySQL'
        elif 'psql' in content or 'postgres' in content:
            db_type = 'PostgreSQL'
        elif 'mongo' in content:
            db_type = 'MongoDB'
        
        if db_type and stdout:
            databases = re.findall(r"Database: (\w+)", stdout)
            tables = re.findall(r"Table: (\w+)", stdout)
            
            cred_match = re.search(r"-u\s+(\w+)\s+-p['\"]?([^'\">\s]+)", content)
            creds = f"{cred_match.group(1)}:{cred_match.group(2)}" if cred_match else "unknown"
            
            host_match = re.search(r"-h\s+([^\s]+)", content)
            host = host_match.group(1) if host_match else "localhost"
            
            key = self._db_key(db_type, host, creds)
            if key in self._seen_db:
                return
            self._seen_db.add(key)
            
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
                sensitive_data=sensitive,
                extraction_command=content.strip(),
                iteration=iteration,
            ))
    
    def _extract_credentials(self, content: str, stdout: str, iteration: int = 0):
        """Extract credentials from output — strict filtering, with extraction command tracking"""
        
        # Skip HTML junk entirely
        if '<html' in stdout.lower() or '<!doctype' in stdout.lower():
            return

        # JSON API responses: extract {email|username,password} pairs.
        try:
            s = (stdout or "").strip()
            if s.startswith("{") or s.startswith("["):
                obj = json.loads(s)

                def walk(o):
                    if isinstance(o, dict):
                        yield o
                        for v in o.values():
                            yield from walk(v)
                    elif isinstance(o, list):
                        for it in o:
                            yield from walk(it)

                for d in walk(obj):
                    if not isinstance(d, dict):
                        continue
                    user = d.get("email") or d.get("username")
                    pwd = d.get("password")
                    if not user or pwd is None:
                        continue
                    user = str(user).strip()
                    pwd = str(pwd).strip()
                    if not self._is_username_plausible(user) or not self._is_password_plausible(pwd):
                        continue
                    up_key = self._userpass_key(user, pwd)
                    if up_key in self._seen_userpass:
                        continue
                    self._seen_userpass.add(up_key)
                    key = self._cred_key(user, pwd, "HTTP")
                    if key in self._seen_creds:
                        continue
                    self._seen_creds.add(key)
                    self.credentials.append(Credential(
                        username=user,
                        password=pwd,
                        service="HTTP",
                        source=f"API response: {content[:80]}",
                        access_level="hash" if re.fullmatch(r"[a-f0-9]{32,128}", pwd.lower()) else "unknown",
                        extraction_command=content.strip(),
                        extraction_method="API Response Parsing",
                        iteration=iteration,
                    ))
        except Exception:
            pass
        
        # Config-file patterns (high confidence)
        config_patterns = [
            (r"MYSQL_ROOT_PASSWORD['\"]?\s*[:=]\s*['\"]?([^'\">\s]+)", "root", "MySQL"),
            (r"DB_PASSWORD['\"]?\s*[:=]\s*['\"]?([^'\">\s]+)", "db_user", "Database"),
            (r"DB_USER(?:NAME)?['\"]?\s*[:=]\s*['\"]?([^'\">\s]+)", None, None),  # username only
            (r"POSTGRES_PASSWORD['\"]?\s*[:=]\s*['\"]?([^'\">\s]+)", "postgres", "PostgreSQL"),
            (r"REDIS_PASSWORD['\"]?\s*[:=]\s*['\"]?([^'\">\s]+)", "redis", "Redis"),
            (r"\$db_password\s*=\s*['\"]([^'\"]+)", "db_user", "Database"),
            (r"\$db_user\s*=\s*['\"]([^'\"]+)", None, None),  # username extraction
        ]
        
        # First pass: extract usernames from config for pairing
        config_usernames = {}
        user_patterns = [
            r"DB_USER(?:NAME)?['\"]?\s*[:=]\s*['\"]?([^'\">\s]+)",
            r"\$db_user\s*=\s*['\"]([^'\"]+)['\"]",
            r"\$_?\w+\s*\[\s*['\"]db_user['\"]\s*\]\s*=\s*['\"]([^'\"]+)",
        ]
        for up in user_patterns:
            um = re.findall(up, stdout + content, re.IGNORECASE)
            for u in um:
                if len(u) > 1 and not self._is_junk(u):
                    config_usernames['db_user'] = u
        
        pass_patterns = [
            r"\$_?\w+\s*\[\s*['\"]db_password['\"]\s*\]\s*=\s*['\"]([^'\"]*)['\"]",
            r"\$db_password\s*=\s*['\"]([^'\"]*)['\"]",
        ]
        for pp in pass_patterns:
            pm = re.findall(pp, stdout + content, re.IGNORECASE)
            for p in pm:
                if not self._is_junk(p):
                    username = config_usernames.get('db_user', 'unknown')
                    if self._is_cred_placeholder(username):
                        username = "unknown"
                    key = self._cred_key(username, p, "config file")
                    if key not in self._seen_creds:
                        up_key = self._userpass_key(username, p)
                        if up_key in self._seen_userpass:
                            continue
                        self._seen_userpass.add(up_key)
                        self._seen_creds.add(key)
                        self.credentials.append(Credential(
                            username=username,
                            password=p,
                            service="Database (config file)",
                            source=f"Config file: {content[:80]}",
                            access_level="database",
                            extraction_command=content.strip(),
                            extraction_method="Configuration File Disclosure",
                            iteration=iteration,
                        ))
        
        for pattern, default_user, service in config_patterns:
            if service is None:
                continue  # Skip username-only patterns
            matches = re.findall(pattern, stdout + content, re.IGNORECASE)
            for match in matches:
                if len(match) > 2 and not self._is_junk(match):
                    username = config_usernames.get('db_user', default_user)
                    if self._is_cred_placeholder(username):
                        username = default_user or "unknown"
                    key = self._cred_key(username, match, service)
                    if key not in self._seen_creds:
                        up_key = self._userpass_key(username, match)
                        if up_key in self._seen_userpass:
                            continue
                        self._seen_userpass.add(up_key)
                        self._seen_creds.add(key)
                        self.credentials.append(Credential(
                            username=username,
                            password=match,
                            service=service,
                            source=f"Config file: {content[:80]}",
                            access_level="database" if 'db' in service.lower() else "unknown",
                            extraction_command=content.strip(),
                            extraction_method="Configuration File Disclosure",
                            iteration=iteration,
                        ))
        
        # Tool output patterns (hydra, medusa, sqlmap, etc.)
        tool_cred_patterns = [
            (r'\+\s*(\w+):(\S+)\s*$', "Brute Force Attack"),
            (r'password for (\w+) is (\S+)', "Password Cracking"),
            (r'login:\s*(\w+)\s+password:\s*(\S+)', "Brute Force Attack"),
            (r'\[.*?\]\[.*?\]\s+host:.*?login:\s*(\S+)\s+password:\s*(\S+)', "Brute Force Attack"),
        ]
        for pattern, method in tool_cred_patterns:
            matches = re.findall(pattern, stdout, re.MULTILINE | re.IGNORECASE)
            for username, password in matches:
                if len(password) > 2 and self._is_username_plausible(username) and self._is_password_plausible(password):
                    up_key = self._userpass_key(username, password)
                    if up_key in self._seen_userpass:
                        continue
                    self._seen_userpass.add(up_key)
                    key = self._cred_key(username, password, "brute force")
                    if key not in self._seen_creds:
                        self._seen_creds.add(key)
                        self.credentials.append(Credential(
                            username=username,
                            password=password,
                            service="Brute Force",
                            source=f"Tool output: {content[:80]}",
                            access_level="unknown",
                            extraction_command=content.strip(),
                            extraction_method=method,
                            iteration=iteration,
                        ))
    
    def _extract_shell_access(self, content: str, stdout: str, iteration: int = 0):
        shell_type = "unknown"
        if 'nc -e' in content or 'bash -i' in content:
            shell_type = "reverse shell"
        elif '.php' in content and 'system' in content:
            shell_type = "webshell"
        elif 'ssh' in content:
            shell_type = "SSH"
        
        if shell_type != "unknown":
            key = hashlib.md5(f"shell:{shell_type}:{content[:100]}".encode()).hexdigest()
            if key in self._seen_shells:
                return
            self._seen_shells.add(key)
            self.shell_access.append(ShellAccess(
                type=shell_type,
                host="target",
                user="unknown",
                method=content[:200],
                persistence=False,
                extraction_command=content.strip(),
                iteration=iteration,
            ))
    
    def _extract_file_access(self, content: str, stdout: str, iteration: int = 0):
        if stdout and len(stdout) > 50:
            # Skip local artifact enumeration (not target data)
            if self._is_local_artifact_command(content):
                return
            file_type = "unknown"
            if '/etc/passwd' in content:
                file_type = "System users (/etc/passwd)"
            elif '/etc/shadow' in content:
                file_type = "Password hashes (/etc/shadow)"
            elif 'config' in content.lower():
                file_type = "Configuration files"
            
            key = hashlib.md5(f"file:{file_type}:{content[:60]}".encode()).hexdigest()
            if key in self._seen_files:
                return
            self._seen_files.add(key)
            
            self.data_exfiltration.append(DataExfiltration(
                type=file_type,
                source=content[:100],
                size=f"{len(stdout)} bytes",
                location="/tmp/extracted",
                content_preview=stdout[:300],
                extraction_command=content.strip(),
                iteration=iteration,
            ))
    
    def _extract_lateral_movement(self, content: str, stdout: str, iteration: int = 0):
        if 'ssh' in content and '@' in content:
            match = re.search(r"(\w+)@([\d\.]+)", content)
            if match:
                self.lateral_movement.append(LateralMovement(
                    from_host="attacker",
                    to_host=match.group(2),
                    method="SSH",
                    credentials_used=match.group(1),
                    services_accessed=["SSH"],
                    extraction_command=content.strip(),
                    iteration=iteration,
                ))
    
    # ── Attack chain builder ──────────────────────────────────────────
    
    def build_attack_chains(self):
        """
        Group related findings into attack chains.
        e.g., Config File Disclosure → Credential Extraction → Database Access
        """
        chains = []
        
        # Chain: Config disclosure → creds → DB access
        config_creds = [c for c in self.credentials if 'config' in c.extraction_method.lower()]
        if config_creds and self.database_access:
            steps = []
            # Step 1: The vulnerability that exposed the config
            config_vulns = [v for v in self.vulnerabilities 
                           if v.type in ('Information Disclosure', 'Remote File Inclusion', 'Local File Inclusion')]
            if config_vulns:
                steps.append({"type": "vulnerability", "data": asdict(config_vulns[0]),
                              "description": f"Discovered {config_vulns[0].type} at {config_vulns[0].endpoint}"})
            
            # Step 2: Credential extraction
            for cred in config_creds:
                steps.append({"type": "credential", "data": asdict(cred),
                              "description": f"Extracted {cred.username}@{cred.service} via {cred.extraction_method}"})
            
            # Step 3: DB access
            for db in self.database_access:
                steps.append({"type": "database_access", "data": asdict(db),
                              "description": f"Accessed {db.db_type} at {db.host}"})
            
            if steps:
                chains.append(AttackChain(
                    chain_id="config-to-db",
                    title="Configuration Disclosure → Database Compromise",
                    steps=steps,
                    severity="critical",
                    summary=f"Configuration file exposed database credentials ({len(config_creds)} creds), "
                            f"leading to {len(self.database_access)} database(s) compromised."
                ))
        
        # Chain: Brute force → shell
        brute_creds = [c for c in self.credentials if 'brute' in c.extraction_method.lower()]
        if brute_creds and self.shell_access:
            steps = []
            for cred in brute_creds:
                steps.append({"type": "credential", "data": asdict(cred),
                              "description": f"Brute-forced {cred.username}@{cred.service}"})
            for shell in self.shell_access:
                steps.append({"type": "shell_access", "data": asdict(shell),
                              "description": f"Obtained {shell.type} on {shell.host}"})
            
            chains.append(AttackChain(
                chain_id="brute-to-shell",
                title="Brute Force → Shell Access",
                steps=steps,
                severity="critical",
                summary=f"Brute forced {len(brute_creds)} credential(s) leading to shell access."
            ))
        
        self.attack_chains = chains
    
    # ── Report generation ─────────────────────────────────────────────
    
    def generate_markdown_report(self) -> str:
        self.build_attack_chains()
        report = []
        report.append("# 🎯 TazoSploit Comprehensive Exploitation Report")
        report.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Executive Summary
        report.append("## 📊 Executive Summary\n")
        report.append(f"- **Vulnerabilities Exploited:** {len(self.vulnerabilities)}")
        report.append(f"- **Unique Credentials Obtained:** {len(self.credentials)}")
        report.append(f"- **Database Access:** {len(self.database_access)}")
        report.append(f"- **Shell Access:** {len(self.shell_access)}")
        report.append(f"- **Lateral Movement:** {len(self.lateral_movement)}")
        report.append(f"- **Data Exfiltrated:** {len(self.data_exfiltration)}")
        report.append(f"- **Attack Chains Identified:** {len(self.attack_chains)}\n")

        if self.security_controls:
            report.append("## 🛡️ Security Controls Observed (Evidence)\n")
            report.append("The following events indicate security controls blocking/throttling actions. This is observability, not evasion.\n")
            report.append("| # | Kind | Marker | Tool | Iteration | Snippet |")
            report.append("|---|------|--------|------|-----------|---------|")
            for i, ev in enumerate(self.security_controls[:50], 1):
                kind = ev.get("kind", "")
                marker = ev.get("marker", "")
                tool = ev.get("tool", "")
                it = ev.get("iteration", "")
                snip = (ev.get("output_snip", "") or "").replace("\n", " ")
                snip = (snip[:80] + "...") if len(snip) > 80 else snip
                report.append(f"| {i} | {kind} | {marker} | {tool} | {it} | `{snip}` |")
            report.append("")
        
        # Attack Chains (new!)
        if self.attack_chains:
            report.append("## ⛓️ Attack Chains\n")
            for chain in self.attack_chains:
                report.append(f"### {chain.title}")
                report.append(f"**Severity:** {chain.severity.upper()} | **Summary:** {chain.summary}\n")
                for j, step in enumerate(chain.steps, 1):
                    report.append(f"{j}. **[{step['type'].upper()}]** {step['description']}")
                report.append("")
        
        # Vulnerabilities
        if self.vulnerabilities:
            report.append("## 🔓 Exploited Vulnerabilities\n")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                report.append(f"### {i}. {vuln.type}")
                report.append(f"- **Service:** {vuln.service}")
                report.append(f"- **Endpoint:** `{vuln.endpoint}`")
                report.append(f"- **Payload:** `{vuln.payload}`")
                report.append(f"- **Impact:** {vuln.impact}")
                if vuln.extraction_command:
                    report.append(f"- **Command:** `{vuln.extraction_command[:200]}`")
                if vuln.iteration:
                    report.append(f"- **Discovered:** Iteration {vuln.iteration}")
                report.append(f"- **Evidence:**\n```\n{vuln.evidence[:200]}\n```\n")
        
        # Credentials
        if self.credentials:
            report.append("## 🔑 Obtained Credentials\n")
            report.append("| # | Username | Password | Service | Extraction Method | Command |")
            report.append("|---|----------|----------|---------|-------------------|---------|")
            for i, cred in enumerate(self.credentials, 1):
                cmd_short = cred.extraction_command[:60] + "..." if len(cred.extraction_command) > 60 else cred.extraction_command
                report.append(f"| {i} | {cred.username} | {cred.password} | {cred.service} | {cred.extraction_method} | `{cmd_short}` |")
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
                if db.extraction_command:
                    report.append(f"- **Command:** `{db.extraction_command[:200]}`")
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
                report.append(f"- **Command:** `{data.extraction_command[:200]}`" if data.extraction_command else f"- **Source:** `{data.source[:80]}`")
                report.append(f"- **Size:** {data.size}")
                report.append(f"- **Preview:**\n```\n{data.content_preview}\n```\n")
        
        return "\n".join(report)
    
    def generate_json_report(self) -> Dict:
        self.build_attack_chains()
        vulnerabilities = self.vulnerabilities
        credentials = self.credentials
        database_access = self.database_access
        shell_access = self.shell_access
        lateral_movement = self.lateral_movement
        data_exfiltration = self.data_exfiltration
        if self.strict_evidence_only:
            vulnerabilities = [v for v in vulnerabilities if self._is_vuln_proven(v)]
            credentials = [c for c in credentials if c.extraction_command and self._has_exec_cmd(c.extraction_command)]
            database_access = [d for d in database_access if self._is_access_proven(d.extraction_command, d.credentials)]
            shell_access = [s for s in shell_access if self._is_access_proven(s.extraction_command, s.method)]
            lateral_movement = [l for l in lateral_movement if self._is_access_proven(l.extraction_command, l.method)]
            data_exfiltration = [d for d in data_exfiltration if self._is_access_proven(d.extraction_command, d.content_preview)]
        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "vulnerabilities": len(vulnerabilities),
                "credentials": len(credentials),
                "database_access": len(database_access),
                "shell_access": len(shell_access),
                "lateral_movement": len(lateral_movement),
                "data_exfiltration": len(data_exfiltration),
                "attack_chains": len(self.attack_chains),
                "security_controls_events": len(self.security_controls),
            },
            "attack_chains": [asdict(c) for c in self.attack_chains],
            "vulnerabilities": [asdict(v) for v in vulnerabilities],
            "credentials": [asdict(c) for c in credentials],
            "database_access": [asdict(d) for d in database_access],
            "shell_access": [asdict(s) for s in shell_access],
            "lateral_movement": [asdict(l) for l in lateral_movement],
            "data_exfiltration": [asdict(d) for d in data_exfiltration],
            "security_controls": self.security_controls,
        }

    # ══════════════════════════════════════════════════════════════════════
    #  PDF & HTML Professional Report Generation
    # ══════════════════════════════════════════════════════════════════════

    # MITRE ATT&CK auto-mapping for common vulnerability types
    _MITRE_AUTO_MAP = {
        "SQL Injection": ("T1190", "Initial Access", "Exploit Public-Facing Application"),
        "Remote Code Execution": ("T1059", "Execution", "Command and Scripting Interpreter"),
        "Command Injection": ("T1059.004", "Execution", "Unix Shell"),
        "Local File Inclusion": ("T1005", "Collection", "Data from Local System"),
        "Remote File Inclusion": ("T1105", "Command and Control", "Ingress Tool Transfer"),
        "Cross-Site Scripting": ("T1189", "Initial Access", "Drive-by Compromise"),
        "Default Credentials": ("T1078", "Initial Access", "Valid Accounts"),
        "File Upload": ("T1505.003", "Persistence", "Web Shell"),
        "Directory Traversal": ("T1083", "Discovery", "File and Directory Discovery"),
        "Path Traversal": ("T1083", "Discovery", "File and Directory Discovery"),
        "XML External Entity": ("T1059.007", "Execution", "JavaScript"),
        "Server-Side Request Forgery": ("T1090", "Command and Control", "Proxy"),
        "Information Disclosure": ("T1592", "Reconnaissance", "Gather Victim Host Information"),
        "Weak Password": ("T1110", "Credential Access", "Brute Force"),
        "Insecure Direct Object Reference": ("T1548", "Privilege Escalation", "Abuse Elevation Control"),
        "Broken Access Control": ("T1548", "Privilege Escalation", "Abuse Elevation Control"),
        "Cross-Site Request Forgery": ("T1185", "Collection", "Browser Session Hijacking"),
        "Open Redirect": ("T1036", "Defense Evasion", "Masquerading"),
        "Mass Assignment": ("T1548", "Privilege Escalation", "Abuse Elevation Control"),
    }

    _REMEDIATION_MAP = {
        "SQL Injection": "Use parameterized queries and prepared statements. Implement strict input validation with allowlists. Deploy a Web Application Firewall (WAF). Apply least privilege to database accounts.",
        "Remote Code Execution": "Patch the vulnerable software immediately. Implement input sanitization. Use application sandboxing and containers. Deploy RASP.",
        "Command Injection": "Never pass user input directly to system commands. Use language-specific APIs instead of shell commands. Implement strict input validation.",
        "Local File Inclusion": "Sanitize and validate all file path inputs. Use a whitelist of allowed files. Disable allow_url_include in PHP. Implement proper filesystem access controls.",
        "Remote File Inclusion": "Disable allow_url_include and allow_url_fopen in PHP configuration. Validate and sanitize all user inputs. Use allowlist for file includes.",
        "Cross-Site Scripting": "Implement context-aware output encoding. Use Content Security Policy (CSP) headers. Sanitize HTML with a proven library. Set HTTPOnly and Secure cookie flags.",
        "Default Credentials": "Change all default credentials immediately. Implement a strong password policy. Use multi-factor authentication. Conduct regular credential audits.",
        "File Upload": "Validate file types using content inspection (magic bytes), not extensions. Store uploads outside web root. Rename uploaded files. Implement size limits.",
        "Directory Traversal": "Validate and sanitize file paths. Use a chroot jail or containerization. Implement proper access controls. Never use user input directly in file operations.",
        "Path Traversal": "Canonicalize file paths before validation. Use a whitelist of allowed directories. Implement chroot jail.",
        "XML External Entity": "Disable XML external entity processing. Use less complex data formats (JSON). Configure XML parser to prevent XXE.",
        "Server-Side Request Forgery": "Validate and sanitize all URLs. Implement allowlists for permitted hosts. Block requests to internal IP ranges. Use network segmentation.",
        "Information Disclosure": "Remove sensitive information from error messages. Implement proper access controls. Review and harden application configuration.",
        "Weak Password": "Enforce strong password policies (12+ characters, complexity). Implement account lockout. Use multi-factor authentication. Deploy credential stuffing protection.",
        "Insecure Direct Object Reference": "Implement proper authorization checks for every object access. Use indirect references. Validate user permissions server-side.",
        "Broken Access Control": "Implement role-based access control (RBAC). Deny access by default. Validate permissions on every request. Log access control failures.",
        "Cross-Site Request Forgery": "Implement anti-CSRF tokens. Use SameSite cookie attribute. Verify Origin and Referer headers.",
        "Open Redirect": "Validate redirect URLs against a whitelist. Use relative URLs for redirects. Warn users before redirecting externally.",
        "Mass Assignment": "Use allowlists for bindable parameters. Implement DTOs (Data Transfer Objects). Never bind user input directly to internal models.",
    }

    def set_metadata(self, **kwargs):
        """Set report metadata: title, targets, assessor, classification, duration, cost, etc."""
        self.metadata.update(kwargs)

    def _get_severity_stats(self) -> Dict[str, int]:
        """Count all findings by severity level."""
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in self.vulnerabilities:
            sev = self._vuln_type_to_severity(vuln.type)
            stats[sev] = stats.get(sev, 0) + 1
        for _ in self.database_access:
            stats["critical"] += 1
        for _ in self.shell_access:
            stats["critical"] += 1
        for _ in self.data_exfiltration:
            stats["high"] += 1
        return stats

    def _calculate_risk_score(self) -> int:
        """Calculate overall risk score (0-100)."""
        score = 0
        stats = self._get_severity_stats()
        score += stats.get("critical", 0) * 25
        score += stats.get("high", 0) * 15
        score += stats.get("medium", 0) * 8
        score += stats.get("low", 0) * 3
        score += stats.get("info", 0) * 1
        score += len(self.attack_chains) * 10
        return min(score, 100)

    def _get_all_targets(self) -> List[str]:
        """Extract unique targets from all findings."""
        targets = set()
        for vuln in self.vulnerabilities:
            if vuln.service and vuln.service != "unknown":
                targets.add(vuln.service)
        for db in self.database_access:
            if db.host and db.host != "unknown":
                targets.add(db.host)
        for shell in self.shell_access:
            if shell.host and shell.host not in ("unknown", "target"):
                targets.add(shell.host)
        targets.discard("")
        return list(targets) or self.metadata.get("targets", ["Target(s) not specified"])

    def _get_mitre_techniques_used(self) -> List[Dict[str, str]]:
        """Get all MITRE ATT&CK techniques observed in findings."""
        techniques: Dict[str, Dict[str, str]] = {}
        for vuln in self.vulnerabilities:
            if vuln.mitre_id:
                techniques[vuln.mitre_id] = {
                    "id": vuln.mitre_id, "tactic": "See ATT&CK",
                    "name": vuln.type, "source": vuln.endpoint,
                }
            if vuln.type in self._MITRE_AUTO_MAP:
                mid, tactic, name = self._MITRE_AUTO_MAP[vuln.type]
                techniques.setdefault(mid, {"id": mid, "tactic": tactic, "name": name, "source": vuln.endpoint})
        for cred in self.credentials:
            m = cred.extraction_method.lower()
            if "brute" in m:
                techniques.setdefault("T1110", {"id": "T1110", "tactic": "Credential Access", "name": "Brute Force", "source": cred.service})
            elif "config" in m:
                techniques.setdefault("T1552.001", {"id": "T1552.001", "tactic": "Credential Access", "name": "Credentials In Files", "source": cred.service})
        for shell in self.shell_access:
            techniques.setdefault("T1059", {"id": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter", "source": shell.host})
        for move in self.lateral_movement:
            key = "T1021.004" if "ssh" in move.method.lower() else "T1021.002"
            name = "SSH" if "ssh" in move.method.lower() else "SMB/Windows Admin Shares"
            techniques.setdefault(key, {"id": key, "tactic": "Lateral Movement", "name": name, "source": move.to_host})
        for data in self.data_exfiltration:
            techniques.setdefault("T1041", {"id": "T1041", "tactic": "Exfiltration", "name": "Exfiltration Over C2 Channel", "source": data.source[:50]})
        return list(techniques.values())

    @staticmethod
    def _estimate_cvss(severity: str) -> float:
        """Rough CVSS estimate from severity label."""
        return {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 3.5, "info": 0.0}.get(severity, 0.0)

    def _build_report_findings(self) -> List[Dict[str, Any]]:
        """Build a unified, enriched list of findings for HTML/PDF reports."""
        findings = []
        fid = 0
        for vuln in self.vulnerabilities:
            fid += 1
            sev = self._vuln_type_to_severity(vuln.type)
            mitre = vuln.mitre_id or ""
            if not mitre and vuln.type in self._MITRE_AUTO_MAP:
                mitre = self._MITRE_AUTO_MAP[vuln.type][0]
            findings.append({
                "id": f"VULN-{fid:03d}",
                "title": f"{vuln.type} \u2014 {vuln.endpoint}",
                "severity": sev,
                "type": "vulnerability",
                "target": vuln.endpoint,
                "description": vuln.impact,
                "evidence_cmd": vuln.extraction_command,
                "evidence_output": vuln.evidence[:800] if vuln.evidence else "",
                "mitre_id": mitre,
                "mitre_name": self._MITRE_AUTO_MAP.get(vuln.type, ("", "", ""))[2] if vuln.type in self._MITRE_AUTO_MAP else "",
                "remediation": self._REMEDIATION_MAP.get(vuln.type, "Consult vendor documentation for remediation guidance."),
                "cvss": self._estimate_cvss(sev),
                "iteration": vuln.iteration,
                "status": "Confirmed",
            })
        for db in self.database_access:
            fid += 1
            findings.append({
                "id": f"DBA-{fid:03d}",
                "title": f"Database Access \u2014 {db.db_type} @ {db.host}",
                "severity": "critical",
                "type": "database_access",
                "target": db.host,
                "description": f"Full database access to {db.db_type}. Databases: {', '.join(db.databases)}. Tables dumped: {len(db.tables_dumped)}. Records: ~{db.records_count}.",
                "evidence_cmd": db.extraction_command,
                "evidence_output": f"Databases: {', '.join(db.databases)}\n" + (f"Sensitive data: {', '.join(db.sensitive_data)}" if db.sensitive_data else ""),
                "mitre_id": "T1005",
                "mitre_name": "Data from Local System",
                "remediation": "Restrict database access with strong authentication and network segmentation. Remove default credentials. Implement least-privilege access.",
                "cvss": 9.8,
                "iteration": db.iteration,
                "status": "Confirmed",
            })
        for shell in self.shell_access:
            fid += 1
            findings.append({
                "id": f"RCE-{fid:03d}",
                "title": f"Shell Access \u2014 {shell.type} on {shell.host}",
                "severity": "critical",
                "type": "shell_access",
                "target": shell.host,
                "description": f"{shell.type} as user '{shell.user}' via {shell.method[:100]}",
                "evidence_cmd": shell.extraction_command,
                "evidence_output": shell.method[:500],
                "mitre_id": "T1059",
                "mitre_name": "Command and Scripting Interpreter",
                "remediation": "Patch the vulnerable entry point. Implement WAF and IDS. Restrict outbound connections. Harden application security.",
                "cvss": 9.8,
                "iteration": shell.iteration,
                "status": "Confirmed",
            })
        for data in self.data_exfiltration:
            fid += 1
            findings.append({
                "id": f"EXF-{fid:03d}",
                "title": f"Data Exfiltration \u2014 {data.type}",
                "severity": "high",
                "type": "data_exfiltration",
                "target": data.source[:80],
                "description": f"Exfiltrated {data.size} of {data.type} data.",
                "evidence_cmd": data.extraction_command,
                "evidence_output": data.content_preview[:500],
                "mitre_id": "T1041",
                "mitre_name": "Exfiltration Over C2 Channel",
                "remediation": "Implement DLP controls. Restrict file access. Monitor for anomalous data transfers.",
                "cvss": 7.5,
                "iteration": data.iteration,
                "status": "Confirmed",
            })
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: sev_rank.get(f["severity"], 5))
        return findings

    def _detect_tools_used(self) -> List[str]:
        """Auto-detect tools from extraction commands."""
        known = ["nmap", "sqlmap", "nikto", "gobuster", "dirb", "wfuzz", "hydra",
                 "metasploit", "curl", "wget", "nuclei", "ffuf", "burpsuite",
                 "wpscan", "medusa", "john", "hashcat", "crackmapexec", "responder",
                 "sslscan", "sslyze", "commix", "whatweb", "subfinder", "amass"]
        tools = set()
        for vuln in self.vulnerabilities:
            cmd = (vuln.extraction_command or "").lower()
            for t in known:
                if t in cmd:
                    tools.add(t)
        for cred in self.credentials:
            cmd = (cred.extraction_command or "").lower()
            for t in known:
                if t in cmd:
                    tools.add(t)
        return sorted(tools) if tools else ["(auto-detected from command analysis)"]

    # ─────────────────────────────────────────────────────────────────────
    #  HTML Report  (self-contained, dark-themed, interactive)
    # ─────────────────────────────────────────────────────────────────────

    def generate_html_report(self, output_path: str) -> str:
        """Generate a self-contained dark-themed HTML pentest report."""
        esc = html_escape
        self.build_attack_chains()
        now = datetime.now()
        title = self.metadata.get("title", "Penetration Test Report")
        classification = self.metadata.get("classification", "CONFIDENTIAL")
        assessor = self.metadata.get("assessor", "TazoSploit Automated Assessment")
        targets = self._get_all_targets()
        stats = self._get_severity_stats()
        risk = self._calculate_risk_score()
        mitre = self._get_mitre_techniques_used()
        findings = self._build_report_findings()
        total = sum(stats.values())
        duration = self.metadata.get("duration", "N/A")
        cost = self.metadata.get("cost", "N/A")
        tools = self._detect_tools_used()

        # Risk colour
        if risk >= 80:
            risk_color = "var(--crit)"
        elif risk >= 60:
            risk_color = "var(--high)"
        elif risk >= 40:
            risk_color = "var(--med)"
        else:
            risk_color = "var(--ok)"

        # ── Severity bar segments ──
        bar_parts = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = stats.get(sev, 0)
            if cnt > 0 and total > 0:
                pct = max(cnt / total * 100, 8)
                bar_parts += f'<div style="width:{pct:.1f}%;background:var(--{sev})">{cnt}</div>'

        # ── Findings table rows ──
        findings_rows = ""
        for f in findings:
            s = f["severity"]
            findings_rows += (
                f'<tr data-sev="{esc(s)}">'
                f'<td>{esc(f["id"])}</td>'
                f'<td>{esc(f["title"][:80])}</td>'
                f'<td><span class="badge {esc(s)}">{esc(s.upper())}</span></td>'
                f'<td>{esc(str(f["target"])[:50])}</td>'
                f'<td>{f["cvss"]:.1f}</td>'
                f'<td>{esc(f["status"])}</td>'
                f'</tr>\n'
            )

        # ── Detailed findings ──
        findings_detail = ""
        for f in findings:
            s = f["severity"]
            mitre_link = (
                f'<a href="https://attack.mitre.org/techniques/{esc(f["mitre_id"])}/" target="_blank">'
                f'{esc(f["mitre_id"])} \u2014 {esc(f["mitre_name"])}</a>'
            ) if f.get("mitre_id") else "N/A"
            ev_cmd = f'<span class="cmd">$ {esc(f["evidence_cmd"][:200])}</span>\n' if f.get("evidence_cmd") else ""
            ev_out = esc(f.get("evidence_output", "")[:600]) or "See command output"
            findings_detail += (
                f'<details data-sev="{esc(s)}">\n'
                f'<summary><span class="badge {esc(s)}">{esc(s.upper())}</span> '
                f'{esc(f["id"])} \u2014 {esc(f["title"][:80])}</summary>\n'
                f'<div class="finding-body">\n'
                f'<div class="finding-grid">\n'
                f'<div class="fg-item"><div class="fg-label">Target</div><div class="fg-value">{esc(str(f["target"]))}</div></div>\n'
                f'<div class="fg-item"><div class="fg-label">CVSS Score</div><div class="fg-value">{f["cvss"]:.1f}</div></div>\n'
                f'<div class="fg-item"><div class="fg-label">MITRE ATT&CK</div><div class="fg-value">{mitre_link}</div></div>\n'
                f'<div class="fg-item"><div class="fg-label">Iteration</div><div class="fg-value">{f.get("iteration", "N/A")}</div></div>\n'
                f'</div>\n'
                f'<h4>Description</h4>\n'
                f'<p>{esc(f.get("description", "N/A"))}</p>\n'
                f'<h4 style="margin-top:16px">Evidence</h4>\n'
                f'<div class="evidence-block">{ev_cmd}{ev_out}</div>\n'
                f'<h4 style="margin-top:16px">Remediation</h4>\n'
                f'<div class="remediation">{esc(f.get("remediation", "Consult vendor documentation."))}</div>\n'
                f'</div></details>\n'
            )

        # ── Timeline ──
        timeline_items = ""
        all_tl = sorted(
            [(f.get("iteration", 0) or 0, f["severity"], f["title"], f["id"]) for f in findings],
            key=lambda x: x[0],
        )
        for it, sev, t, fid in all_tl:
            timeline_items += (
                f'<div class="tl-item"><div class="tl-iter">Iteration {it}</div>'
                f'<div class="tl-title"><span class="badge {esc(sev)}">{esc(sev.upper())}</span> '
                f'{esc(fid)} \u2014 {esc(t[:60])}</div></div>\n'
            )

        # ── MITRE cards ──
        mitre_cards = ""
        for t in mitre:
            tid_path = t["id"].replace(".", "/")
            mitre_cards += (
                f'<div class="mitre-card">'
                f'<div class="tid"><a href="https://attack.mitre.org/techniques/{esc(tid_path)}/" target="_blank">{esc(t["id"])}</a></div>'
                f'<div class="tname">{esc(t["name"])}</div>'
                f'<div class="ttactic">{esc(t["tactic"])}</div>'
                f'</div>\n'
            )

        # ── Credentials table ──
        cred_rows = ""
        for i, cred in enumerate(self.credentials, 1):
            cred_rows += (
                f'<tr><td>{i}</td>'
                f'<td>{esc(cred.username)}</td>'
                f'<td>{esc(cred.password)}</td>'
                f'<td>{esc(cred.service)}</td>'
                f'<td>{esc(cred.extraction_method)}</td></tr>\n'
            )

        # ── Attack chains ──
        chains_html = ""
        for chain in self.attack_chains:
            steps_html = "".join(
                f'<div class="tl-item"><div class="tl-iter">Step {j + 1} \u2014 {esc(s["type"].upper())}</div>'
                f'<div class="tl-title">{esc(s["description"])}</div></div>'
                for j, s in enumerate(chain.steps)
            )
            chains_html += (
                f'<details><summary><span class="badge critical">{esc(chain.severity.upper())}</span> '
                f'{esc(chain.title)}</summary>'
                f'<div class="finding-body"><p>{esc(chain.summary)}</p>'
                f'<div class="timeline" style="margin-top:16px">{steps_html}</div></div></details>\n'
            )

        # ── Tools list ──
        tools_list = "".join(f"<li>{esc(t)}</li>" for t in tools)

        # ── Full HTML ──
        html = f'''<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} \u2014 TazoSploit</title>
<style>
:root{{--bg:#0a0a1a;--bg2:#12122a;--card:#1a1a3e;--card-h:#22224e;--accent:#e94560;--accent-d:#b83050;
--text:#e0e0f0;--text2:#8892b0;--muted:#5a6380;--border:#2a2a5a;--crit:#ff0040;--high:#ff6600;
--med:#ffbb00;--low:#00aaff;--info:#6c757d;--ok:#00cc88;
--sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
--mono:'JetBrains Mono','Fira Code','Cascadia Code','Courier New',monospace}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:var(--sans);background:var(--bg);color:var(--text);line-height:1.65;font-size:14px}}
a{{color:var(--accent);text-decoration:none}}a:hover{{text-decoration:underline}}
.wrap{{max-width:1100px;margin:0 auto;padding:24px}}
.cover{{text-align:center;padding:80px 20px 60px;border-bottom:3px solid var(--accent);margin-bottom:40px}}
.cover .logo{{font-size:48px;font-weight:800;letter-spacing:-1px;color:var(--accent);margin-bottom:8px}}
.cover .logo span{{color:var(--text)}}
.cover h1{{font-size:28px;color:var(--text);margin:16px 0 8px}}
.cover .meta{{color:var(--text2);font-size:14px;margin-top:20px;display:flex;flex-wrap:wrap;justify-content:center;gap:24px}}
.cover .meta div{{background:var(--card);padding:8px 18px;border-radius:6px;border:1px solid var(--border)}}
.cover .class-badge{{display:inline-block;margin-top:16px;background:var(--accent);color:#fff;padding:6px 20px;border-radius:4px;font-weight:700;letter-spacing:2px;font-size:12px}}
.toc{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px 32px;margin-bottom:40px}}
.toc h2{{font-size:18px;margin-bottom:12px;color:var(--accent)}}.toc ol{{padding-left:20px}}.toc li{{margin:6px 0}}.toc a{{color:var(--text2)}}.toc a:hover{{color:var(--accent)}}
section{{margin-bottom:48px}}section>h2{{font-size:22px;color:var(--accent);border-bottom:2px solid var(--border);padding-bottom:8px;margin-bottom:20px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;margin-bottom:24px}}
.stat{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;text-align:center}}
.stat .val{{font-size:32px;font-weight:800;color:var(--accent)}}.stat .lbl{{color:var(--text2);font-size:12px;margin-top:4px;text-transform:uppercase;letter-spacing:1px}}
.sev-bar{{display:flex;height:32px;border-radius:6px;overflow:hidden;margin:16px 0}}
.sev-bar div{{display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#fff;min-width:30px}}
.risk-gauge{{text-align:center;margin:24px 0}}.risk-gauge .score{{display:inline-flex;align-items:center;justify-content:center;width:120px;height:120px;border-radius:50%;font-size:36px;font-weight:800;border:6px solid}}
.badge{{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;color:#fff;text-transform:uppercase;letter-spacing:.5px}}
.badge.critical{{background:var(--crit)}}.badge.high{{background:var(--high)}}.badge.medium{{background:var(--med);color:#1a1a1a}}.badge.low{{background:var(--low)}}.badge.info{{background:var(--info)}}
table{{width:100%;border-collapse:collapse;margin:16px 0}}
th{{background:var(--card);color:var(--accent);font-size:11px;text-transform:uppercase;letter-spacing:1px;padding:12px 16px;text-align:left;border-bottom:2px solid var(--accent)}}
td{{padding:10px 16px;border-bottom:1px solid var(--border);font-size:13px}}tr:hover td{{background:var(--card)}}
details{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;margin-bottom:16px;overflow:hidden}}
details[open]{{border-color:var(--accent)}}
summary{{padding:16px 20px;cursor:pointer;display:flex;align-items:center;gap:12px;font-weight:600;font-size:15px}}
summary:hover{{background:var(--card)}}summary::marker{{color:var(--accent)}}
.finding-body{{padding:20px;border-top:1px solid var(--border)}}
.finding-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}}
.finding-grid .fg-item{{background:var(--card);padding:12px;border-radius:6px}}
.finding-grid .fg-label{{color:var(--text2);font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}}
.finding-grid .fg-value{{font-size:14px}}
.evidence-block{{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:16px;margin:12px 0;font-family:var(--mono);font-size:12px;color:#c9d1d9;white-space:pre-wrap;word-break:break-all;overflow-x:auto;max-height:400px;overflow-y:auto}}
.evidence-block .cmd{{color:var(--ok);font-weight:700}}
.remediation{{background:#0d2818;border:1px solid #1a4d2e;border-radius:6px;padding:16px;margin:12px 0;color:#7ee787}}
.timeline{{position:relative;padding-left:32px;margin:20px 0}}.timeline::before{{content:'';position:absolute;left:12px;top:0;bottom:0;width:2px;background:var(--border)}}
.tl-item{{position:relative;margin-bottom:20px;padding-left:20px}}.tl-item::before{{content:'';position:absolute;left:-24px;top:6px;width:12px;height:12px;border-radius:50%;background:var(--accent);border:2px solid var(--bg)}}
.tl-iter{{color:var(--text2);font-size:11px;text-transform:uppercase;letter-spacing:1px}}.tl-title{{font-weight:600;margin:4px 0}}
.mitre-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}}
.mitre-card{{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:12px}}
.mitre-card .tid{{color:var(--accent);font-weight:700;font-size:13px}}.mitre-card .tname{{font-size:12px;margin:4px 0;color:var(--text)}}.mitre-card .ttactic{{font-size:11px;color:var(--text2)}}
.filters{{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}}
.filters button{{padding:6px 14px;border-radius:4px;border:1px solid var(--border);background:var(--bg2);color:var(--text2);cursor:pointer;font-size:12px;font-weight:600}}
.filters button:hover,.filters button.active{{background:var(--accent);color:#fff;border-color:var(--accent)}}
.appendix-list{{columns:2;column-gap:24px}}.appendix-list li{{margin:4px 0;font-size:13px;color:var(--text2)}}
.footer{{text-align:center;padding:40px 0 20px;color:var(--muted);font-size:12px;border-top:1px solid var(--border);margin-top:40px}}
@media print{{body{{background:#fff;color:#1a1a1a;font-size:11px}}.cover{{border-color:#333}}.cover .logo{{color:#333}}.cover .logo span{{color:#666}}
section>h2{{color:#333}}.stat,.finding-grid .fg-item,.mitre-card{{background:#f5f5f5;border-color:#ddd}}
details{{border-color:#ddd}}.evidence-block{{background:#f0f0f0;color:#1a1a1a;border-color:#ccc}}.badge.medium{{color:#1a1a1a}}
.filters,.toc{{display:none}}th{{background:#333;color:#fff}}td{{border-color:#ddd}}.sev-bar div{{color:#fff}}}}
</style></head>
<body><div class="wrap">
<div class="cover"><div class="logo">\u26a1 Tazo<span>Sploit</span></div>
<h1>{esc(title)}</h1>
<div class="meta">
<div><strong>Target(s):</strong> {esc(', '.join(str(t) for t in targets))}</div>
<div><strong>Date:</strong> {now.strftime('%B %d, %Y')}</div>
<div><strong>Assessor:</strong> {esc(assessor)}</div>
<div><strong>Duration:</strong> {esc(str(duration))}</div>
</div>
<div class="class-badge">{esc(classification)}</div></div>

<nav class="toc"><h2>Table of Contents</h2>
<ol><li><a href="#exec-summary">Executive Summary</a></li>
<li><a href="#findings-overview">Findings Overview</a></li>
<li><a href="#findings-detail">Detailed Findings</a></li>
<li><a href="#credentials">Discovered Credentials</a></li>
<li><a href="#attack-chains">Attack Chains</a></li>
<li><a href="#timeline">Attack Timeline</a></li>
<li><a href="#mitre">MITRE ATT&CK Coverage</a></li>
<li><a href="#appendix">Appendix</a></li></ol></nav>

<section id="exec-summary"><h2>1. Executive Summary</h2>
<div class="stats">
<div class="stat"><div class="val">{total}</div><div class="lbl">Total Findings</div></div>
<div class="stat"><div class="val" style="color:var(--crit)">{stats.get('critical',0)}</div><div class="lbl">Critical</div></div>
<div class="stat"><div class="val" style="color:var(--high)">{stats.get('high',0)}</div><div class="lbl">High</div></div>
<div class="stat"><div class="val" style="color:var(--med)">{stats.get('medium',0)}</div><div class="lbl">Medium</div></div>
<div class="stat"><div class="val" style="color:var(--low)">{stats.get('low',0)}</div><div class="lbl">Low</div></div>
<div class="stat"><div class="val">{len(self.credentials)}</div><div class="lbl">Credentials</div></div>
<div class="stat"><div class="val">{len(targets)}</div><div class="lbl">Targets</div></div>
</div>
<div class="sev-bar">{bar_parts}</div>
<div class="risk-gauge"><div class="score" style="border-color:{risk_color};color:{risk_color}">{risk}</div>
<div style="margin-top:8px;color:var(--text2)">Overall Risk Score</div></div>
<p style="margin-top:20px;color:var(--text2)">This automated penetration test identified <strong>{total}</strong> finding(s) across <strong>{len(targets)}</strong> target(s). Overall risk score: <strong>{risk}/100</strong>.{' Cost: ' + esc(str(cost)) if cost != 'N/A' else ''}</p>
</section>

<section id="findings-overview"><h2>2. Findings Overview</h2>
<div class="filters">
<button class="active" onclick="filterFindings('all')">All ({total})</button>
<button onclick="filterFindings('critical')">Critical ({stats.get('critical',0)})</button>
<button onclick="filterFindings('high')">High ({stats.get('high',0)})</button>
<button onclick="filterFindings('medium')">Medium ({stats.get('medium',0)})</button>
<button onclick="filterFindings('low')">Low ({stats.get('low',0)})</button>
<button onclick="filterFindings('info')">Info ({stats.get('info',0)})</button>
</div>
<table id="findings-table">
<thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Target</th><th>CVSS</th><th>Status</th></tr></thead>
<tbody>{findings_rows}</tbody></table></section>

<section id="findings-detail"><h2>3. Detailed Findings</h2>
{findings_detail if findings_detail else '<p style="color:var(--text2)">No findings to display.</p>'}
</section>

<section id="credentials"><h2>4. Discovered Credentials</h2>
{'<table><thead><tr><th>#</th><th>Username</th><th>Password</th><th>Service</th><th>Method</th></tr></thead><tbody>' + cred_rows + '</tbody></table>' if cred_rows else '<p style="color:var(--text2)">No credentials discovered.</p>'}
</section>

<section id="attack-chains"><h2>5. Attack Chains</h2>
{chains_html if chains_html else '<p style="color:var(--text2)">No attack chains identified.</p>'}
</section>

<section id="timeline"><h2>6. Attack Timeline</h2>
<div class="timeline">{timeline_items if timeline_items else '<p style="color:var(--text2)">No timeline data.</p>'}</div></section>

<section id="mitre"><h2>7. MITRE ATT&CK Coverage</h2>
<p style="margin-bottom:16px;color:var(--text2)"><strong>{len(mitre)}</strong> technique(s) observed.</p>
<div class="mitre-grid">{mitre_cards if mitre_cards else '<p style="color:var(--text2)">No MITRE techniques mapped.</p>'}</div></section>

<section id="appendix"><h2>8. Appendix</h2>
<h3 style="color:var(--text);margin:16px 0 8px">A. Tools Used</h3>
<ul class="appendix-list">{tools_list}</ul>
<h3 style="color:var(--text);margin:24px 0 8px">B. Methodology</h3>
<p style="color:var(--text2)">This assessment was conducted using TazoSploit, an AI-driven automated penetration testing platform. The AI agent autonomously selects tools, executes attacks, and iterates through the MITRE ATT&CK framework to discover and exploit vulnerabilities.</p>
<h3 style="color:var(--text);margin:24px 0 8px">C. Disclaimer</h3>
<p style="color:var(--text2)">This report is confidential and intended solely for the authorized recipient. The findings represent the security posture at the time of assessment. No guarantee is made that all vulnerabilities have been identified. Redistribution without authorization is prohibited.</p>
</section>

<div class="footer"><p>Generated by TazoSploit on {now.strftime('%B %d, %Y at %H:%M')}</p>
<p>\u00a9 {now.year} TazoSploit \u2014 Automated Penetration Testing Platform</p></div>
</div>
<script>
function filterFindings(sev){{
  document.querySelectorAll('.filters button').forEach(b=>b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#findings-table tbody tr').forEach(r=>{{r.style.display=(sev==='all'||r.dataset.sev===sev)?'':'none'}});
  document.querySelectorAll('#findings-detail details').forEach(d=>{{d.style.display=(sev==='all'||d.dataset.sev===sev)?'':'none'}});
}}
</script></body></html>'''
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return output_path

    # ─────────────────────────────────────────────────────────────────────
    #  PDF Report  (fpdf2-based, professional layout)
    # ─────────────────────────────────────────────────────────────────────

    def generate_pdf_report(self, output_path: str) -> str:
        """Generate a professional PDF pentest report using fpdf2."""
        try:
            from fpdf import FPDF
        except ImportError:
            raise ImportError("fpdf2 is required for PDF generation: pip install fpdf2")

        self.build_attack_chains()
        now = datetime.now()
        title = self.metadata.get("title", "Penetration Test Report")
        classification = self.metadata.get("classification", "CONFIDENTIAL")
        assessor = self.metadata.get("assessor", "TazoSploit Automated Assessment")
        targets = self._get_all_targets()
        stats = self._get_severity_stats()
        risk = self._calculate_risk_score()
        mitre = self._get_mitre_techniques_used()
        findings = self._build_report_findings()
        total = sum(stats.values())
        duration = self.metadata.get("duration", "N/A")
        cost = self.metadata.get("cost", "N/A")
        tools = self._detect_tools_used()

        sev_rgb = {
            "critical": (255, 0, 64), "high": (255, 102, 0),
            "medium": (255, 187, 0), "low": (0, 170, 255), "info": (108, 117, 125),
        }

        # Custom PDF class with header/footer
        def _latin_safe(text):
            """Strip non-latin-1 chars for built-in fonts."""
            if not text:
                return ""
            return text.encode("latin-1", errors="replace").decode("latin-1")

        _title_safe = _latin_safe(title)
        _class_safe = _latin_safe(classification)
        _now = now

        class TazoPDF(FPDF):
            def header(self):
                if self.page_no() > 1:
                    self.set_font("Helvetica", "I", 8)
                    self.set_text_color(150, 150, 150)
                    self.cell(0, 8, f"TazoSploit  |  {_title_safe}  |  {_class_safe}", align="L")
                    self.ln(4)
                    self.set_draw_color(233, 69, 96)
                    self.set_line_width(0.5)
                    self.line(10, self.get_y(), 200, self.get_y())
                    self.ln(6)

            def footer(self):
                self.set_y(-15)
                self.set_font("Helvetica", "I", 8)
                self.set_text_color(150, 150, 150)
                self.cell(0, 10,
                          f"Page {self.page_no()}/{{nb}}  |  {_class_safe}  |  Generated {_now.strftime('%Y-%m-%d')}",
                          align="C")

        pdf = TazoPDF()
        pdf.alias_nb_pages()
        pdf.set_auto_page_break(auto=True, margin=20)

        # Try to load Unicode fonts (DejaVu available on most Linux)
        _has_uni = False
        for dejavu_dir in ["/usr/share/fonts/truetype/dejavu",
                           "/usr/share/fonts/dejavu",
                           "/usr/share/fonts/truetype"]:
            dv = os.path.join(dejavu_dir, "DejaVuSans.ttf")
            dvb = os.path.join(dejavu_dir, "DejaVuSans-Bold.ttf")
            dvm = os.path.join(dejavu_dir, "DejaVuSansMono.ttf")
            if os.path.exists(dv):
                try:
                    pdf.add_font("DejaVu", "", dv)
                    pdf.add_font("DejaVu", "B", dvb if os.path.exists(dvb) else dv)
                    if os.path.exists(dvm):
                        pdf.add_font("DejaVuMono", "", dvm)
                    _has_uni = True
                except Exception:
                    pass
                break

        def safe(text, maxlen=500):
            if not text:
                return ""
            t = str(text)[:maxlen]
            if not _has_uni:
                t = t.encode("latin-1", errors="replace").decode("latin-1")
            return t

        def sfont(style="", size=10):
            if _has_uni:
                pdf.set_font("DejaVu", "B" if "B" in style else "", size)
            else:
                pdf.set_font("Helvetica", style, size)

        def mfont(size=8):
            if _has_uni:
                pdf.set_font("DejaVuMono", "", size)
            else:
                pdf.set_font("Courier", "", size)

        # ── COVER PAGE ──
        pdf.add_page()
        pdf.set_fill_color(10, 10, 26)
        pdf.rect(0, 0, 210, 297, "F")
        pdf.set_y(60)
        pdf.set_text_color(233, 69, 96)
        sfont("B", 36)
        pdf.cell(0, 16, safe("TazoSploit"), ln=True, align="C")
        pdf.set_text_color(224, 224, 240)
        sfont("B", 22)
        pdf.cell(0, 14, safe(title), ln=True, align="C")
        pdf.ln(10)
        pdf.set_draw_color(233, 69, 96)
        pdf.set_line_width(1)
        pdf.line(60, pdf.get_y(), 150, pdf.get_y())
        pdf.ln(15)
        sfont("", 12)
        pdf.set_text_color(136, 146, 176)
        for line in [f"Target(s): {', '.join(str(t) for t in targets)}",
                     f"Date: {now.strftime('%B %d, %Y')}",
                     f"Assessor: {assessor}",
                     f"Duration: {duration}"]:
            pdf.cell(0, 8, safe(line), ln=True, align="C")
        pdf.ln(20)
        pdf.set_fill_color(233, 69, 96)
        pdf.set_text_color(255, 255, 255)
        sfont("B", 12)
        w = pdf.get_string_width(classification) + 20
        pdf.set_x((210 - w) / 2)
        pdf.cell(w, 10, safe(classification), fill=True, align="C")

        # ── EXECUTIVE SUMMARY ──
        pdf.add_page()
        pdf.set_text_color(233, 69, 96)
        sfont("B", 18)
        pdf.cell(0, 12, "1. Executive Summary", ln=True)
        pdf.set_draw_color(233, 69, 96)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(8)
        # Risk score box
        rc = (255, 0, 64) if risk >= 80 else (255, 102, 0) if risk >= 60 else (255, 187, 0) if risk >= 40 else (0, 204, 136)
        pdf.set_fill_color(*rc)
        pdf.set_text_color(255, 255, 255)
        sfont("B", 28)
        pdf.set_x(75)
        pdf.cell(60, 25, f"{risk}/100", fill=True, align="C", ln=True)
        sfont("", 10)
        pdf.set_text_color(136, 146, 176)
        pdf.cell(0, 8, "Overall Risk Score", align="C", ln=True)
        pdf.ln(8)
        # Stats table
        col_w = 31.6
        headers = ["Total", "Critical", "High", "Medium", "Low", "Info"]
        values = [str(total), str(stats.get("critical", 0)), str(stats.get("high", 0)),
                  str(stats.get("medium", 0)), str(stats.get("low", 0)), str(stats.get("info", 0))]
        colors_list = [(233, 69, 96), (255, 0, 64), (255, 102, 0), (255, 187, 0), (0, 170, 255), (108, 117, 125)]
        pdf.set_fill_color(26, 26, 62)
        pdf.set_text_color(233, 69, 96)
        sfont("B", 8)
        x_start = (210 - col_w * 6) / 2
        pdf.set_x(x_start)
        for h in headers:
            pdf.cell(col_w, 8, h, border=1, align="C", fill=True)
        pdf.ln()
        pdf.set_x(x_start)
        for i, v in enumerate(values):
            pdf.set_text_color(*colors_list[i])
            sfont("B", 14)
            pdf.cell(col_w, 10, v, border=1, align="C")
        pdf.ln(16)
        # Severity bar
        sfont("B", 11)
        pdf.set_text_color(50, 50, 50)
        pdf.cell(0, 8, "Severity Distribution", ln=True)
        pdf.ln(2)
        bar_x = 10.0
        bar_total_w = 190.0
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = stats.get(sev, 0)
            if cnt > 0 and total > 0:
                w = max(cnt / total * bar_total_w, 15)
                r, g, b = sev_rgb.get(sev, (108, 117, 125))
                pdf.set_fill_color(r, g, b)
                pdf.set_text_color(255, 255, 255)
                sfont("B", 8)
                pdf.set_x(bar_x)
                pdf.cell(w, 8, f"{sev[0].upper()}: {cnt}", fill=True, align="C")
                bar_x += w
        pdf.ln(12)
        # Summary paragraph
        pdf.set_text_color(80, 80, 80)
        sfont("", 10)
        summary_text = (
            f"This automated penetration test against {', '.join(str(t) for t in targets)} "
            f"identified {total} findings: {stats.get('critical',0)} critical, {stats.get('high',0)} high, "
            f"{stats.get('medium',0)} medium, {stats.get('low',0)} low, and {stats.get('info',0)} informational."
        )
        pdf.multi_cell(0, 6, safe(summary_text, 500))
        if self.credentials:
            pdf.ln(2)
            pdf.multi_cell(0, 6, safe(f"{len(self.credentials)} credential(s) were discovered during the assessment."))

        # ── FINDINGS TABLE ──
        pdf.add_page()
        pdf.set_text_color(233, 69, 96)
        sfont("B", 18)
        pdf.cell(0, 12, "2. Findings Overview", ln=True)
        pdf.set_draw_color(233, 69, 96)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(6)
        col_widths = [20, 70, 22, 40, 16, 22]
        pdf.set_fill_color(26, 26, 62)
        pdf.set_text_color(233, 69, 96)
        sfont("B", 8)
        for h, cw in zip(["ID", "Title", "Severity", "Target", "CVSS", "Status"], col_widths):
            pdf.cell(cw, 7, h, border=1, align="C", fill=True)
        pdf.ln()
        for f in findings:
            if pdf.get_y() > 270:
                pdf.add_page()
            sev = f["severity"]
            r, g, b = sev_rgb.get(sev, (108, 117, 125))
            pdf.set_text_color(50, 50, 50)
            sfont("", 7)
            pdf.cell(col_widths[0], 6, safe(f["id"], 10), border=1)
            pdf.cell(col_widths[1], 6, safe(f["title"], 45), border=1)
            pdf.set_text_color(r, g, b)
            sfont("B", 7)
            pdf.cell(col_widths[2], 6, sev.upper(), border=1, align="C")
            pdf.set_text_color(50, 50, 50)
            sfont("", 7)
            pdf.cell(col_widths[3], 6, safe(str(f["target"]), 25), border=1)
            pdf.cell(col_widths[4], 6, f'{f["cvss"]:.1f}', border=1, align="C")
            pdf.cell(col_widths[5], 6, safe(f["status"], 12), border=1, align="C")
            pdf.ln()

        # ── DETAILED FINDINGS ──
        pdf.add_page()
        pdf.set_text_color(233, 69, 96)
        sfont("B", 18)
        pdf.cell(0, 12, "3. Detailed Findings", ln=True)
        pdf.set_draw_color(233, 69, 96)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(6)
        for f in findings:
            if pdf.get_y() > 220:
                pdf.add_page()
            sev = f["severity"]
            r, g, b = sev_rgb.get(sev, (108, 117, 125))
            # Title bar
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            sfont("B", 10)
            pdf.cell(0, 8, safe(f"  [{sev.upper()}] {f['id']}  {f['title']}", 90), fill=True, ln=True)
            pdf.ln(2)
            # Metadata
            pdf.set_text_color(80, 80, 80)
            sfont("", 9)
            pdf.cell(30, 5, "Target:")
            sfont("B", 9)
            pdf.cell(0, 5, safe(str(f["target"]), 80), ln=True)
            sfont("", 9)
            pdf.cell(30, 5, "CVSS:")
            sfont("B", 9)
            pdf.cell(0, 5, f'{f["cvss"]:.1f}', ln=True)
            if f.get("mitre_id"):
                sfont("", 9)
                pdf.cell(30, 5, "MITRE:")
                sfont("B", 9)
                pdf.cell(0, 5, safe(f'{f["mitre_id"]} - {f.get("mitre_name", "")}', 80), ln=True)
            # Description
            pdf.ln(2)
            sfont("B", 9)
            pdf.set_text_color(50, 50, 50)
            pdf.cell(0, 5, "Description", ln=True)
            sfont("", 9)
            pdf.multi_cell(0, 5, safe(f.get("description", "N/A"), 300))
            # Evidence
            if f.get("evidence_cmd") or f.get("evidence_output"):
                pdf.ln(2)
                sfont("B", 9)
                pdf.cell(0, 5, "Evidence", ln=True)
                pdf.set_fill_color(13, 17, 23)
                mfont(7)
                ev_w = pdf.w - pdf.l_margin - pdf.r_margin
                if f.get("evidence_cmd"):
                    pdf.set_text_color(0, 204, 136)
                    pdf.set_x(pdf.l_margin)
                    pdf.multi_cell(ev_w, 4, safe(f'$ {f["evidence_cmd"]}', 200), fill=True)
                if f.get("evidence_output"):
                    pdf.set_text_color(201, 209, 217)
                    pdf.set_x(pdf.l_margin)
                    pdf.multi_cell(ev_w, 4, safe(f["evidence_output"], 400), fill=True)
            # Remediation
            pdf.ln(2)
            pdf.set_text_color(0, 140, 80)
            sfont("B", 9)
            pdf.cell(0, 5, "Remediation", ln=True)
            sfont("", 9)
            pdf.multi_cell(0, 5, safe(f.get("remediation", "Consult vendor documentation."), 300))
            # Separator
            pdf.ln(4)
            pdf.set_draw_color(42, 42, 90)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(6)

        # ── ATTACK CHAINS ──
        if self.attack_chains:
            pdf.add_page()
            pdf.set_text_color(233, 69, 96)
            sfont("B", 18)
            pdf.cell(0, 12, "4. Attack Chains", ln=True)
            pdf.set_draw_color(233, 69, 96)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(6)
            for chain in self.attack_chains:
                sfont("B", 12)
                pdf.set_text_color(233, 69, 96)
                pdf.cell(0, 8, safe(chain.title, 80), ln=True)
                sfont("", 9)
                pdf.set_text_color(80, 80, 80)
                pdf.multi_cell(0, 5, safe(chain.summary, 300))
                pdf.ln(2)
                for j, step in enumerate(chain.steps, 1):
                    sfont("", 8)
                    pdf.set_text_color(136, 146, 176)
                    pdf.cell(8, 5, f"{j}.")
                    pdf.set_text_color(50, 50, 50)
                    pdf.cell(0, 5, safe(f'[{step["type"].upper()}] {step["description"]}', 100), ln=True)
                pdf.ln(6)

        # ── MITRE ATT&CK COVERAGE ──
        if mitre:
            pdf.add_page()
            pdf.set_text_color(233, 69, 96)
            sfont("B", 18)
            pdf.cell(0, 12, "5. MITRE ATT&CK Coverage", ln=True)
            pdf.set_draw_color(233, 69, 96)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(6)
            # Group by tactic
            by_tactic: Dict[str, list] = {}
            for t in mitre:
                tactic = t.get("tactic", "Unknown")
                by_tactic.setdefault(tactic, []).append(t)
            for tactic, techs in by_tactic.items():
                if pdf.get_y() > 260:
                    pdf.add_page()
                sfont("B", 11)
                pdf.set_text_color(233, 69, 96)
                pdf.cell(0, 7, safe(tactic), ln=True)
                for t in techs:
                    sfont("B", 9)
                    pdf.set_text_color(80, 80, 80)
                    pdf.cell(25, 5, safe(t["id"]))
                    sfont("", 9)
                    pdf.cell(0, 5, safe(t["name"], 80), ln=True)
                pdf.ln(4)

        # ── APPENDIX ──
        pdf.add_page()
        pdf.set_text_color(233, 69, 96)
        sfont("B", 18)
        pdf.cell(0, 12, "6. Appendix", ln=True)
        pdf.set_draw_color(233, 69, 96)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(8)

        sfont("B", 12)
        pdf.set_text_color(233, 69, 96)
        pdf.cell(0, 8, "A. Tools Used", ln=True)
        sfont("", 9)
        pdf.set_text_color(80, 80, 80)
        for t in tools:
            pdf.cell(0, 5, safe(f"  - {t}"), ln=True)
        pdf.ln(6)

        sfont("B", 12)
        pdf.set_text_color(233, 69, 96)
        pdf.cell(0, 8, "B. Methodology", ln=True)
        sfont("", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 5, safe(
            "This assessment was conducted using TazoSploit, an AI-driven automated penetration "
            "testing platform. The AI agent autonomously selects tools, executes attacks, and "
            "iterates through the MITRE ATT&CK framework to discover and exploit vulnerabilities. "
            "All testing was performed within the authorized scope."
        ))
        pdf.ln(6)

        sfont("B", 12)
        pdf.set_text_color(233, 69, 96)
        pdf.cell(0, 8, "C. Disclaimer", ln=True)
        sfont("", 9)
        pdf.set_text_color(80, 80, 80)
        pdf.multi_cell(0, 5, safe(
            "This report is confidential and intended solely for the authorized recipient. The "
            "findings represent the security posture at the time of assessment. No guarantee is "
            "made that all vulnerabilities have been identified. Redistribution without "
            "authorization is prohibited."
        ))

        pdf.output(output_path)
        return output_path

    def generate_api_findings(self) -> List[Dict]:
        """
        Generate findings for the API.
        IMPORTANT: Credentials are NOT included here — they go to the credentials table only.
        This prevents the duplicate display issue.
        """
        self.build_attack_chains()
        findings = []
        def _safe_evidence(value) -> str:
            if value is None:
                return ""
            if isinstance(value, str):
                return value
            try:
                return json.dumps(value, indent=2)[:800]
            except Exception:
                return str(value)[:800]
        
        # Vulnerabilities → findings
        for vuln in self.vulnerabilities:
            if self.strict_evidence_only and not self._is_vuln_proven(vuln):
                continue
            findings.append({
                "title": f"{vuln.type} — {vuln.endpoint}",
                "description": vuln.impact,
                "severity": self._vuln_type_to_severity(vuln.type),
                "finding_type": "vulnerability",
                "target": vuln.endpoint,
                "evidence": _safe_evidence(vuln.evidence),
                "proof_of_concept": vuln.payload,
                "extraction_command": vuln.extraction_command,
                "iteration": vuln.iteration,
                "mitre_id": vuln.mitre_id,
            })
        
        # Database access → findings (but NOT as credentials)
        for db in self.database_access:
            if self.strict_evidence_only and not self._is_access_proven(db.extraction_command, db.credentials):
                continue
            findings.append({
                "title": f"Database Access — {db.db_type} @ {db.host}",
                "description": f"Databases: {', '.join(db.databases)}, Tables dumped: {len(db.tables_dumped)}",
                "severity": "critical",
                "finding_type": "database_access",
                "target": db.host,
                "evidence": f"Credentials: {db.credentials}",
                "extraction_command": db.extraction_command,
                "iteration": db.iteration,
            })
        
        # Shell access → findings
        for shell in self.shell_access:
            if self.strict_evidence_only and not self._is_access_proven(shell.extraction_command, shell.method):
                continue
            findings.append({
                "title": f"Shell Access — {shell.type} on {shell.host}",
                "description": f"User: {shell.user}, Method: {shell.method[:100]}",
                "severity": "critical",
                "finding_type": "shell_access",
                "target": shell.host,
                "evidence": shell.method[:500],
                "extraction_command": shell.extraction_command,
                "iteration": shell.iteration,
            })
        
        # Data exfiltration → findings
        for data in self.data_exfiltration:
            if self.strict_evidence_only and not self._is_access_proven(data.extraction_command, data.content_preview):
                continue
            findings.append({
                "title": f"Data Exfiltration — {data.type}",
                "description": f"Size: {data.size}",
                "severity": "high",
                "finding_type": "data_exfiltration",
                "target": data.source[:80],
                "evidence": data.content_preview[:300],
                "extraction_command": data.extraction_command,
                "iteration": data.iteration,
            })
        
        # Attack chains → findings (as a summary finding)
        for chain in self.attack_chains:
            findings.append({
                "title": f"⛓️ Attack Chain: {chain.title}",
                "description": chain.summary,
                "severity": chain.severity,
                "finding_type": "attack_chain",
                "target": "",
                "evidence": json.dumps(chain.steps, indent=2)[:500],
                "steps_count": len(chain.steps),
            })

        # Final dedup pass (defense in depth): keep the "best" record per fingerprint.
        return self._dedup_findings(findings)

    def _dedup_findings(self, findings: List[Dict]) -> List[Dict]:
        severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

        def fp(f: Dict) -> str:
            return hashlib.md5(
                "|".join(
                    [
                        str(f.get("finding_type") or ""),
                        str(f.get("title") or ""),
                        str(f.get("target") or ""),
                        str(f.get("proof_of_concept") or ""),
                        str(f.get("extraction_command") or ""),
                    ]
                ).lower().encode()
            ).hexdigest()

        best: Dict[str, Dict] = {}
        for f in findings or []:
            key = fp(f)
            cur = best.get(key)
            if not cur:
                best[key] = f
                continue
            cur_rank = severity_rank.get(str(cur.get("severity") or "").lower(), 0)
            new_rank = severity_rank.get(str(f.get("severity") or "").lower(), 0)
            if new_rank > cur_rank:
                best[key] = f
                continue
            if new_rank == cur_rank:
                # Prefer richer evidence when severity ties.
                if len(str(f.get("evidence") or "")) > len(str(cur.get("evidence") or "")):
                    best[key] = f

        return list(best.values())
    
    def _vuln_type_to_severity(self, vuln_type: str) -> str:
        critical = ['Remote Code Execution', 'Command Injection', 'Remote File Inclusion']
        high = ['SQL Injection', 'Local File Inclusion', 'File Upload', 'Directory Traversal',
                'XML External Entity', 'Server-Side Request Forgery', 'Default Credentials',
                'Insecure Direct Object Reference', 'Broken Access Control', 'Mass Assignment',
                'Path Traversal']
        medium = ['Cross-Site Scripting', 'Cross-Site Request Forgery', 'Weak Password']
        
        if vuln_type in critical:
            return "critical"
        elif vuln_type in high:
            return "high"
        elif vuln_type in medium:
            return "medium"
        return "info"
    
    def write_evidence_files(self, output_dir: str):
        """Write structured evidence files to the output directory"""
        import os
        evidence_dir = os.path.join(output_dir, "evidence")
        os.makedirs(evidence_dir, exist_ok=True)
        
        if self.credentials:
            with open(os.path.join(evidence_dir, "credentials.json"), 'w') as f:
                json.dump([asdict(c) for c in self.credentials], f, indent=2)
        
        if self.vulnerabilities:
            with open(os.path.join(evidence_dir, "vulnerabilities.json"), 'w') as f:
                json.dump([asdict(v) for v in self.vulnerabilities], f, indent=2)
        
        # findings.json — for the worker to read
        findings = self.generate_api_findings()
        with open(os.path.join(evidence_dir, "findings.json"), 'w') as f:
            json.dump(findings, f, indent=2)
        
        if self.database_access:
            with open(os.path.join(evidence_dir, "database_access.json"), 'w') as f:
                json.dump([asdict(d) for d in self.database_access], f, indent=2)
        
        if self.attack_chains:
            with open(os.path.join(evidence_dir, "attack_chains.json"), 'w') as f:
                json.dump([asdict(c) for c in self.attack_chains], f, indent=2)

        if self.security_controls:
            with open(os.path.join(evidence_dir, "security_controls.json"), "w") as f:
                json.dump(self.security_controls, f, indent=2)

        # Generate professional HTML and PDF reports
        try:
            html_path = os.path.join(output_dir, "report.html")
            self.generate_html_report(html_path)
        except Exception as e:
            print(f"[report] HTML report generation failed: {e}")

        try:
            pdf_path = os.path.join(output_dir, "report.pdf")
            self.generate_pdf_report(pdf_path)
        except Exception as e:
            print(f"[report] PDF report generation failed (install fpdf2): {e}")

        return evidence_dir
