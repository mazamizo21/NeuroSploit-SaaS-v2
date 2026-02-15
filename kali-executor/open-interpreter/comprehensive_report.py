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
        # Valid: admin@juice-sh.op, bkimminich, test_user1, john.doe, root
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
                "bkimminich", "mc", "jim", "bender", "morty",  # Juice Shop defaults
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
        # Examples: "admin@juice-sh.op / admin123", "user:pass"
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
            'dvwa': 'DVWA', 'admin': 'Admin Panel', 'postgres': 'PostgreSQL',
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

        # JSON API responses (common in Juice Shop): extract {email|username,password} pairs.
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
            r"\$_DVWA\s*\[\s*['\"]db_user['\"]\s*\]\s*=\s*['\"]([^'\"]+)",
        ]
        for up in user_patterns:
            um = re.findall(up, stdout + content, re.IGNORECASE)
            for u in um:
                if len(u) > 1 and not self._is_junk(u):
                    config_usernames['db_user'] = u
        
        pass_patterns = [
            r"\$_DVWA\s*\[\s*['\"]db_password['\"]\s*\]\s*=\s*['\"]([^'\"]*)['\"]",
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
        
        return evidence_dir
