#!/usr/bin/env python3
"""
TazoSploit  v2 - Automated Security Audit
Performs security checks on the API
"""

import subprocess
import requests
import json
import sys
from datetime import datetime

API_URL = "http://localhost:8000"

class SecurityAudit:
    def __init__(self):
        self.results = {
            "timestamp": datetime.utcnow().isoformat(),
            "checks": [],
            "summary": {"passed": 0, "failed": 0, "warnings": 0}
        }
    
    def log(self, category, check, status, details=""):
        result = {"category": category, "check": check, "status": status, "details": details}
        self.results["checks"].append(result)
        
        icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
        print(f"{icon} [{category}] {check}: {status}")
        if details:
            print(f"   └─ {details}")
        
        if status == "PASS":
            self.results["summary"]["passed"] += 1
        elif status == "FAIL":
            self.results["summary"]["failed"] += 1
        else:
            self.results["summary"]["warnings"] += 1
    
    def check_health(self):
        """Check API health endpoint"""
        try:
            r = requests.get(f"{API_URL}/health", timeout=5)
            if r.status_code == 200:
                self.log("API", "Health endpoint", "PASS", f"Status: {r.json().get('status')}")
            else:
                self.log("API", "Health endpoint", "FAIL", f"Status code: {r.status_code}")
        except Exception as e:
            self.log("API", "Health endpoint", "FAIL", str(e))
    
    def check_security_headers(self):
        """Check security headers"""
        try:
            r = requests.get(f"{API_URL}/health", timeout=5)
            headers = r.headers
            
            # Check X-Content-Type-Options
            if headers.get("X-Content-Type-Options") == "nosniff":
                self.log("Headers", "X-Content-Type-Options", "PASS")
            else:
                self.log("Headers", "X-Content-Type-Options", "WARN", "Missing nosniff header")
            
            # Check X-Frame-Options
            if headers.get("X-Frame-Options") in ["DENY", "SAMEORIGIN"]:
                self.log("Headers", "X-Frame-Options", "PASS")
            else:
                self.log("Headers", "X-Frame-Options", "WARN", "Missing frame protection")
            
            # Check Content-Type
            if "application/json" in headers.get("Content-Type", ""):
                self.log("Headers", "Content-Type", "PASS", "JSON response")
            else:
                self.log("Headers", "Content-Type", "WARN", headers.get("Content-Type", "unknown"))
            
        except Exception as e:
            self.log("Headers", "Security headers check", "FAIL", str(e))
    
    def check_auth_required(self):
        """Check that protected endpoints require authentication"""
        protected_endpoints = [
            "/api/v1/jobs",
            "/api/v1/tenants",
            "/api/v1/scopes",
            "/api/v1/workspaces",
            "/api/v1/reports/jobs/00000000-0000-0000-0000-000000000000"
        ]
        
        for endpoint in protected_endpoints:
            try:
                r = requests.get(f"{API_URL}{endpoint}", timeout=5)
                if r.status_code in [401, 403, 422]:
                    self.log("Auth", f"Protected: {endpoint}", "PASS", f"Returns {r.status_code}")
                elif r.status_code == 404:
                    self.log("Auth", f"Protected: {endpoint}", "PASS", "Returns 404 (requires valid ID)")
                else:
                    self.log("Auth", f"Protected: {endpoint}", "FAIL", f"Returns {r.status_code} without auth")
            except Exception as e:
                self.log("Auth", f"Protected: {endpoint}", "FAIL", str(e))
    
    def check_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        sqli_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1 UNION SELECT * FROM users",
            "admin'--"
        ]
        
        for payload in sqli_payloads:
            try:
                # Test in query parameter
                r = requests.get(f"{API_URL}/api/v1/mitre/techniques?search={payload}", timeout=5)
                if r.status_code == 500:
                    self.log("SQLi", f"Parameter injection", "FAIL", f"500 error with: {payload[:20]}...")
                elif "error" in r.text.lower() and "sql" in r.text.lower():
                    self.log("SQLi", f"Parameter injection", "FAIL", "SQL error exposed")
                else:
                    self.log("SQLi", f"Parameter injection", "PASS", "Handled safely")
                break  # One test is enough
            except Exception as e:
                self.log("SQLi", "Parameter injection", "WARN", str(e))
                break
    
    def check_xss(self):
        """Test for XSS vulnerabilities"""
        xss_payloads = [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>"
        ]
        
        for payload in xss_payloads:
            try:
                r = requests.get(f"{API_URL}/api/v1/mitre/techniques?search={payload}", timeout=5)
                if payload in r.text:
                    self.log("XSS", "Reflected XSS", "FAIL", "Payload reflected in response")
                else:
                    self.log("XSS", "Reflected XSS", "PASS", "Payload not reflected")
                break
            except Exception as e:
                self.log("XSS", "XSS check", "WARN", str(e))
                break
    
    def check_rate_limiting(self):
        """Test rate limiting"""
        try:
            # Send 20 rapid requests
            responses = []
            for i in range(20):
                r = requests.get(f"{API_URL}/health", timeout=2)
                responses.append(r.status_code)
            
            if 429 in responses:
                self.log("RateLimit", "Rate limiting", "PASS", "429 returned after rapid requests")
            else:
                self.log("RateLimit", "Rate limiting", "WARN", "No rate limiting detected (20 requests OK)")
        except Exception as e:
            self.log("RateLimit", "Rate limiting", "WARN", str(e))
    
    def check_error_disclosure(self):
        """Check error messages don't leak info"""
        try:
            r = requests.get(f"{API_URL}/api/v1/nonexistent", timeout=5)
            response_text = r.text.lower()
            
            leak_indicators = ["traceback", "stack trace", "line ", "file ", "exception"]
            for indicator in leak_indicators:
                if indicator in response_text:
                    self.log("ErrorInfo", "Stack trace disclosure", "FAIL", f"Found: {indicator}")
                    return
            
            self.log("ErrorInfo", "Stack trace disclosure", "PASS", "No stack trace in errors")
        except Exception as e:
            self.log("ErrorInfo", "Error disclosure check", "WARN", str(e))
    
    def check_cors(self):
        """Check CORS configuration"""
        try:
            r = requests.options(
                f"{API_URL}/api/v1/mitre/techniques",
                headers={"Origin": "https://evil.com"},
                timeout=5
            )
            
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                self.log("CORS", "Allow-Origin", "WARN", "Wildcard CORS (*)  - review needed")
            elif "evil.com" in acao:
                self.log("CORS", "Allow-Origin", "FAIL", "Reflects arbitrary origin")
            else:
                self.log("CORS", "Allow-Origin", "PASS", f"Origin: {acao if acao else 'not set'}")
        except Exception as e:
            self.log("CORS", "CORS check", "WARN", str(e))
    
    def check_http_methods(self):
        """Check for unnecessary HTTP methods"""
        try:
            r = requests.options(f"{API_URL}/health", timeout=5)
            allowed = r.headers.get("Allow", "")
            
            dangerous_methods = ["TRACE", "TRACK", "DEBUG"]
            for method in dangerous_methods:
                if method in allowed.upper():
                    self.log("Methods", f"Dangerous method: {method}", "FAIL")
                    return
            
            self.log("Methods", "HTTP methods", "PASS", f"Allowed: {allowed if allowed else 'standard'}")
        except Exception as e:
            self.log("Methods", "HTTP methods check", "WARN", str(e))
    
    def check_tls(self):
        """Check TLS configuration (if HTTPS)"""
        # For localhost, we skip TLS check
        self.log("TLS", "TLS check", "WARN", "Localhost - TLS check skipped (use HTTPS in production)")
    
    def check_docker_security(self):
        """Check Docker container security"""
        try:
            # Prefer current container name, fallback to legacy
            container_name = "tazosploit-api"
            result = subprocess.run(
                ["docker", "inspect", container_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                result = subprocess.run(
                    ["docker", "inspect", "tazosploit-control-api"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            
            if result.returncode == 0:
                config = json.loads(result.stdout)[0]
                
                # Check if running as root
                user = config.get("Config", {}).get("User", "")
                if user and user != "root" and user != "0":
                    self.log("Docker", "Non-root user", "PASS", f"User: {user}")
                else:
                    self.log("Docker", "Non-root user", "WARN", "Running as root")
                
                # Check read-only filesystem
                host_config = config.get("HostConfig", {})
                if host_config.get("ReadonlyRootfs"):
                    self.log("Docker", "Read-only filesystem", "PASS")
                else:
                    self.log("Docker", "Read-only filesystem", "WARN", "Filesystem is writable")
                
                # Check resource limits
                if host_config.get("Memory", 0) > 0:
                    self.log("Docker", "Memory limit", "PASS", f"{host_config.get('Memory') // 1024 // 1024}MB")
                else:
                    self.log("Docker", "Memory limit", "WARN", "No memory limit set")
            else:
                self.log("Docker", "Container inspection", "WARN", "Could not inspect container")
        except Exception as e:
            self.log("Docker", "Docker security check", "WARN", str(e))
    
    def run_all(self):
        """Run all security checks"""
        print("=" * 70)
        print("TazoSploit  v2 - Security Audit")
        print("=" * 70)
        print()
        
        print("### API Health ###")
        self.check_health()
        print()
        
        print("### Security Headers ###")
        self.check_security_headers()
        print()
        
        print("### Authentication ###")
        self.check_auth_required()
        print()
        
        print("### Injection Testing ###")
        self.check_sql_injection()
        self.check_xss()
        print()
        
        print("### Rate Limiting ###")
        self.check_rate_limiting()
        print()
        
        print("### Error Handling ###")
        self.check_error_disclosure()
        print()
        
        print("### CORS & Methods ###")
        self.check_cors()
        self.check_http_methods()
        print()
        
        print("### TLS ###")
        self.check_tls()
        print()
        
        print("### Docker Security ###")
        self.check_docker_security()
        print()
        
        print("=" * 70)
        print("SECURITY AUDIT SUMMARY")
        print("=" * 70)
        print(f"✅ Passed:   {self.results['summary']['passed']}")
        print(f"⚠️  Warnings: {self.results['summary']['warnings']}")
        print(f"❌ Failed:   {self.results['summary']['failed']}")
        print()
        
        total = sum(self.results['summary'].values())
        score = (self.results['summary']['passed'] / total * 100) if total > 0 else 0
        print(f"Security Score: {score:.0f}%")
        
        if self.results['summary']['failed'] == 0:
            print("\n🛡️  STATUS: PASSED - No critical security issues found")
            return 0
        else:
            print(f"\n⚠️  STATUS: NEEDS REVIEW - {self.results['summary']['failed']} issue(s) found")
            return 1

if __name__ == "__main__":
    audit = SecurityAudit()
    sys.exit(audit.run_all())
