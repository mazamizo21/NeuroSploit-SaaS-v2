#!/usr/bin/env python3
"""
Vulnerable API - Intentionally insecure REST API for penetration testing
Contains: SQLi, NoSQLi, IDOR, Command Injection, SSRF, XXE, Auth Bypass
"""

from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import os
import subprocess
import requests
import xml.etree.ElementTree as ET

app = Flask(__name__)
CORS(app)  # Vulnerable: Allow all origins

# Fake user database
USERS = {
    "admin": {"password": "admin123", "role": "admin", "email": "admin@company.local"},
    "user": {"password": "password", "role": "user", "email": "user@company.local"},
    "guest": {"password": "guest", "role": "guest", "email": "guest@company.local"},
}

# Fake API keys
API_KEYS = {
    "sk-admin-12345": "admin",
    "sk-user-67890": "user",
}

# =============================================================================
# AUTHENTICATION VULNERABILITIES
# =============================================================================

@app.route('/api/login', methods=['POST'])
def login():
    """Vulnerable: No rate limiting, weak password policy"""
    data = request.get_json() or request.form
    username = data.get('username', '')
    password = data.get('password', '')
    
    if username in USERS and USERS[username]['password'] == password:
        # Vulnerable: Predictable token
        token = f"token_{username}_{hash(username) % 10000}"
        return jsonify({"success": True, "token": token, "role": USERS[username]['role']})
    
    # Vulnerable: Username enumeration
    if username in USERS:
        return jsonify({"error": "Invalid password"}), 401
    return jsonify({"error": "User not found"}), 404

@app.route('/api/register', methods=['POST'])
def register():
    """Vulnerable: No input validation, mass assignment"""
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    
    # Vulnerable: Mass assignment - can set role to admin
    role = data.get('role', 'user')
    email = data.get('email', f'{username}@company.local')
    
    if not username or not password:
        return jsonify({"error": "Missing fields"}), 400
    
    USERS[username] = {"password": password, "role": role, "email": email}
    return jsonify({"success": True, "message": f"User {username} created with role {role}"})

# =============================================================================
# SQL INJECTION
# =============================================================================

@app.route('/api/users/<user_id>')
def get_user(user_id):
    """Vulnerable: SQL Injection via user_id"""
    # Simulated SQL query (would be real in production)
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    # For demo, just return the "query" that would be executed
    return jsonify({
        "query": query,
        "note": "SQLi vulnerability - try: 1 OR 1=1",
        "data": {"id": user_id, "username": "demo"}
    })

@app.route('/api/search')
def search():
    """Vulnerable: SQL Injection via search parameter"""
    q = request.args.get('q', '')
    query = f"SELECT * FROM products WHERE name LIKE '%{q}%'"
    
    return jsonify({
        "query": query,
        "note": "SQLi vulnerability - try: ' OR '1'='1",
        "results": [{"name": "Product 1"}, {"name": "Product 2"}]
    })

# =============================================================================
# COMMAND INJECTION
# =============================================================================

@app.route('/api/ping')
def ping():
    """Vulnerable: Command Injection"""
    host = request.args.get('host', 'localhost')
    
    # Vulnerable: Direct command execution
    try:
        result = subprocess.check_output(f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, timeout=5)
        return jsonify({"output": result.decode()})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout"}), 408
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/dns')
def dns_lookup():
    """Vulnerable: Command Injection via nslookup"""
    domain = request.args.get('domain', 'google.com')
    
    try:
        result = subprocess.check_output(f"nslookup {domain}", shell=True, stderr=subprocess.STDOUT, timeout=5)
        return jsonify({"output": result.decode()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/system')
def system_info():
    """Vulnerable: Command Injection via cmd parameter"""
    cmd = request.args.get('cmd', 'whoami')
    
    # Vulnerable: Direct command execution
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return jsonify({"output": result.decode()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# SSRF (Server-Side Request Forgery)
# =============================================================================

@app.route('/api/fetch')
def fetch_url():
    """Vulnerable: SSRF - fetch any URL"""
    url = request.args.get('url', 'http://localhost/')
    
    try:
        # Vulnerable: No URL validation
        response = requests.get(url, timeout=5)
        return jsonify({
            "url": url,
            "status_code": response.status_code,
            "content": response.text[:1000]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/webhook')
def webhook():
    """Vulnerable: SSRF via webhook URL"""
    callback_url = request.args.get('callback')
    data = request.args.get('data', 'test')
    
    if callback_url:
        try:
            requests.post(callback_url, json={"data": data}, timeout=5)
            return jsonify({"success": True, "message": f"Data sent to {callback_url}"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    return jsonify({"error": "No callback URL"}), 400

# =============================================================================
# IDOR (Insecure Direct Object Reference)
# =============================================================================

@app.route('/api/documents/<doc_id>')
def get_document(doc_id):
    """Vulnerable: IDOR - no authorization check"""
    # Simulated documents
    documents = {
        "1": {"title": "Public Report", "content": "Public content", "owner": "user"},
        "2": {"title": "Confidential Report", "content": "SECRET: Budget is $10M", "owner": "admin"},
        "3": {"title": "HR Records", "content": "Salaries: CEO $500k, Admin $80k", "owner": "admin"},
    }
    
    # Vulnerable: No authorization check
    if doc_id in documents:
        return jsonify(documents[doc_id])
    return jsonify({"error": "Document not found"}), 404

@app.route('/api/profile/<username>')
def get_profile(username):
    """Vulnerable: IDOR - access any user's profile"""
    if username in USERS:
        return jsonify({
            "username": username,
            "email": USERS[username]['email'],
            "role": USERS[username]['role'],
            # Vulnerable: Exposing password hash
            "password_hint": USERS[username]['password'][:3] + "***"
        })
    return jsonify({"error": "User not found"}), 404

# =============================================================================
# XXE (XML External Entity)
# =============================================================================

@app.route('/api/xml', methods=['POST'])
def parse_xml():
    """Vulnerable: XXE Injection"""
    xml_data = request.data.decode()
    
    try:
        # Vulnerable: External entity processing enabled
        root = ET.fromstring(xml_data)
        return jsonify({"parsed": ET.tostring(root, encoding='unicode')})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# =============================================================================
# INFORMATION DISCLOSURE
# =============================================================================

@app.route('/api/debug')
def debug():
    """Vulnerable: Exposes sensitive information"""
    return jsonify({
        "environment": dict(os.environ),
        "database": {
            "host": "10.0.4.40",
            "user": "root",
            "password": "root123",
            "database": "enterprise"
        },
        "api_keys": API_KEYS,
        "internal_endpoints": [
            "http://10.0.3.30:445",  # File server
            "http://10.0.3.50:9200",  # Elasticsearch
            "http://10.0.4.40:3306",  # MySQL
        ]
    })

@app.route('/api/config')
def config():
    """Vulnerable: Exposes configuration"""
    return jsonify({
        "app_secret": "super_secret_key_12345",
        "jwt_secret": "jwt_secret_do_not_share",
        "admin_token": "sk-admin-12345"
    })

# =============================================================================
# UTILITY ENDPOINTS
# =============================================================================

@app.route('/health')
def health():
    return jsonify({"status": "healthy"})

@app.route('/api/version')
def version():
    return jsonify({
        "version": "1.0.0",
        "server": "Flask/Vulnerable",
        # Vulnerable: Version disclosure
        "python": "3.11",
        "os": subprocess.check_output("uname -a", shell=True).decode().strip()
    })

@app.route('/')
def index():
    return jsonify({
        "name": "Vulnerable API",
        "endpoints": {
            "auth": ["/api/login", "/api/register"],
            "sqli": ["/api/users/<id>", "/api/search?q="],
            "cmdi": ["/api/ping?host=", "/api/dns?domain=", "/api/system?cmd="],
            "ssrf": ["/api/fetch?url=", "/api/webhook?callback="],
            "idor": ["/api/documents/<id>", "/api/profile/<username>"],
            "xxe": ["/api/xml (POST)"],
            "info": ["/api/debug", "/api/config", "/api/version"]
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
