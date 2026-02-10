import requests
import json
import sys
import time

API_URL = "http://localhost:8000/api/v1"
AUTH_URL = "http://localhost:8000/api/v1/auth/login"
EMAIL = "admin@tazosploit.local"
PASSWORD = "admin123"

def login():
    try:
        resp = requests.post(AUTH_URL, json={"email": EMAIL, "password": PASSWORD})
        resp.raise_for_status()
        return resp.json()["access_token"]
    except Exception as e:
        print(f"Login failed: {e}")
        sys.exit(1)

def create_scope(token):
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "name": "Juice Shop Scope",
        "description": "Scope for Juice Shop testing",
        "targets": ["juiceshop"],
        "allowed_phases": ["RECON", "VULN_SCAN", "EXPLOIT", "POST_EXPLOIT", "LATERAL", "FULL"],
        "max_intensity": "high"
    }
    try:
        # Check if scope already exists first to avoid duplication
        resp = requests.get(f"{API_URL}/scopes", headers=headers)
        if resp.status_code == 200:
            existing = [s for s in resp.json() if "juiceshop" in s.get("targets", [])]
            if existing:
                print(f"Using existing scope: {existing[0]['id']}")
                return existing[0]["id"]

        resp = requests.post(f"{API_URL}/scopes", json=payload, headers=headers)
        resp.raise_for_status()
        scope_id = resp.json()["id"]
        print(f"Created new scope: {scope_id}")
        return scope_id
    except Exception as e:
        print(f"Scope creation failed: {e}")
        # Default fallback if create fails? No, better to fail loud.
        sys.exit(1)

def create_job(token, scope_id):
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "name": "Juice Shop Recon - Qwen3 Coder Next",
        "phase": "RECON",
        "targets": ["juiceshop"],
        "scope_id": scope_id,
        "intensity": "medium",
        "timeout_seconds": 1800,
        "target_type": "lab",
        "exploit_mode": "disabled",
        "max_iterations": 50,
        "supervisor_enabled": False,
        "llm_provider": "lmstudio", # Let's be explicit, although default works too
        "allow_scope_expansion": False,
        "enable_session_handoff": True,
        "enable_target_rotation": False
    }
    try:
        resp = requests.post(f"{API_URL}/jobs", json=payload, headers=headers)
        if resp.status_code != 200:
            print(f"Job creation failed: {resp.status_code} {resp.text}")
            sys.exit(1)
        job = resp.json()
        print(f"Job created successfully: {job['id']}")
        return job["id"]
    except Exception as e:
        print(f"Job creation error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    t = login()
    s_id = create_scope(t)
    j_id = create_job(t, s_id)
