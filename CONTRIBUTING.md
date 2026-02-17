# Contributing to TazoSploit

## The #1 Rule: NO Target-Specific Logic

TazoSploit is a **general-purpose SaaS pentest platform**. It must work against ANY target using general penetration testing knowledge only.

### What this means:

**NEVER** add code that:
- References specific vulnerable applications by name (Juice Shop, DVWA, DVNA, WebGoat, Metasploitable, HackTheBox machines, etc.)
- Hardcodes default credentials for specific applications
- Contains exploit paths specific to a known vulnerable app
- Detects specific application signatures to trigger special behavior
- Uses knowledge of a specific app's architecture to "cheat"

**ALWAYS** write code that:
- Uses general pentest techniques that work against any target
- Discovers application behavior dynamically (fingerprinting, probing, fuzzing)
- Detects vulnerability patterns generically (e.g., "HTML response to API endpoint" not "Juice Shop returns HTML")
- Lets the LLM agent figure out target-specific details on its own

### The Test

Before committing any fix, ask yourself:

> "If I replaced the target with a completely unknown web application, would this code still make sense?"

If the answer is NO, you're writing target-specific logic. Rewrite it to be general.

### Examples

❌ **BAD** — Target-specific:
```python
# Juice Shop returns HTML for unknown paths
if "<title>owasp juice shop" in response:
    mark_as_false_positive()
```

✅ **GOOD** — General:
```python
# SPA frameworks may return HTML index pages for unknown API paths
if looks_like_html_page(response) and expected_json_or_api:
    mark_as_false_positive()
```

❌ **BAD** — Hardcoded credentials:
```python
KNOWN_USERS = ["bkimminich", "mc", "jim", "bender", "morty"]  # Juice Shop defaults
```

✅ **GOOD** — Dynamic discovery:
```python
# Agent discovers credentials through enumeration, brute force, or data leaks
```

❌ **BAD** — Target-specific hint in agent prompt:
```python
# Juice Shop login SQLi is typically JSON POST
hint = "Try JSON POST for login endpoint"
```

✅ **GOOD** — General technique:
```python
# Agent determines request format by observing the application's behavior
# (Content-Type headers, form structure, API responses)
```

### CI Enforcement

The `scripts/lint_no_target_specific.sh` script runs on every commit and will FAIL if it finds target-specific references in production source code. Test files and the vulnerable-lab directory are excluded.

### Why This Matters

This is a commercial SaaS product. If a customer finds hardcoded exploit paths for Juice Shop in our code, it destroys credibility. Our agent must demonstrate genuine pentest capability, not scripted attacks against known targets.

## Test Targets

We use Juice Shop, DVWA, and other vulnerable apps for **testing only**. References to these are fine in:
- `tests/` directory
- `vulnerable-lab/` directory  
- Test launcher scripts (`launch_*_test.py`, `run_*_test.py`)
- Benchmark configs (`scripts/learning/`)
- Docker compose files

They are **NOT fine** in:
- `kali-executor/open-interpreter/` (the agent brain)
- `control-plane/` (the API)
- `frontend/src/` (the UI)
- Any production code that ships to customers
