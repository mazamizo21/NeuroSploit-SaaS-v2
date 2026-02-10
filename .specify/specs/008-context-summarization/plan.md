# Plan: 008 Context Summarization (Smart Memory)

**Branch**: `008-context-summarization` | **Date**: 2026-02-08 | **Spec**: spec.md

## Summary

Replace the crude context trimming (keep last 20 messages + basic evidence summary) with intelligent LLM-powered summarization. Before trimming, summarize old messages into a structured digest that persists across trims. Include the digest in every context pack so the agent never loses critical findings.

## Technical Context

**Language/Version**: Python 3.11+
**Primary File**: `kali-executor/open-interpreter/dynamic_agent.py` (~4673 lines)
**Key Code Locations**:
- Lines 83-120: `_summarize_evidence()` — current evidence summarizer (reads JSON files)
- Lines 345-460: `__init__` — state variables
- Lines 597-640: `_reset_conversation()` — needs digest injection
- Lines 2624-2660: Session resume trimming — needs digest injection
- Lines 2710-2760: Context pack (current trimming) — PRIMARY CHANGE AREA
**Testing**: Manual E2E via Docker Compose against Juice Shop lab

## Constitution Check

- ✅ Evidence-First Exploitation — preserves proof context across trims
- ✅ No Hardcoded Exploits — digest captures LLM reasoning, not hardcoded paths
- ✅ Separation of Concerns — changes limited to Kali Plane
- ✅ Defense-in-Depth Redaction — credentials in digest are already redacted by existing pipeline

## Changes Required

All changes in `kali-executor/open-interpreter/dynamic_agent.py`:

### 1. New State Variables in `__init__` (line ~380)

```python
# Context summarization (Spec 008)
self.context_digest = ""  # Running structured summary
self.context_digest_path = os.path.join(self.log_dir, "context_digest.md")
self.max_digest_chars = int(os.getenv("MAX_DIGEST_CHARS", "4000"))
self.digest_trim_count = 0  # How many trims have enriched this digest
# Load persisted digest on startup/resume
if os.path.exists(self.context_digest_path):
    try:
        self.context_digest = open(self.context_digest_path).read()[:self.max_digest_chars]
    except Exception:
        pass
```

### 2. Summarization Prompt Template (module-level constant)

```python
DIGEST_SUMMARIZATION_PROMPT = """Summarize the following pentest conversation into a structured intelligence digest.
Use EXACTLY this format:

## SERVICES FOUND
- [service] at [target]:[port] — [version/details]

## VULNERABILITIES
- [vuln type] at [target/endpoint] — [status: unproven/proven/failed]

## CREDENTIALS & TOKENS
- [username]:[password] @ [service/url]
- [token type]: [token value snippet]

## COMMANDS TRIED & RESULTS
- [command summary] → [result: success/fail/partial + key output]

## FAILED APPROACHES (DO NOT RETRY)
- [what was tried] → [why it failed]

## CURRENT PROGRESS
- [what phase we're in, what's next]

Keep each section concise. Preserve ALL credentials and tokens exactly. Maximum 3000 characters total.

CONVERSATION TO SUMMARIZE:
{conversation_text}"""
```

**Design rationale**: The prompt is extremely structured with explicit section headers. Even weak LLMs (GLM 4.7) can follow fill-in-the-blank templates. The sections map directly to what the agent needs to remember.

### 3. New Method: `_summarize_for_digest(self, messages: List[Dict]) -> str`

**Purpose**: Take a list of old messages about to be trimmed, produce a structured summary.

```python
def _summarize_for_digest(self, messages: List[Dict]) -> str:
    """Summarize old messages into structured digest via LLM call."""
```

**Algorithm**:
1. Flatten messages into a condensed text (role: content, truncated to ~4000 chars total)
2. Build summarization prompt from `DIGEST_SUMMARIZATION_PROMPT`
3. Make a single LLM call with low max_tokens (512) and temperature 0
4. Parse response — if it follows the template structure, use it
5. On LLM failure: fall back to `_rule_based_digest_extraction(messages)`

**LLM call**: Uses existing `self.llm.chat()` with a separate conversation (not the main one):
```python
summary_conversation = [
    {"role": "system", "content": "You are a pentest note-taker. Summarize accurately."},
    {"role": "user", "content": prompt}
]
response, usage = self.llm.chat(summary_conversation, max_tokens=512)
```

### 4. New Method: `_rule_based_digest_extraction(self, messages: List[Dict]) -> str`

**Purpose**: Fallback when LLM summarization fails. Extract key data using regex/keyword matching.

```python
def _rule_based_digest_extraction(self, messages: List[Dict]) -> str:
    """Extract key findings from messages using regex patterns. Fallback for LLM failure."""
```

**Extraction rules**:
- Credentials: regex for `username:password`, `admin/password`, `token:`, `JWT`, `Bearer`
- Services: regex for `\d+/tcp\s+open\s+`, nmap output patterns
- Vulns: look for `VULN TRACKED`, `vulnerability`, `injection`, `xss`, `traversal`
- Failed commands: look for `exit code`, `error`, `failed`, `timeout`
- Include vuln_tracker state from `self.vulns_found` (always available, not LLM-dependent)

### 5. New Method: `_merge_digest(self, existing_digest: str, new_summary: str) -> str`

**Purpose**: Merge a new summary into the existing running digest without duplication.

```python
def _merge_digest(self, existing_digest: str, new_summary: str) -> str:
    """Merge new summary into existing digest. Deduplicates and caps size."""
```

**Algorithm**:
1. Parse both existing and new digest into sections (split on `## ` headers)
2. For each section, merge bullet points — skip exact duplicates
3. For CREDENTIALS section: always keep all entries (never prune creds)
4. For FAILED APPROACHES: keep growing (important for avoiding loops)
5. For COMMANDS TRIED: keep last N entries, prune oldest
6. Reassemble and cap at `max_digest_chars`
7. If over cap: prune SERVICES (least critical) → COMMANDS TRIED (keep recent) → CURRENT PROGRESS (regenerated anyway)
8. Never prune CREDENTIALS or VULNERABILITIES

### 6. Modified: Context Pack Logic (lines 2710-2760)

**Current flow**: trim → keep last 20 → add basic evidence summary
**New flow**: summarize old messages → merge into digest → trim → inject digest + keep last 20

```python
if len(self.conversation) > max_messages:
    system_msg = self.conversation[0]
    recent = self.conversation[-20:]
    old_messages = self.conversation[1:-20]  # Messages being trimmed

    # NEW: Summarize before trimming
    try:
        new_summary = self._summarize_for_digest(old_messages)
        self.context_digest = self._merge_digest(self.context_digest, new_summary)
        self.digest_trim_count += 1
        self._save_digest()  # Persist to disk
    except Exception:
        pass  # Digest update failed — proceed with trim anyway

    # Build context pack with digest
    trimmed = [system_msg]

    # Inject digest as first message after system prompt
    if self.context_digest:
        trimmed.append({
            "role": "user",
            "content": f"**ACCUMULATED INTELLIGENCE (auto — trim #{self.digest_trim_count})**\n\n{self.context_digest}"
        })

    # Existing evidence summary (complements digest with latest file-based data)
    evidence_summary = _summarize_evidence(self.log_dir, max_chars=1500)
    if evidence_summary:
        trimmed.append({"role": "user", "content": f"**EVIDENCE FILES**\n{evidence_summary}"})

    trimmed.extend(recent)
    self.conversation = trimmed
```

### 7. Modified: `_reset_conversation()` (line ~597)

After reset, inject digest if available:
```python
if self.context_digest:
    self.conversation.insert(1, {
        "role": "user",
        "content": f"**ACCUMULATED INTELLIGENCE (preserved through reset)**\n\n{self.context_digest}"
    })
```

### 8. Modified: Session Resume (lines 2624-2660)

Include digest in session resume trimming:
```python
if self.context_digest:
    trimmed.insert(1, {
        "role": "user",
        "content": f"**ACCUMULATED INTELLIGENCE (from previous session)**\n\n{self.context_digest}"
    })
```

### 9. New Method: `_save_digest(self)`

```python
def _save_digest(self):
    """Persist digest to disk for crash recovery."""
    try:
        with open(self.context_digest_path, "w") as f:
            f.write(self.context_digest)
    except Exception:
        pass
```

### 10. Vuln Tracker Auto-Inclusion in Digest

The digest merge always appends current vuln_tracker state at the bottom of the VULNERABILITIES section:
```python
# In _merge_digest, after section merge:
vuln_status = []
for vid, v in self.vulns_found.items():
    status = "proven" if v.get("proof") else ("attempted" if v.get("attempted") else "unproven")
    vuln_status.append(f"- {v['type']} at {v['target']} — {status} (attempts: {v.get('attempt_count', 0)})")
# Replace VULNERABILITIES section with vuln_tracker data (authoritative source)
```

## Method Signatures

```python
# New methods
def _summarize_for_digest(self, messages: List[Dict]) -> str:
def _rule_based_digest_extraction(self, messages: List[Dict]) -> str:
def _merge_digest(self, existing_digest: str, new_summary: str) -> str:
def _save_digest(self) -> None:

# Modified methods
def _reset_conversation(self, reason: str, directive: Dict) -> None:  # Add digest injection
# Context pack block in run() main loop  # Add summarize-before-trim
# Session resume block in run()  # Add digest injection
```

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| LLM summarization call slow (adds latency on trim) | Only happens on trim (~every 60 iterations), not every iteration. 30s timeout. |
| LLM produces bad summary (weak model) | Structured template prompt + rule-based fallback |
| Digest grows too large | Hard cap at `MAX_DIGEST_CHARS`, pruning strategy prioritizes creds/vulns |
| Digest + recent messages exceed context window | Budget: system prompt (~2K) + digest (~4K) + 20 messages (~10K) = ~16K, well under 20K cap |
| Summarization prompt too complex for GLM 4.7 | Template is fill-in-the-blank with clear headers — simplest possible structure |
