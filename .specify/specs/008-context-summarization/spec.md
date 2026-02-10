# Spec 008: Context Summarization (Smart Memory)

**Feature Branch**: `008-context-summarization`
**Created**: 2026-02-08
**Status**: Draft
**Dependencies**: Enhances Spec 006 (exploit context preservation), feeds Spec 010 (arsenal persistence)

## Problem Statement

When the Dynamic Agent's conversation exceeds 60 messages (configurable via `MAX_CONTEXT_MESSAGES`), the current context pack logic (lines 2710-2760) keeps the system prompt + last 20 messages + a basic `_summarize_evidence()` output. Everything else is **permanently lost**.

### What Gets Lost

1. **Reasoning chains**: Why the agent chose technique A over B, what it learned from output analysis
2. **Failed approaches**: Which payloads/commands were tried and WHY they failed — agent re-tries them
3. **Discovered information**: Service versions, directory structures, API endpoints, parameter names
4. **Exploit progress**: Partial exploitation chains, what step the agent was on before trim
5. **Credentials & tokens**: Found in early iterations, lost after context trim, rediscovered 15+ times
6. **Target intelligence**: Internal IPs found via SSRF, database schemas from SQLi, user lists from IDOR

### Current Implementation (What We're Replacing)

```python
# Lines 2710-2760: Context pack (just trimming)
if len(self.conversation) > max_messages:
    system_msg = self.conversation[0]
    recent = self.conversation[-20:]
    summary_parts = []
    # memory_store context (basic keyword search)
    # _summarize_evidence() — reads JSON files from evidence dir
    # ... that's it. No LLM summarization. No structured digest.
    trimmed = [system_msg, summary_msg] + recent
```

```python
# Lines 2624-2660: Session resume trimming
if len(self.conversation) > 50:
    # Keeps system + last 40 + messages containing [REMEMBER: or "credential"
    # Very crude — misses most important context
```

### Impact

From a 1346-iteration Juice Shop run ($29.39 LLM cost):
- Credentials were rediscovered **15+ times** because they were trimmed from context
- Same SQLi payloads were retried **8+ times** across context trims
- Exploit chains were broken mid-progress when trims occurred
- Estimated **40-60% of iterations were wasted** repeating work the agent had already done

## Goals

1. **Never lose critical findings**: Vulns, credentials, proven exploits, and service maps survive ALL context trims
2. **Preserve failure memory**: Track what didn't work so the agent doesn't repeat failed approaches
3. **Structured digest format**: Use a consistent, parseable format that even weak LLMs can understand
4. **LLM-generated summaries**: Use one LLM call to summarize old messages BEFORE trimming them
5. **Running digest**: Accumulate across multiple trims — each trim enriches the digest, never replaces it
6. **Zero data loss for key artifacts**: Credentials, tokens, access levels are ALWAYS preserved verbatim

## User Stories

### US-1: LLM-Powered Context Summarization

**As a** Dynamic Agent running a long pentest,
**I want** old conversation messages to be summarized by the LLM before being trimmed,
**So that** key findings, reasoning, and progress are preserved in a structured digest.

**Acceptance Criteria:**
- [ ] Before trimming, a single LLM call summarizes messages being removed
- [ ] Summary is stored in `self.context_digest` (persists across trims)
- [ ] Summary follows a structured template (sections for vulns, creds, commands tried, etc.)
- [ ] LLM call uses a simple, structured prompt that works with weak models (GLM 4.7)
- [ ] If LLM summarization fails (timeout, error), fall back to rule-based extraction

### US-2: Structured Digest Format

**As a** Dynamic Agent reading its own digest,
**I want** the digest to be in a consistent, machine-parseable format,
**So that** I can quickly find relevant info without re-parsing free-form text.

**Acceptance Criteria:**
- [ ] Digest has sections: SERVICES, VULNERABILITIES, CREDENTIALS, COMMANDS_TRIED, FAILED_APPROACHES, EXPLOIT_PROGRESS, TARGET_MAP
- [ ] Each section uses bullet points with consistent formatting
- [ ] Credentials are always preserved verbatim (username:password@service)
- [ ] Commands tried include the command AND its outcome (success/fail/partial)
- [ ] Digest is ≤3000 chars to stay within token budget

### US-3: Running Digest Accumulation

**As a** Dynamic Agent experiencing multiple context trims,
**I want** each trim to ENRICH the existing digest rather than replace it,
**So that** information from iteration 1-60 isn't lost when messages 60-120 are summarized.

**Acceptance Criteria:**
- [ ] First trim creates initial digest
- [ ] Subsequent trims merge new summary into existing digest
- [ ] Merge deduplicates (don't list same credential 5 times)
- [ ] Digest grows but is capped at `MAX_DIGEST_CHARS` (default 4000)
- [ ] When digest exceeds cap, oldest low-priority items are pruned (keep creds/vulns, prune failed approaches)

### US-4: Context Pack Integration

**As a** Dynamic Agent with an active digest,
**I want** the digest to be included in every context pack,
**So that** I never start a trimmed conversation without my accumulated knowledge.

**Acceptance Criteria:**
- [ ] Digest is injected as the FIRST user message after system prompt in every context pack
- [ ] Digest is labeled clearly: `**ACCUMULATED INTELLIGENCE (auto)**`
- [ ] Session resume also includes the digest
- [ ] Digest is saved to disk (`context_digest.md` in log_dir) for crash recovery

## Requirements

### Functional Requirements

- **FR-001**: System MUST summarize old messages via LLM before trimming
- **FR-002**: Summary MUST follow structured template with defined sections
- **FR-003**: Summary MUST preserve ALL credentials and tokens verbatim
- **FR-004**: Running digest MUST accumulate across multiple trims
- **FR-005**: Digest MUST be included in every context pack after system prompt
- **FR-006**: Digest MUST be capped at configurable max chars
- **FR-007**: System MUST fall back to rule-based extraction if LLM summarization fails
- **FR-008**: Digest MUST be persisted to disk for crash recovery
- **FR-009**: Vuln tracker state MUST be included in digest automatically (not LLM-dependent)

### Non-Functional Requirements

- **NFR-001**: Summarization LLM call MUST complete within 30 seconds
- **NFR-002**: Digest MUST work with ANY LLM provider (Anthropic, Zhipu/GLM, etc.)
- **NFR-003**: Summarization prompt MUST be ≤500 tokens to work with weak models
- **NFR-004**: Context pack with digest MUST stay under `MAX_CONTEXT_CHARS` budget

## Success Criteria

- **SC-001**: Credential rediscovery drops from 15+ times to ≤2 per run
- **SC-002**: Failed approach repetition drops by ≥70%
- **SC-003**: Agent maintains awareness of discovered vulns across ALL context trims
- **SC-004**: Total wasted iterations decrease by ≥30% in comparable runs
- **SC-005**: LLM cost per proven exploit decreases (fewer wasted iterations)

## Constraints

- ALL changes in `kali-executor/open-interpreter/dynamic_agent.py` only
- Must work with GLM 4.7 (slow, weak LLM) — summarization prompt must be simple
- Must not increase per-iteration LLM cost significantly (one extra call only on trim, not every iteration)
- Must not exceed `MAX_CONTEXT_CHARS` even with digest included
- Must be backward compatible with existing session resume logic
- Digest format must be plain text (no JSON in conversation messages — LLMs handle prose better)
