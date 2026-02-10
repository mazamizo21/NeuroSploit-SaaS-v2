# Tasks: 008 Context Summarization (Smart Memory)

**Input**: spec.md + plan.md
**Target File**: `kali-executor/open-interpreter/dynamic_agent.py`

## Phase 1: Digest Infrastructure (MVP)

- [ ] T001 [US-2] Add `DIGEST_SUMMARIZATION_PROMPT` constant at module level (near line ~80):
  - Structured template with sections: SERVICES, VULNERABILITIES, CREDENTIALS, COMMANDS TRIED, FAILED APPROACHES, CURRENT PROGRESS
  - Placeholder `{conversation_text}` for message content
  - Instruction to keep ≤3000 chars and preserve all credentials verbatim

- [ ] T002 [US-1] Add state variables to `__init__` (near line ~380):
  - `self.context_digest = ""`
  - `self.context_digest_path = os.path.join(self.log_dir, "context_digest.md")`
  - `self.max_digest_chars = int(os.getenv("MAX_DIGEST_CHARS", "4000"))`
  - `self.digest_trim_count = 0`
  - Load persisted digest from disk if exists

- [ ] T003 [US-1] Add `_save_digest(self)` method:
  - Write `self.context_digest` to `self.context_digest_path`
  - Wrap in try/except (never crash on save failure)

- [ ] T004 Test: Verify state variables initialize correctly, digest file read/write works

**Checkpoint**: Digest infrastructure in place

## Phase 2: Summarization Engine

- [ ] T005 [US-1] Add `_summarize_for_digest(self, messages: List[Dict]) -> str` method:
  - Flatten messages into condensed text: `"[role]: content[:200]"` per message
  - Cap total input at ~4000 chars (truncate oldest messages if needed)
  - Build prompt from `DIGEST_SUMMARIZATION_PROMPT` template
  - Make LLM call via `self.llm.chat()` with separate conversation, max_tokens=512, temperature=0
  - Set 30-second timeout on the call
  - Return the LLM's response text
  - On any failure (timeout, error, empty response): call `_rule_based_digest_extraction(messages)` instead
  - Log: "DIGEST: LLM summarization completed" or "DIGEST: Fell back to rule-based extraction"

- [ ] T006 [US-1] Add `_rule_based_digest_extraction(self, messages: List[Dict]) -> str` method:
  - Scan all message content for:
    - Credentials: regex `r'(\w+):(\S+)\s*@\s*(\S+)'`, `password`, `token`, `JWT`, `Bearer`, `api[_-]?key`
    - Services: regex `r'(\d+)/tcp\s+open\s+(\S+)'` (nmap output)
    - Vulns: keywords `vulnerability`, `injection`, `xss`, `traversal`, `rce`, `VULN TRACKED`
    - Failures: keywords `error`, `failed`, `timeout`, `exit code`, `not found`
  - Build structured output with same section headers as LLM template
  - Append current `self.vulns_found` state to VULNERABILITIES section
  - Cap at 3000 chars

- [ ] T007 Test: Verify LLM summarization produces valid structured output; verify fallback works when LLM is unavailable

**Checkpoint**: Can summarize old messages into structured digest

## Phase 3: Digest Merge & Persistence

- [ ] T008 [US-3] Add `_merge_digest(self, existing_digest: str, new_summary: str) -> str` method:
  - Parse both strings into sections by splitting on `## ` headers
  - For each section: merge bullet points from new into existing
  - Deduplication: skip lines that are exact matches (case-insensitive strip comparison)
  - CREDENTIALS section: always keep ALL entries (never prune)
  - VULNERABILITIES section: replace with authoritative data from `self.vulns_found`
  - FAILED APPROACHES: keep all (growing list is valuable)
  - COMMANDS TRIED: keep last 20 entries, prune oldest when over limit
  - SERVICES: keep all but prune duplicates
  - Reassemble sections in order
  - If total > `max_digest_chars`: prune COMMANDS TRIED (oldest first) → SERVICES (least recent) → CURRENT PROGRESS
  - Never prune CREDENTIALS, VULNERABILITIES, or FAILED APPROACHES

- [ ] T009 [US-3] Add vuln_tracker auto-inclusion to `_merge_digest`:
  - After section merge, rebuild VULNERABILITIES from `self.vulns_found`:
    ```
    - [type] at [target] — [proven|attempted|unproven] (attempts: N, techniques: [...])
    ```
  - This ensures VULNERABILITIES is always authoritative regardless of LLM summary quality

- [ ] T010 Test: Verify merge correctly accumulates across 3+ trims, deduplicates, respects caps

**Checkpoint**: Digest accumulates correctly across multiple trims

## Phase 4: Context Pack Integration

- [ ] T011 [US-4] Modify context pack logic (lines 2710-2760):
  - Before trimming: extract `old_messages = self.conversation[1:-20]`
  - Call `new_summary = self._summarize_for_digest(old_messages)`
  - Call `self.context_digest = self._merge_digest(self.context_digest, new_summary)`
  - Increment `self.digest_trim_count`
  - Call `self._save_digest()`
  - Build trimmed conversation: system_msg → digest message → evidence summary → recent 20
  - Digest message: `"**ACCUMULATED INTELLIGENCE (auto — trim #{N})**\n\n{digest}"`
  - Wrap entire summarization block in try/except (never crash the main loop)

- [ ] T012 [US-4] Modify `_reset_conversation()` (line ~597):
  - After building reset conversation, inject digest as second message if `self.context_digest` exists
  - Label: `"**ACCUMULATED INTELLIGENCE (preserved through reset)**"`

- [ ] T013 [US-4] Modify session resume block (lines 2624-2660):
  - After building trimmed conversation, inject digest as second message if `self.context_digest` exists
  - Label: `"**ACCUMULATED INTELLIGENCE (from previous session)**"`

- [ ] T014 Test: Run job, observe context trim → digest injected → agent references prior findings

**Checkpoint**: Digest flows through all context management paths

## Phase 5: Polish & Validation

- [ ] T015 Verify digest stays within `MAX_CONTEXT_CHARS` budget when combined with recent messages:
  - System prompt (~2K) + digest (~4K) + evidence (~1.5K) + 20 messages (~10K) = ~17.5K < 20K cap
  - If over budget, reduce `recent` from 20 to 15 messages

- [ ] T016 Verify digest works with session resume (start job → kill → resume → verify digest loaded)

- [ ] T017 Run full Juice Shop job, measure:
  - How many times credentials are rediscovered (target: ≤2, baseline: 15+)
  - How many times same failed approach is repeated (target: ≤3, baseline: 8+)
  - Total iterations to achieve same number of proven exploits

- [ ] T018 Document changes in commit message referencing spec 008

## Dependencies

- T001 → T005 (prompt template needed for summarization)
- T002, T003 → T005, T006 (state vars needed)
- T005, T006 → T008 (summarization needed before merge)
- T008, T009 → T011 (merge needed before context pack integration)
- T011 → T012, T013 (context pack first, then reset and resume)
- Phase 5 depends on all above
- Spec 006 (`_get_exploit_templates_for_vuln()`) is not required but complements this
- Spec 010 (arsenal) will build on top of the digest infrastructure
