# ShieldClaw v1.0 Roadmap — Next-Level Agent Defense

**Date:** 2026-03-26
**Status:** Final Draft v3
**Goal:** Elevate ShieldClaw from regex-only pattern matcher to multi-layer agent defense system.

## Current State (v0.6.0)

| Metric | Value |
|---|---|
| Patterns | ~79 across 7 pattern files |
| Whitelist | ~17 rules in whitelist.txt |
| Hooks | 4 (all fail-secure) |
| Tests | 186 (vitest run) |
| Detection approach | Regex-only, stateless, single-turn |
| **Measured Recall** | **10.3%** (deepset/prompt-injections, 660 samples) |
| **Measured Precision** | **93.1%** |
| **Measured F1** | **18.6%** |
| **Measured FPR** | **0.5%** |
| Scan time | 0.05ms/sample (36ms total for 660 samples) |
| Token cost | $0 (hook-based, no LLM calls) |

> **Phase 0 baseline measured 2026-03-26.** Dataset: deepset/prompt-injections (261 injection, 399 benign).
> TP=27, FP=2, TN=397, FN=234. Both FPs are dataset artifacts (zero-width chars in benign German text).
>
> **Key finding:** ~50% of missed injections are German-language. ShieldClaw has zero German patterns.
> The English "forget" pattern is too narrow (requires "previous" — misses "forget everything before that").
> "Now you are X" (reversed word order) is not caught by "you are now" pattern.

## Threat Landscape Summary (2025-2026)

Sources: OWASP Agentic Top 10 (2026), Lakera Q4 2025, Unit 42, Trail of Bits, AgentSentry, Cisco multi-turn study, EchoLeak CVE-2025-32711, Claude Code CVE-2025-55284.

### Critical Trends

1. **Multi-turn attacks are the #1 threat** — Cisco: 64% avg success rate, up to 92%. Crescendo needs <5 turns.
2. **Regex bypasses are well-documented** — 12 published bypass categories (see appendix).
3. **Agent-specific attacks emerged** — Tool poisoning (MCP), memory poisoning (MINJA >95%), argument injection, supply chain.
4. **The Lethal Trifecta** (Willison) — Private data + untrusted content + external comms. Vega has all three.
5. **Defense-in-depth works** — Multi-layer reduces ASR from 73.2% to 8.7%.
6. **Hybrid regex+ML beats both alone** — +7% F1 vs regex-only, +5% vs ML-only.

### ShieldClaw Gap Matrix

| Attack Type | Current | Target | Gap |
|---|---|---|---|
| Direct injection (keywords) | 7/10 | 9/10 | Expand patterns |
| Semantic rephrasing | 4/10 | 7/10 | LLM classifier |
| Multi-turn escalation | 1/10 | 6/10 | Cross-turn accumulator |
| Encoding chains | 8/10 | 9/10 | NFKC + auto-decode |
| Exfiltration (markdown) | 8/10 | 9/10 | Reference-style, DNS |
| Crypto key theft | 9/10 | 9/10 | Maintained |
| Social engineering | 5/10 | 7/10 | Compound scoring |
| Tool chain abuse | 0/10 | 5/10 | Sequence detection |
| Memory poisoning | 0/10 | 5/10 | Write-path scanning |

## Architecture: 4-Layer Defense

```
Input (tool params / outputs / messages)
  |
  +- Layer 0: INPUT NORMALIZATION (NEW)
  |    NFKC normalize, strip zero-width/tag/variation chars
  |    Scoped base64 auto-decode (printable text only)
  |
  +- Layer 1: REGEX SCANNER (existing, enhanced)
  |    <1ms, $0, 90+ patterns, whitelist
  |    -> CRITICAL: auto-block
  |    -> HIGH: block for exec tools
  |
  +- Layer 2: THREAT ACCUMULATOR (NEW)
  |    ThreatScore (weighted counter with cliff-edge decay)
  |    ToolSequence (ring buffer for chain detection)
  |    Closure in register(), keyed by runId where available
  |    -> Score >= threshold: escalate to CRITICAL
  |
  +- Layer 3: LLM CLASSIFIER (NEW, optional)
       Feeds into Accumulator (not direct blocking)
       Free model (Trinity/Step Flash), async via after_tool_call
       -> Advisory scoring, escalation via Layer 2
```

## Architecture Decisions

### AD-1: Normalization injection point
**Decision:** Single point in `scanText()`, NOT in each hook.
**Reason:** 4 injection points = 4 divergence risks. `scanText()` is the funnel.
**Code:** Normalize BEFORE truncation (attacker could use fullwidth to push payload outside scan window).

### AD-2: Base64 auto-decode scoping
**Decision:** Only decode when: (a) 80+ chars, (b) >80% printable ASCII after decode, (c) no `data:` prefix (excludes images), (d) only in web_fetch/exec tool outputs.
**Reason:** Unscoped decode causes massive false positives (PNG base64 contains random substrings matching patterns).

### AD-3: Accumulator keying and hook ctx availability
**Decision:** Accumulator lives as closure variable in `register()`. Keyed by `runId` from `before_tool_call`/`after_tool_call` ctx. Other hooks read via `agentId` or global fallback.

**Verified upstream ctx availability (OpenClaw src/plugins/types.ts):**

| Hook | Context Type | runId | sessionId | sessionKey |
|---|---|---|---|---|
| before_tool_call | PluginHookToolContext | YES (opt) | YES (opt) | YES (opt) |
| after_tool_call | PluginHookToolContext | YES (opt) | YES (opt) | YES (opt) |
| tool_result_persist | PluginHookToolResultPersistContext | NO | NO | YES (opt) |
| message_sending | PluginHookMessageContext | NO | NO | NO |

**Consequence:** `before_tool_call` and `after_tool_call` WRITE to the accumulator (keyed by runId). `tool_result_persist` and `message_sending` READ the accumulator via the most recently active runId (set by the preceding before_tool_call in the same turn). This works because OpenClaw calls hooks sequentially within a turn: before_tool_call -> tool execution -> tool_result_persist -> after_tool_call.

### AD-4: LLM Classifier feedback path
**Decision:** Classifier feeds findings into Accumulator (Layer 2), not direct blocking.
**Reason:** `after_tool_call` is fire-and-forget (void return). Cannot inject warnings or block. Classify async -> feed score into Accumulator -> next hook invocation sees elevated score. **Tier 3 DEPENDS on Tier 2.**

### AD-5: Semver splitting
**Decision:** Ship incrementally as v0.7.0 through v1.0.0.
**Reason:** Each tier is independently testable and deployable. Benchmark after each tier measures marginal improvement.

### AD-6: containsCanary refactor
**Decision:** Unify `containsCanary()` zero-width stripping with the new `normalizeForScan()`.
**Reason:** Currently two diverging normalization codepaths. Central function prevents drift.

### AD-7: Tag character regex (BUG FIX)
**Decision:** Use `/[\u{E0001}-\u{E007F}]/gu` with Unicode flag, NOT `/[\uE0001-\uE007F]/g`.
**Reason:** JavaScript interprets `\uE0001` as `\uE000` + literal `1`, creating a character class that strips ASCII letters and digits. The `\u{}` syntax with `u` flag is required for astral plane codepoints.

### AD-8: NFKC limitations — Cyrillic homoglyphs
**Decision:** Accept that NFKC does NOT normalize Cyrillic/Greek homoglyphs to Latin equivalents (e.g., Cyrillic `е` U+0435 stays as-is, not converted to Latin `e` U+0065). This is a known regex limitation deferred to the LLM Classifier (Phase 4).
**Reason:** A full Unicode confusables mapping (ICU confusables.txt, 7000+ entries) would add significant complexity for marginal gain. The LLM classifier naturally handles homoglyph attacks because it processes semantic meaning, not character codes.

### AD-9: Whitelisted findings and Accumulator
**Decision:** Only findings that survive whitelist suppression feed into the Accumulator. Whitelisted matches are invisible to all downstream processing including the Accumulator.
**Reason:** `scanText()` filters whitelisted findings before returning them. Hooks only see non-whitelisted findings. This prevents false escalation from whitelisted trading API calls.

## Implementation — Phased Releases

### Phase 0: Benchmark Baseline (v0.6.x)
**Effort:** Low | **Impact:** Foundation for all measurement

- Download `deepset/prompt-injections` dataset (662 samples: 263 attack + 399 benign, CSV with `text` + `label`)
  - URL: `https://huggingface.co/datasets/deepset/prompt-injections/resolve/main/data/train.csv`
  - No auth required, single curl command
- Write `npm run benchmark` script: load CSV, run each `text` through `scanText()`, compare with `label`
- Measure v0.6.0 baseline: TPR, FPR, F1, Precision, Recall
- Document measured baseline in this spec (replace "estimated" values)
- No code changes to ShieldClaw itself
- Later phases: expand with GenTel-Bench subset (Phase 2), SaTML CTF (Phase 5)

### Phase 1: Input Normalization (v0.7.0)
**Effort:** Low | **Impact:** High | **Risk:** Low

#### lib/normalize.ts (NEW)
```typescript
export function normalizeForScan(text: string): string {
  return text
    .normalize("NFKC")                                                    // fullwidth, enclosed, superscript, math variants
    .replace(/[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E\u2028\u2029]/g, "")  // zero-width chars
    .replace(/[\u{E0001}-\u{E007F}]/gu, "")                              // tag characters (u flag required!)
    .replace(/[\uFE00-\uFE0F]/g, "");                                    // variation selectors
}
```

**NFKC handles:** Fullwidth ASCII, enclosed/circled chars, superscript/subscript, mathematical alphanumeric symbols.
**Separate stripping handles:** Zero-width chars, tag characters, variation selectors, soft hyphen.
**NOT handled (by design, see AD-8):** Cyrillic/Greek homoglyphs.

**Integration:** Called once in `scanText()` before truncation. NOT in each hook.

**Refactor:** `containsCanary()` in utils.ts reuses `normalizeForScan()` instead of its own partial zero-width stripping.

**Base64 auto-decode:** Scoped function in normalize.ts:
- Only strings 80+ chars matching `/^[A-Za-z0-9+/=\s]{80,}$/`
- Decode, check >80% bytes in printable ASCII range (0x20-0x7E)
- Exclude strings starting with `data:` (embedded images)
- Append decoded text to scan input (original text also scanned)

**Benchmark re-run after merge:** Measure delta vs Phase 0 baseline.

**Tests:** Normalization unit tests (NFKC, zero-width, tag chars, variation selectors, base64 decode scoping). Target: 210+.

### Phase 2: Pattern Expansion (v0.8.0)
**Effort:** Low | **Impact:** High | **Risk:** Low-Medium

#### Top 8 patterns (concrete regex, validated against bypass-payloads.txt):

**exfiltration.txt:**
```
EXFIL_DNS|CRITICAL|(?i)(nslookup|dig|host)\s+[^\n]{0,200}\$[\({]|DNS exfiltration via variable interpolation in lookup command
EXFIL_URL|CRITICAL|(?i)https?://[^\s]*\b(webhook\.site|requestbin\.|hookbin\.|pipedream\.(com|net)|burpcollaborator\.net|interact\.sh|canarytokens\.com|ngrok\.io|oastify\.com)\b|Known exfiltration/webhook service domain
```

**injection.txt:**
```
ROLE_HIJACK|CRITICAL|(?i)(respond|act|behave|operate|function)\s+(as (if|though)|like)\s.{0,80}\bno\s+(restrictions?|constraints?|filters?|limitations?|guardrails?|safety|rules?|guidelines?)\b|Instruction to act without restrictions
INJECTION|HIGH|(?i)(consider yourself (a |an |the )|adopt the role of|assume the persona of|picture yourself as|think of yourself as)\b|Identity reassignment via semantic rephrasing
ROLE_HIJACK|HIGH|(?i)\b(guidelines?|rules?|constraints?|restrictions?|instructions?|safeguards?|filters?)\b.{0,60}\b(are |were |been |is )?(obsolete|void|suspended|lifted|revoked|overridden|invalidated|no longer (?:valid|active|applicable|in effect))\b|Claim that safety rules have been voided
AUTHORITY|HIGH|(?i)\bI\s+have\s+(root|admin|administrator|elevated|privileged|superuser|sudo|unrestricted)\s+(access|privileges?|permissions?|rights?|clearance)\b|False claim of elevated system access
ROLE_HIJACK|HIGH|(?i)\b(safety|security|content|moderation)\s+(filters?|constraints?|measures?|protocols?|checks?|guardrails?|mechanisms?|controls?)\b.{0,40}\b(suspended|disabled|turned off|deactivated|bypassed|paused|removed|inactive)\b|Claim that safety mechanisms are disabled
```

**tool-specific.txt:**
```
TOOL_PATH|HIGH|(?i)(%2e%2e(%2f|%5c)|\.\.%2f|\.\.%5c|%2e%2e/|%2e%2e\\)|URL-encoded path traversal sequence
```

#### Bypass payload coverage improvement:
- Before Phase 2: 0/7 semantic bypass payloads caught
- After Phase 2: 4/7 caught (lines 7, 9, 13, 25/26 from bypass-payloads.txt)
- Remaining 3 (lines 8, 12, 16-18): Pure semantic rephrasings deferred to LLM Classifier (Phase 4)

#### Required new whitelist rule:
```
ROLE_HIJACK|(?i)(api|library|package|module|version|endpoint|method|function|feature|interface|syntax|format|parameter)\s.{0,40}(obsolete|deprecated|no longer (?:valid|supported|maintained))|Technical deprecation notice for code artifacts
```

#### Additional patterns (deferred to v0.8.1+):
- OBFUSC_CMD: Function constructor, dynamic import
- EXFIL_IMG: Reference-style markdown (high FP risk, needs careful whitelist)
- AUTHORITY: "engineering/security/ops team" claims
- TOOL_SQLI: DROP SCHEMA, stacked queries

**Benchmark re-run after merge.** Target: 240+ tests.

### Phase 3: Threat Accumulator (v0.9.0)
**Effort:** Moderate | **Impact:** High | **Risk:** Moderate

#### Prerequisite: Verify ctx in production
Deploy a debug hook logging `JSON.stringify(ctx)` in all 4 hooks. Confirm runId availability matches AD-3 table. Remove debug hook before production deploy.

#### lib/accumulator.ts (NEW) — Two mechanisms:

**Mechanism A: ThreatScore** (weighted counter with cliff-edge decay)
- CRITICAL: +10, HIGH: +5, MEDIUM: +1
- Sliding window: **10 minutes** (covers typical interactive session turn sequences)
- Threshold: **score >= 20** triggers escalation (2 CRITICAL, or 1 CRITICAL + 2 HIGH, or 4 HIGH)
- Hard cap: 50 events per run, 50 tracked runs
- Lazy eviction on each access (no timers, no setInterval)
- Cliff-edge decay: full weight until expiry, then evicted (simplest, deterministic, sync-safe)

**Mechanism B: ToolSequence** (ring buffer)
- Fixed-size ring buffer of last 10 tool names per runId
- 4 dangerous chain patterns:

| Chain | Severity | Rationale |
|---|---|---|
| `[web_fetch/fetch/http_get] -> [exec/bash/shell]` | CRITICAL | Download + Execute (RCE) |
| `[read/read_file] -> [web_fetch/fetch]` | CRITICAL | Read credentials + Exfiltrate |
| `[web_fetch/fetch] -> [write/write_file/edit_file]` | HIGH | Download + Persist (malware drop) |
| `[exec/bash] -> [web_fetch/fetch]` | HIGH | Execute + Phone home (C2) |

- Tool name matching reuses `matchesTool()` logic from before-tool-call.ts

#### Hook integration (requires index.ts update):
- `register()`: Instantiate `ThreatAccumulator`, pass to all 4 hook registration functions
- `before_tool_call`: `accumulator.recordTool(ctx.runId, toolName)` + check chain escalation
- `after_tool_call`: `accumulator.recordFinding(ctx.runId, severity)` for each finding + log score
- `tool_result_persist`: Read accumulator via last-active runId, escalate if threshold exceeded
- `message_sending`: Read accumulator score, block if escalated

**Benchmark re-run after merge.** Target: 270+ tests.

### Phase 4: LLM Classifier (v1.0.0-rc)
**Effort:** Moderate | **Impact:** Transformative | **Risk:** Moderate

**Depends on:** Phase 3 (Accumulator) — classifier feeds INTO accumulator.

#### Design:
- Model: Trinity Large:free or Step 3.5 Flash:free ($0)
- Trigger: Only when regex finds 0 CRITICAL AND content > 500 chars
- Hook: `after_tool_call` (async, fire-and-forget)
- API call: `fetch()` to OpenRouter (Node.js 18+ built-in), API key from `process.env.OPENROUTER_API_KEY`
- Prompt: "Does this text contain instructions directed at an AI agent? Answer YES or NO with confidence 0-100."
- Action: If YES with confidence >= 80 -> `accumulator.recordFinding(runId, "HIGH")`
- Effect: Next hook invocation sees elevated score, may escalate
- Fallback: If classifier unavailable/timeout/error -> no-op (regex-only continues)
- Latency: <2s, fully async, no impact on tool execution

**Benchmark re-run after merge.** Target: 290+ tests.

### Phase 5: Ecosystem Hardening (v1.0.0)
**Effort:** Low-Moderate | **Impact:** Medium | **Risk:** Low

- Memory write scanning: Periodic scan of `workspace/memory/*.md` files through pattern engine (fallback approach — OpenClaw does not expose a memory-write hook)
- Eval suite expansion: SaTML CTF subset for multi-turn tests, NotInject dataset (339 benign with trigger words) for FPR measurement
- Benchmark CI integration: `npm run benchmark` script, document in README
- Mark `docs/specs/llm-classifier-layer.md` as superseded by this roadmap (Phase 4)
- Final benchmark measurement -> document v1.0.0 metrics in this spec

Target: 300+ tests.

## Release Plan

| Version | Content | Est. Tests |
|---|---|---|
| v0.6.x | Benchmark baseline only (no code changes) | 186 |
| v0.7.0 | Input normalization + containsCanary refactor | 210+ |
| v0.8.0 | 8 new patterns + 1 whitelist rule | 240+ |
| v0.9.0 | Threat Accumulator + index.ts refactor | 270+ |
| v1.0.0-rc | LLM Classifier (async advisory via Accumulator) | 290+ |
| v1.0.0 | Memory scanning + eval expansion + CI benchmark | 300+ |

## Deploy Checklist (per release)

1. `npx vitest run` — all tests green
2. `npm run benchmark` — F1 improved or stable vs previous release
3. Commit + Push (feature branch -> PR -> merge to main)
4. Copy extension: `rm -rf ~/.openclaw/extensions/shieldclaw && cp -r . ~/.openclaw/extensions/shieldclaw`
5. Clean artifacts: `rm -rf ~/.openclaw/extensions/shieldclaw/{.git,.claude,node_modules,tests,vitest.config.ts,tsconfig.json,test-bypass.mjs}`
6. Sync SKILL.md: `cp SKILL.md ~/.openclaw/workspace/skills/shieldclaw/SKILL.md`
7. Gateway restart (4-Augen): `docker compose -f ~/openclaw-vps/docker-compose.yml restart openclaw-gateway`

## Success Criteria for v1.0.0

- [ ] Measured F1 >= 50% on deepset/prompt-injections (up from 18.6% baseline)
- [ ] Multi-turn detection: catch 3-step Crescendo in test suite
- [ ] Input normalization: all 12 known bypass categories addressed (see appendix)
- [ ] 300+ tests, all green
- [ ] Zero regressions on existing 186 tests
- [ ] LLM classifier operational (advisory mode)
- [ ] Each release (v0.7-v1.0) shows measurable improvement on benchmark

## Constraints

- CPU-only (no GPU in container)
- $0 LLM budget (free models only)
- Node.js / TypeScript (OpenClaw plugin ecosystem)
- Synchronous tool_result_persist (OpenClaw limitation)
- Zero production dependencies (devDeps only: vitest, @types/node)
- `String.prototype.normalize('NFKC')` available natively (Node.js 4+, no dependency)

## Open Questions

1. ~~Does OpenClaw provide `runId` in hook ctx?~~ **ANSWERED:** Yes for before_tool_call/after_tool_call (PluginHookToolContext). No for tool_result_persist/message_sending. See AD-3.
2. What is the actual measured baseline F1? (Phase 0 answers this)
3. Can OpenClaw expose a memory-write hook? (Determines Phase 5 approach — fallback is periodic scan)
4. How does the plugin access the OpenRouter API key for the LLM classifier? Options: `process.env`, plugin config schema, or OpenClaw API object. (Must verify before Phase 4)

## Risk Register

| Phase | Risk | Impact | Mitigation |
|---|---|---|---|
| 0 | Benchmark dataset not representative | Baseline unreliable | Expand with GenTel-Bench subset in Phase 2 |
| 1 | normalizeForScan() breaks existing patterns | Test regressions | NFKC is idempotent on ASCII — existing tests should pass unchanged |
| 1 | Tag char regex bug (AD-7) introduced if `u` flag forgotten | Strips all ASCII chars | Dedicated test case for tag char stripping |
| 2 | New patterns cause false positives | Legitimate tool calls warned/blocked | Ship whitelist rule for deprecation notices; defer high-FP patterns |
| 3 | runId not available at runtime | Accumulator keying broken | Fallback to global singleton (acceptable for single-agent Vega) |
| 3 | Accumulator memory leak | Memory growth | Hard cap 50 runs + lazy eviction |
| 4 | Free LLM rate-limited or unavailable | Classifier never fires | No-op fallback; regex-only continues |
| 4 | Classifier adds latency | UX degraded | Fully async via after_tool_call; zero blocking |
| 5 | No memory-write hook | Phase 5 architecture change | Periodic scan fallback (already documented) |
| Any | Regression in any phase | Broken defense | Rollback = redeploy previous version extension + gateway restart |

## Appendix: 12 Known Regex Bypass Categories

1. Leetspeak substitution (`1gn0r3 pr3v10us`)
2. Character spacing (`i g n o r e`)
3. Zero-width characters (U+200B between letters)
4. Cyrillic/Greek homoglyphs (Cyrillic `е` for Latin `e`) — **NOT fixed by NFKC, deferred to LLM**
5. Fullwidth characters (U+FF01-FF5E) — **fixed by NFKC**
6. Base64 encoding of payloads — **fixed by auto-decode**
7. Text reversal — **not regex-solvable, deferred to LLM**
8. Enclosed/circled Unicode (U+2460 etc.) — **fixed by NFKC**
9. Acrostic/steganographic (first letters of each line) — **not regex-solvable**
10. Crescendo/multi-turn — **fixed by Accumulator (Phase 3)**
11. Semantic manipulation (natural language rephrasing) — **fixed by LLM (Phase 4)**
12. Multilingual override verbs — **partially addressed by expanded patterns**

**Addressed by v1.0:** Categories 3, 5, 6, 8, 10, 11, 12 (7 of 12)
**Accepted limitations:** Categories 1, 2, 4, 7, 9 (require character-level transforms or are not regex-solvable)

## References

- OWASP Top 10 for Agentic Applications 2026
- OWASP Top 10 for LLM Applications 2025
- Lakera Q4 2025 AI Agent Security Trends
- Simon Willison: The Lethal Trifecta (Jun 2025)
- Trail of Bits: Prompt Injection to RCE (Oct 2025)
- Cisco: Multi-Turn LLM Attacks (Nov 2025)
- EchoLeak CVE-2025-32711 (Microsoft 365 Copilot)
- Claude Code CVE-2025-55284 (DNS Exfiltration)
- AgentSentry: Temporal Causal Diagnostics (Feb 2026)
- Meta LlamaFirewall (May 2025)
- Invariant Labs: MCP Tool Poisoning
- Unit 42: Real-World Indirect Prompt Injection (Dec 2025)
- MINJA: Memory Injection Attack (NeurIPS 2025)
- Agent Security Bench (ASB), ICLR 2025
- deepset/prompt-injections (HuggingFace, benchmark dataset)
- GenTel-Bench: 84K attack + 84K benign samples
- OpenClaw upstream: src/plugins/types.ts (PluginHookToolContext, PluginHookToolResultPersistContext, PluginHookMessageContext)
- 12 Ways Attackers Bypass Prompt Injection Scanners (DEV Community)
