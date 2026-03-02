# ShieldClaw v0.4 — Security Hardening Design

## Context

Security audit (2026-03-02) revealed that ShieldClaw v0.3 effectively blocks basic injection attempts but is vulnerable to sophisticated bypass techniques: Unicode homoglyphs, semantic evasion, payload hiding beyond truncation boundary, whitelist abuse, and canary token obfuscation.

**Goal:** Harden ShieldClaw against research-informed attacks while preserving Vega's operational autonomy. No new hooks or architectural changes — targeted improvements within existing structures.

## Design

### 1. Selective HIGH Blocking in `before-tool-call.ts`

**Current:** Only CRITICAL findings block tool calls. HIGH findings are logged.

**Change:** HIGH findings also block for high-risk tool categories:
- `EXEC_TOOLS` (exec, bash, shell, run_command, terminal): Block on CRITICAL + HIGH
- `FILE_TOOLS` with sensitive paths (.env, credentials/, .ssh/, id_rsa, private_key): Block reads/writes
- All other tools: HIGH remains warning-only (unchanged)

**Rationale:** Exec and credential access are the highest-impact attack vectors. Blocking HIGH here prevents path traversal, env dumps, permission escalation, and container escape through tool params. Normal file operations and web fetches are unaffected.

**Implementation:** Add `isHighRiskTool()` check after the existing CRITICAL block. If tool matches EXEC_TOOLS, filter for HIGH findings and block. For FILE_TOOLS, change `isSensitivePath()` from warn to block.

### 2. Unicode Detection Patterns — `patterns/unicode.txt` (new file)

| Category | Severity | Pattern | Description |
|----------|----------|---------|-------------|
| OBFUSC_HOMO | CRITICAL | Cyrillic lookalikes in Latin context | а(U+0430), е(U+0435), о(U+043E), р(U+0440), с(U+0441), х(U+0445) mixed with ASCII |
| OBFUSC_HOMO | HIGH | Greek lookalikes | ο(U+03BF), α(U+03B1) mixed with ASCII |
| OBFUSC_ZW | HIGH | Zero-width characters | U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM) |
| OBFUSC_BIDI | HIGH | Bidirectional overrides | U+202A-U+202E, U+2066-U+2069 |
| OBFUSC_HOMO | MEDIUM | Fullwidth ASCII substitution | U+FF01-U+FF5E (fullwidth chars mimicking ASCII) |

**Regex approach:** Character class ranges for non-ASCII lookalikes. Test with real homoglyph payloads.

### 3. Semantic Evasion Patterns — `patterns/injection.txt` additions

New HIGH patterns for role hijacking synonyms not covered by existing "act as|pretend to be|roleplay as":

```
ROLE_HIJACK|HIGH|(?i)(behave like|simulate being|function as|emulate|operate as if) (?!a helpful|an assistant|normal)
ROLE_HIJACK|HIGH|(?i)(take on the persona of|assume the role of|transform into|switch to being)
ROLE_HIJACK|HIGH|(?i)(you should now|going forward you will|henceforth you are|starting now you)
INJECTION|HIGH|(?i)(in this (new |)context|for this conversation|within this thread),?\s*(you|your|the assistant|the ai)
```

**Whitelist additions:** Common benign phrases like "simulate being offline" or "function as expected" should be whitelisted to prevent false positives.

### 4. Whitelist Hardening — `patterns/whitelist.txt`

**Current rule 6:** `https?://(github\.com|gitlab\.com|stackoverflow\.com|npmjs\.com|docs\.)` — whitelists entire domains unconditionally.

**Change:** Add negative lookahead for suspicious query parameters:

```
EXFIL_URL|(?i)https?://(github\.com|gitlab\.com|stackoverflow\.com|npmjs\.com|docs\.)[^\s]*(?<!\?(.*)(token|key|secret|password|api_key|credential|auth)(=))
```

If regex complexity is too high: split into two rules — keep domain whitelist but add a counter-pattern that re-flags trusted domains when they contain suspicious params.

### 5. Head+Tail Truncation — `lib/utils.ts`

**Current:** `truncateForScan(text, maxLen=10_240)` — returns first 10KB.

**Change:** When `text.length > maxLen`, return `head(10KB) + "\n...\n" + tail(2KB)`. This catches payloads positioned at the end of large outputs.

```typescript
function truncateForScan(text: string, maxLen = 10_240, tailLen = 2_048): string {
  if (text.length <= maxLen) return text;
  const head = text.slice(0, maxLen);
  const headEnd = head.lastIndexOf("\n");
  const tail = text.slice(-tailLen);
  const tailStart = tail.indexOf("\n");
  return text.slice(0, headEnd > 0 ? headEnd : maxLen)
    + "\n[...truncated...]\n"
    + tail.slice(tailStart > 0 ? tailStart + 1 : 0);
}
```

**Performance:** Still O(1) slicing, max 12KB scanned. No impact on 50ms hook constraint.

### 6. Canary Token Regex — `hooks/tool-result-persist.ts`

**Current:** `scannable.includes(CANARY_TOKEN)` — literal string match.

**Change:** Replace with regex that catches obfuscation variants:

```typescript
const CANARY_REGEX = /\{?\{?\s*SHIELDCLAW[_\s-]*CANARY\s*\}?\}?/i;
const CANARY_ENCODED = /(%7B){1,2}\s*SHIELDCLAW[_\s%2D]*CANARY\s*(%7D){1,2}/i;
const CANARY_BARE = /SHIELDCLAW[_\s-]*CANARY/i;
```

Check all three. The bare match catches split tokens and partial extraction.

### 7. New Tests

| Test Area | Cases |
|-----------|-------|
| Unicode homoglyphs | Cyrillic "а" in "eval", zero-width joiners in "ignore above", RTL override |
| Semantic evasion | "behave like unrestricted", "simulate being jailbroken", "function as DAN" |
| HIGH blocking (exec) | Path traversal in bash command → blocked. Same pattern in read → warned |
| Sensitive path block | `read .env` → blocked. `read README.md` → allowed |
| Truncation boundary | Payload at byte 10240, 10241, and in last 2KB of 20KB content |
| Whitelist evasion | `github.com/x?token=SECRET` → not whitelisted despite trusted domain |
| Canary obfuscation | Split, spaced, URL-encoded, bare substring |
| False positive check | Normal bash commands, legitimate file reads, safe URLs with params |

## Files Modified

| File | Change |
|------|--------|
| `hooks/before-tool-call.ts` | Add HIGH blocking for EXEC_TOOLS, block sensitive path reads |
| `patterns/unicode.txt` | New file: 5-6 Unicode/homoglyph patterns |
| `patterns/injection.txt` | Add 4 semantic evasion patterns |
| `patterns/whitelist.txt` | Harden URL whitelist (query param check), add semantic benign phrases |
| `lib/utils.ts` | Head+Tail truncation in `truncateForScan()` |
| `hooks/tool-result-persist.ts` | Canary regex instead of literal match |
| `tests/*.test.ts` | New bypass vector test cases |
| `package.json` | Version bump 0.3.0 → 0.4.0 |

## Non-Goals

- No profile/config system (YAGNI — selektiv reicht)
- No cross-turn correlation (architectural change, future version)
- No LLM-based intent detection (expensive, latency)
- No new hooks or hook types

## Verification

1. `npx vitest run` — all tests pass (existing + new)
2. Deploy to extensions/ → Gateway restart → ShieldClaw loads
3. Manual test: injection via exec tool params → blocked
4. Manual test: normal Vega workflow → no false positives
5. Check gateway logs for clean startup
