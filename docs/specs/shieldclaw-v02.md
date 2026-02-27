# ShieldClaw v0.2 Specification — Phase 1

## Goal

Transform ShieldClaw from a passive SKILL.md-only defense into an active OpenClaw plugin with hook-based threat detection. Zero additional token overhead at runtime.

## Requirements

### Functional
1. Load existing pattern database (patterns/*.txt) at plugin startup
2. Scan tool parameters via `before_tool_call` hook — block CRITICAL, log HIGH/MEDIUM
3. Scan tool output via `tool_result_persist` hook — inject warnings into persisted messages
4. Detect canary token leakage (`{{SHIELDCLAW_CANARY}}`) in tool outputs
5. Enhanced SKILL.md with multi-step and social engineering awareness
6. Maintain backward compatibility — SKILL.md works standalone without hooks

### Non-Functional
- Hook execution < 50ms per call
- Pattern scan truncated to 10KB max input
- No external dependencies (Node.js stdlib only)
- Synchronous pattern loading at startup (fs.readFileSync)
- `tool_result_persist` handler MUST be synchronous (no Promises)

## Hook Signatures (from OpenClaw types.ts)

### before_tool_call
```typescript
// Event
type PluginHookBeforeToolCallEvent = {
  toolName: string;
  params: Record<string, unknown>;
};

// Result
type PluginHookBeforeToolCallResult = {
  params?: Record<string, unknown>;  // modified params
  block?: boolean;                    // block the tool call
  blockReason?: string;               // reason shown to agent
};

// Context
type PluginHookToolContext = {
  agentId?: string;
  sessionKey?: string;
  toolName: string;
};
```
- Execution: async, sequential, priority-ordered (higher first)
- Merge strategy: first non-undefined result wins per field

### tool_result_persist
```typescript
// Event
type PluginHookToolResultPersistEvent = {
  toolName?: string;
  toolCallId?: string;
  message: AgentMessage;      // message about to be written to session
  isSynthetic?: boolean;
};

// Result
type PluginHookToolResultPersistResult = {
  message?: AgentMessage;     // modified message
};

// Context
type PluginHookToolResultPersistContext = {
  agentId?: string;
  sessionKey?: string;
  toolName?: string;
  toolCallId?: string;
};
```
- Execution: SYNCHRONOUS, sequential, priority-ordered
- WARNING: Returning a Promise is detected and IGNORED by OpenClaw

## Pattern File Format

```
# Comment lines start with #
CATEGORY|SEVERITY|REGEX_PATTERN|DESCRIPTION
```

- CATEGORY: string identifier (e.g., ROLE_HIJACK, EXFIL_IMG)
- SEVERITY: CRITICAL | HIGH | MEDIUM
- REGEX_PATTERN: Perl-compatible regex (flags applied via inline modifiers like (?i))
- DESCRIPTION: Human-readable finding description

## Design Decisions

1. **Plugin + Skill dual-use**: The repo serves as both an OpenClaw plugin (index.ts → hooks) and a skill (SKILL.md → LLM awareness). This provides defense-in-depth.

2. **Priority 200**: ShieldClaw hooks run at high priority to scan before other plugins can modify tool parameters.

3. **CRITICAL blocks, others log**: Only CRITICAL severity findings block tool calls. HIGH and MEDIUM are logged but allowed, to minimize false-positive disruption.

4. **Warning injection over content removal**: `tool_result_persist` prepends a warning to the message rather than removing content. This preserves information while alerting the LLM.

5. **Truncation at 10KB**: Tool outputs can be very large. Scanning is truncated to prevent performance degradation. Most injection payloads appear early in content.

## Open Questions (Phase 2)

- Whitelist mechanism for known false positives
- `message_sending` hook for exfiltration prevention
- Pattern expansion (social engineering, tool-specific)
- Interactive trainer mode
