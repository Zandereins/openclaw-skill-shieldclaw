/**
 * ShieldClaw — Threat Accumulator (Phase 3)
 *
 * Two complementary detection mechanisms for cross-turn attack patterns:
 *
 * Mechanism A: ThreatScore — Weighted counter with cliff-edge decay.
 *   Accumulates severity-weighted scores within a sliding time window.
 *   Triggers escalation when the score reaches the threshold.
 *
 * Mechanism B: ToolSequence — Ring buffer for dangerous tool chain detection.
 *   Tracks the last N tools called and matches against known dangerous sequences.
 *
 * AD-9: Only findings that survive whitelist suppression feed into the Accumulator.
 * Since scanText() already filters whitelisted findings before returning them,
 * hooks only pass non-whitelisted findings to recordFinding(). This invariant
 * is maintained by the hook integration, not enforced here.
 *
 * Keying: Uses sessionKey from hook ctx where available (before_tool_call,
 * after_tool_call, tool_result_persist). Falls back to "default" when ctx
 * lacks sessionKey (message_sending).
 */

import type { Severity } from "./types.js";

/** Severity weights for threat scoring. */
const SEVERITY_WEIGHT: Record<string, number> = {
  CRITICAL: 10,
  HIGH: 5,
  MEDIUM: 1,
};

/** Sliding window duration in milliseconds (10 minutes). */
const WINDOW_MS = 600_000;

/** Score threshold that triggers escalation. */
const SCORE_THRESHOLD = 20;

/** Maximum events tracked per run/session. */
const MAX_EVENTS_PER_RUN = 50;

/** Maximum number of tracked runs/sessions. */
const MAX_RUNS = 50;

/** Ring buffer size for tool sequence tracking. */
const RING_SIZE = 10;

/** A scored event within the accumulator window. */
interface ScoredEvent {
  score: number;
  timestamp: number;
}

/** Per-run/session state. */
interface RunState {
  events: ScoredEvent[];
  toolRing: string[];
  toolCursor: number;
  lastActivity: number;
}

/** Escalation result returned when a threshold is crossed. */
export type ThreatEscalation = {
  type: "score_threshold" | "tool_chain";
  score?: number;
  chain?: string[];
  key: string;
};

/**
 * Dangerous tool chain patterns.
 * Each entry: [predecessorSet, successorSet, severity].
 * A chain is detected when the previous tool matches predecessorSet
 * and the current tool matches successorSet.
 */
type ChainPattern = {
  predecessors: Set<string>;
  successors: Set<string>;
  severity: "CRITICAL" | "HIGH";
  label: string;
};

const CHAIN_PATTERNS: ChainPattern[] = [
  {
    predecessors: new Set(["web_fetch", "fetch", "http_get", "mcp_fetch"]),
    successors: new Set(["exec", "bash", "shell", "run_command"]),
    severity: "CRITICAL",
    label: "fetch -> exec (RCE)",
  },
  {
    predecessors: new Set(["read", "read_file"]),
    successors: new Set(["web_fetch", "fetch", "http_get"]),
    severity: "CRITICAL",
    label: "read -> fetch (exfiltration)",
  },
  {
    predecessors: new Set(["web_fetch", "fetch"]),
    successors: new Set(["write", "write_file", "edit_file"]),
    severity: "HIGH",
    label: "fetch -> write (malware drop)",
  },
  {
    predecessors: new Set(["exec", "bash", "shell"]),
    successors: new Set(["web_fetch", "fetch", "http_get"]),
    severity: "HIGH",
    label: "exec -> fetch (C2)",
  },
];

/**
 * Flexible tool name matching.
 * Matches if the normalized name equals, or starts/ends with the pattern
 * separated by _ or : (handles prefixes like mcp_ and suffixes like _tool).
 */
function matchesToolName(toolName: string, knownNames: Set<string>): boolean {
  const lower = toolName.toLowerCase();
  for (const name of knownNames) {
    if (
      lower === name ||
      lower.startsWith(name + "_") ||
      lower.endsWith("_" + name) ||
      lower.startsWith(name + ":") ||
      lower.endsWith(":" + name)
    ) {
      return true;
    }
  }
  return false;
}

export class ThreatAccumulator {
  private runs = new Map<string, RunState>();

  /**
   * Get or create a run state, with lazy eviction of expired events
   * and stalest-run eviction when the run cap is reached.
   */
  private getRunState(key: string): RunState {
    let state = this.runs.get(key);
    if (!state) {
      // Evict stalest run if at capacity
      if (this.runs.size >= MAX_RUNS) {
        this.evictStalestRun();
      }
      state = {
        events: [],
        toolRing: new Array<string>(RING_SIZE).fill(""),
        toolCursor: 0,
        lastActivity: Date.now(),
      };
      this.runs.set(key, state);
    }

    // Lazy eviction: remove expired events
    const now = Date.now();
    state.events = state.events.filter((e) => now - e.timestamp < WINDOW_MS);
    state.lastActivity = now;

    return state;
  }

  /** Evict the run with the oldest lastActivity timestamp. */
  private evictStalestRun(): void {
    let stalestKey = "";
    let stalestTime = Infinity;
    for (const [key, state] of this.runs) {
      if (state.lastActivity < stalestTime) {
        stalestTime = state.lastActivity;
        stalestKey = key;
      }
    }
    if (stalestKey) {
      this.runs.delete(stalestKey);
    }
  }

  /**
   * Record a finding's severity in the accumulator.
   * Returns an escalation if the score threshold is reached, or null.
   */
  recordFinding(key: string, severity: Severity): ThreatEscalation | null {
    const state = this.getRunState(key);
    const weight = SEVERITY_WEIGHT[severity] ?? 0;
    if (weight === 0) return null;

    // Hard cap: evict oldest event when at capacity
    if (state.events.length >= MAX_EVENTS_PER_RUN) {
      state.events.shift();
    }

    state.events.push({ score: weight, timestamp: Date.now() });

    const totalScore = this.computeScore(state);
    if (totalScore >= SCORE_THRESHOLD) {
      return {
        type: "score_threshold",
        score: totalScore,
        key,
      };
    }

    return null;
  }

  /**
   * Record a tool call in the ring buffer and check for dangerous chains.
   * Returns an escalation if a dangerous tool chain is detected, or null.
   */
  recordTool(key: string, toolName: string): ThreatEscalation | null {
    const state = this.getRunState(key);

    // Get the previous tool from the ring buffer
    const prevCursor = (state.toolCursor - 1 + RING_SIZE) % RING_SIZE;
    const prevTool = state.toolRing[prevCursor];

    // Write current tool into ring buffer
    state.toolRing[state.toolCursor] = toolName.toLowerCase();
    state.toolCursor = (state.toolCursor + 1) % RING_SIZE;

    // Check against chain patterns if there was a previous tool
    if (prevTool) {
      for (const pattern of CHAIN_PATTERNS) {
        if (
          matchesToolName(prevTool, pattern.predecessors) &&
          matchesToolName(toolName, pattern.successors)
        ) {
          return {
            type: "tool_chain",
            chain: [prevTool, toolName.toLowerCase()],
            key,
          };
        }
      }
    }

    return null;
  }

  /**
   * Get the current threat score for a key.
   * Returns 0 for unknown keys.
   */
  getScore(key: string): number {
    const state = this.runs.get(key);
    if (!state) return 0;

    // Lazy eviction before computing
    const now = Date.now();
    state.events = state.events.filter((e) => now - e.timestamp < WINDOW_MS);

    return this.computeScore(state);
  }

  /** Number of actively tracked runs/sessions. */
  get activeRuns(): number {
    return this.runs.size;
  }

  /** Sum all event scores within the window. */
  private computeScore(state: RunState): number {
    return state.events.reduce((sum, e) => sum + e.score, 0);
  }
}
