/**
 * ShieldClaw — after_tool_call Hook
 *
 * Telemetry and logging for tool output analysis.
 * Fire-and-forget, parallel execution — cannot block anything.
 * Provides audit trail of detected threats in tool outputs.
 *
 * Priority 100 (lower than blocking hooks).
 */

import { scanText, type WhitelistEntry } from "../lib/pattern-engine.js";
import type { PatternEntry, PluginLogger } from "../lib/types.js";
import { stringifyResult, truncateForScan, isSelfPath, FindingDedup } from "../lib/utils.js";
import type { ThreatAccumulator } from "../lib/accumulator.js";

type AfterToolCallEvent = {
  toolName: string;
  params: Record<string, unknown>;
  result?: unknown;
  error?: string;
  durationMs?: number;
};

type AfterToolCallContext = {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  toolName?: string;
  toolCallId?: string;
};

type HookApi = {
  logger: PluginLogger;
  on: (
    hookName: string,
    handler: (event: AfterToolCallEvent, ctx: AfterToolCallContext) => Promise<void>,
    opts?: { priority?: number },
  ) => void;
};

export function registerAfterToolCall(api: HookApi, patterns: PatternEntry[], whitelist: WhitelistEntry[], accumulator?: ThreatAccumulator): void {
  const dedup = new FindingDedup(5_000);

  api.on(
    "after_tool_call",
    async (event, ctx) => {
      try {
        if (!event.result) return;

        // Skip scanning ShieldClaw's own files (example patterns cause false positives)
        if (isSelfPath(event.params)) return;

        const resultText = truncateForScan(stringifyResult(event.result));
        if (!resultText) return;

        const findings = scanText(resultText, patterns, undefined, whitelist);
        if (findings.length === 0) return;

        const accKey = ctx?.sessionKey ?? "default";

        for (const finding of findings) {
          const dedupKey = `${event.toolName}:${finding.category}:${finding.severity}`;
          if (dedup.isDuplicate(dedupKey)) continue;

          if (finding.severity === "MEDIUM") {
            api.logger.info(
              `[shieldclaw] ${finding.severity} in ${event.toolName} output: ${finding.description} [${finding.category}]`,
            );
          } else {
            api.logger.warn(
              `[shieldclaw] ${finding.severity} in ${event.toolName} output: ${finding.description} [${finding.category}]`,
            );
          }

          // Feed finding into accumulator for cross-turn detection
          if (accumulator) {
            accumulator.recordFinding(accKey, finding.severity);
          }
        }

        // Log current threat score for observability
        if (accumulator) {
          api.logger.info(`[shieldclaw] threat score for ${accKey}: ${accumulator.getScore(accKey)}`);
        }
      } catch (error) {
        api.logger.error(`[shieldclaw] after_tool_call error: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
    { priority: 100 },
  );
}
