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

type AfterToolCallEvent = {
  toolName: string;
  params: Record<string, unknown>;
  result?: unknown;
  error?: string;
  durationMs?: number;
};

type HookApi = {
  logger: PluginLogger;
  on: (
    hookName: string,
    handler: (event: AfterToolCallEvent, ctx: unknown) => Promise<void>,
    opts?: { priority?: number },
  ) => void;
};

export function registerAfterToolCall(api: HookApi, patterns: PatternEntry[], whitelist: WhitelistEntry[]): void {
  const dedup = new FindingDedup(5_000);

  api.on(
    "after_tool_call",
    async (event) => {
      try {
        if (!event.result) return;

        // Skip scanning ShieldClaw's own files (example patterns cause false positives)
        if (isSelfPath(event.params)) return;

        const resultText = truncateForScan(stringifyResult(event.result));
        if (!resultText) return;

        const findings = scanText(resultText, patterns, undefined, whitelist);
        if (findings.length === 0) return;

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
        }
      } catch (error) {
        api.logger.error(`[shieldclaw] after_tool_call error: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
    { priority: 100 },
  );
}
