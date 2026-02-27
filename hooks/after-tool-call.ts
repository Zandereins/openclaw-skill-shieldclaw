/**
 * ShieldClaw — after_tool_call Hook
 *
 * Telemetry and logging for tool output analysis.
 * Fire-and-forget, parallel execution — cannot block anything.
 * Provides audit trail of detected threats in tool outputs.
 *
 * Priority 100 (lower than blocking hooks).
 */

import { scanText } from "../lib/pattern-engine.js";
import type { PatternEntry, PluginLogger } from "../lib/types.js";
import { stringifyResult, truncateForScan } from "../lib/utils.js";

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

export function registerAfterToolCall(api: HookApi, patterns: PatternEntry[]): void {
  api.on(
    "after_tool_call",
    async (event) => {
      if (!event.result) return;

      const resultText = truncateForScan(stringifyResult(event.result));
      if (!resultText) return;

      const findings = scanText(resultText, patterns);
      if (findings.length === 0) return;

      for (const finding of findings) {
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
    },
    { priority: 100 },
  );
}
