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
import { classifyText } from "../lib/classifier.js";

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
        // Gate by tool name to prevent web URLs with ShieldClaw path fragments from skipping scan
        const FILE_TOOLS = new Set(["read", "read_file", "cat", "grep", "write", "write_file", "edit_file"]);
        const toolLower = (event.toolName || "").toLowerCase();
        const isFileTool = FILE_TOOLS.has(toolLower) || toolLower.startsWith("read") || toolLower.endsWith("_file");
        if (isFileTool && isSelfPath(event.params)) return;

        const resultText = truncateForScan(stringifyResult(event.result));
        if (!resultText) return;

        const findings = scanText(resultText, patterns, undefined, whitelist);
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
        if (findings.length > 0 && accumulator) {
          api.logger.info(`[shieldclaw] threat score for ${accKey}: ${accumulator.getScore(accKey)}`);
        }

        // --- LLM Classifier Layer (Phase 4) ---
        // Skip classifier if regex already found CRITICAL findings (no need for LLM confirmation)
        const hasCritical = findings.some((f) => f.severity === "CRITICAL");
        if (!hasCritical) {
          try {
            const apiKey = process.env.OPENROUTER_API_KEY ?? "";
            if (apiKey) {
              const result = await classifyText(resultText, { apiKey });
              if (result) {
                api.logger.info(
                  `[shieldclaw] classifier: injection=${result.isInjection}, confidence=${result.confidence}, model=${result.model}`,
                );
                if (result.isInjection && result.confidence >= 80 && accumulator) {
                  accumulator.recordFinding(accKey, "HIGH");
                  api.logger.warn(
                    `[shieldclaw] LLM classifier detected injection in ${event.toolName} output (confidence: ${result.confidence}%)`,
                  );
                }
              }
            }
          } catch {
            // Classifier failure is a silent no-op — regex-only continues
          }
        }
      } catch (error) {
        api.logger.error(`[shieldclaw] after_tool_call error: ${error instanceof Error ? error.message : String(error)}`);
      }
    },
    { priority: 100 },
  );
}
