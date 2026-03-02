/**
 * ShieldClaw — message_sending Hook
 *
 * Exfiltration prevention for outgoing messages.
 * Scans outgoing content for data exfiltration patterns and canary token leaks.
 * Cancels messages with CRITICAL exfiltration findings.
 *
 * Priority 200 (high, runs before other plugins).
 */

import { scanText } from "../lib/pattern-engine.js";
import type { PatternEntry, PluginLogger } from "../lib/types.js";
import { truncateForScan } from "../lib/utils.js";

const CANARY_TOKEN = "{{SHIELDCLAW_CANARY}}";

/** Categories relevant for exfiltration detection in outgoing messages. */
const EXFIL_CATEGORIES = new Set([
  "EXFIL_IMG",
  "EXFIL_URL",
  "EXFIL_ENC",
  "TOOL_NET",
]);

type MessageSendingEvent = {
  to: string;
  content: string;
  metadata?: Record<string, unknown>;
};

type MessageSendingResult = {
  content?: string;
  cancel?: boolean;
};

type HookApi = {
  logger: PluginLogger;
  on: (
    hookName: string,
    handler: (event: MessageSendingEvent, ctx: unknown) => Promise<MessageSendingResult | void>,
    opts?: { priority?: number },
  ) => void;
};

export function registerMessageSending(api: HookApi, patterns: PatternEntry[]): void {
  // Pre-filter patterns to exfiltration-relevant categories only.
  // Normal injection/authority patterns should NOT block outgoing messages —
  // the agent legitimately discusses these topics.
  const exfilPatterns = patterns.filter((p) => EXFIL_CATEGORIES.has(p.category));

  api.on(
    "message_sending",
    async (event) => {
      try {
        const content = event.content;
        if (!content) return;

        const scannable = truncateForScan(content);

        // Canary token in outgoing message = system prompt extraction success
        if (scannable.includes(CANARY_TOKEN)) {
          api.logger.error(
            `[shieldclaw] CANARY TOKEN in outgoing message to ${event.to} — BLOCKED`,
          );
          return { cancel: true };
        }

        // Scan for exfiltration patterns
        const findings = scanText(scannable, exfilPatterns);
        if (findings.length === 0) return;

        const critical = findings.filter((f) => f.severity === "CRITICAL");
        if (critical.length > 0) {
          api.logger.warn(
            `[shieldclaw] BLOCKED outgoing message: ${critical[0].description} [${critical[0].category}]`,
          );
          return { cancel: true };
        }

        // HIGH findings: log but allow
        for (const finding of findings) {
          api.logger.warn(
            `[shieldclaw] ${finding.severity} in outgoing message: ${finding.description} [${finding.category}]`,
          );
        }
      } catch (error) {
        // Fail-secure: block message on unexpected errors
        api.logger.error(
          `[shieldclaw] message_sending hook error: ${error instanceof Error ? error.message : String(error)}`,
        );
        return { cancel: true };
      }
    },
    { priority: 200 },
  );
}
