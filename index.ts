/**
 * ShieldClaw — OpenClaw Plugin Entry Point
 *
 * Prompt injection defense hooks for OpenClaw agents.
 * Loads pattern database at startup and registers security hooks.
 *
 * Hooks:
 * - before_tool_call: Scans tool parameters, blocks CRITICAL threats
 * - tool_result_persist: Injects warnings into suspicious tool outputs (SYNC)
 * - after_tool_call: Telemetry logging for tool output analysis
 * - message_sending: Exfiltration prevention in outgoing messages
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadPatterns, loadWhitelist } from "./lib/pattern-engine.js";
import { registerBeforeToolCall } from "./hooks/before-tool-call.js";
import { registerToolResultPersist } from "./hooks/tool-result-persist.js";
import { registerAfterToolCall } from "./hooks/after-tool-call.js";
import { registerMessageSending } from "./hooks/message-sending.js";

// Resolve plugin root directory from this file's location
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

type PluginApi = {
  resolvePath: (input: string) => string;
  logger: {
    info: (message: string) => void;
    warn: (message: string) => void;
    error: (message: string) => void;
  };
  on: (hookName: string, handler: (...args: unknown[]) => unknown, opts?: { priority?: number }) => void;
};

const plugin = {
  id: "shieldclaw",
  name: "ShieldClaw",
  description: "Prompt injection defense hooks for OpenClaw agents",
  version: "0.3.0",

  register(api: PluginApi) {
    // Use __dirname to resolve patterns relative to this plugin's location
    const patternsDir = path.join(__dirname, "patterns");
    const patterns = loadPatterns(patternsDir);
    const whitelist = loadWhitelist(patternsDir);

    if (patterns.length === 0) {
      api.logger.warn("[shieldclaw] No patterns loaded — hooks will not detect threats");
      return;
    }

    registerBeforeToolCall(api as Parameters<typeof registerBeforeToolCall>[0], patterns);
    registerToolResultPersist(api as Parameters<typeof registerToolResultPersist>[0], patterns);
    registerAfterToolCall(api as Parameters<typeof registerAfterToolCall>[0], patterns);
    registerMessageSending(api as Parameters<typeof registerMessageSending>[0], patterns);

    api.logger.info(
      `[shieldclaw] v0.3.0 active: ${patterns.length} patterns loaded, ${whitelist.length} whitelist rules, 4 hooks registered`,
    );
  },
};

export default plugin;
