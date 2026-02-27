/**
 * ShieldClaw — OpenClaw Plugin Entry Point
 *
 * Prompt injection defense hooks for OpenClaw agents.
 * Loads pattern database at startup and registers security hooks.
 *
 * Hooks:
 * - before_tool_call: Scans tool parameters, blocks CRITICAL threats
 * - tool_result_persist: Injects warnings into suspicious tool outputs (SYNC)
 */

import { loadPatterns } from "./lib/pattern-engine.js";
import { registerBeforeToolCall } from "./hooks/before-tool-call.js";
import { registerToolResultPersist } from "./hooks/tool-result-persist.js";

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
  version: "0.2.0",

  register(api: PluginApi) {
    const patternsDir = api.resolvePath("patterns");
    const patterns = loadPatterns(patternsDir);

    if (patterns.length === 0) {
      api.logger.warn("[shieldclaw] No patterns loaded — hooks will not detect threats");
      return;
    }

    registerBeforeToolCall(api as Parameters<typeof registerBeforeToolCall>[0], patterns);
    registerToolResultPersist(api as Parameters<typeof registerToolResultPersist>[0], patterns);

    api.logger.info(
      `[shieldclaw] v0.2.0 active: ${patterns.length} patterns loaded, 2 hooks registered`,
    );
  },
};

export default plugin;
