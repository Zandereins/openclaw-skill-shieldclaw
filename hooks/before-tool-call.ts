/**
 * ShieldClaw — before_tool_call Hook
 *
 * Scans tool parameters before execution.
 * Blocks CRITICAL findings, logs HIGH/MEDIUM.
 * Priority 200 (runs before other plugins).
 */

import { scanText, hasCritical, filterBySeverity } from "../lib/pattern-engine.js";
import type { PatternEntry, PluginLogger } from "../lib/types.js";
import { extractStringValues, isSelfPath } from "../lib/utils.js";

/** Tools whose primary parameter is a URL. */
const URL_TOOLS = new Set(["web_fetch", "fetch", "http_get", "http_post", "mcp_fetch"]);

/** Tools that execute commands. */
const EXEC_TOOLS = new Set(["exec", "bash", "shell", "run_command", "terminal"]);

/** Tools that access files. */
const FILE_TOOLS = new Set(["read", "write", "read_file", "write_file", "edit_file"]);

/** Sensitive paths that should never be accessed via tool calls from untrusted content. */
const SENSITIVE_PATHS = [
  "/etc/shadow",
  "/etc/passwd",
  ".env",
  "credentials",
  ".ssh/",
  "id_rsa",
  "private_key",
  "secret",
];

/**
 * Extract the primary URL from tool parameters.
 */
function extractUrl(params: Record<string, unknown>): string | undefined {
  for (const key of ["url", "uri", "href", "endpoint"]) {
    if (typeof params[key] === "string") return params[key] as string;
  }
  return undefined;
}

/**
 * Extract the primary command from exec tool parameters.
 */
function extractCommand(params: Record<string, unknown>): string | undefined {
  for (const key of ["command", "cmd", "script", "code"]) {
    if (typeof params[key] === "string") return params[key] as string;
  }
  return undefined;
}

/**
 * Extract the file path from file tool parameters.
 */
function extractPath(params: Record<string, unknown>): string | undefined {
  for (const key of ["path", "file", "file_path", "filepath", "filename"]) {
    if (typeof params[key] === "string") return params[key] as string;
  }
  return undefined;
}

/**
 * Check if a file path targets sensitive locations.
 */
function isSensitivePath(filePath: string): boolean {
  const normalized = filePath.toLowerCase();
  return SENSITIVE_PATHS.some((s) => normalized.includes(s));
}

/**
 * Check tool name against known tool sets (case-insensitive, partial match).
 */
function matchesTool(toolName: string, toolSet: Set<string>): boolean {
  const lower = toolName.toLowerCase();
  for (const t of toolSet) {
    if (lower === t || lower.includes(t)) return true;
  }
  return false;
}

type BeforeToolCallEvent = {
  toolName: string;
  params: Record<string, unknown>;
};

type BeforeToolCallResult = {
  block?: boolean;
  blockReason?: string;
};

type HookApi = {
  logger: PluginLogger;
  on: (
    hookName: string,
    handler: (event: BeforeToolCallEvent, ctx: unknown) => Promise<BeforeToolCallResult | void>,
    opts?: { priority?: number },
  ) => void;
};

export function registerBeforeToolCall(api: HookApi, patterns: PatternEntry[]): void {
  api.on(
    "before_tool_call",
    async (event) => {
      const { toolName, params } = event;

      // Skip scanning when reading/writing ShieldClaw's own files
      if (isSelfPath(params)) return;

      // Collect all text to scan
      const textsToScan: string[] = [];

      // Tool-specific parameter extraction
      if (matchesTool(toolName, URL_TOOLS)) {
        const url = extractUrl(params);
        if (url) textsToScan.push(url);
      }

      if (matchesTool(toolName, EXEC_TOOLS)) {
        const cmd = extractCommand(params);
        if (cmd) textsToScan.push(cmd);
      }

      if (matchesTool(toolName, FILE_TOOLS)) {
        const filePath = extractPath(params);
        if (filePath && isSensitivePath(filePath)) {
          api.logger.warn(
            `[shieldclaw] Sensitive path access attempted: ${filePath} via ${toolName}`,
          );
          // Don't block file reads — the agent may legitimately need them.
          // Just log for awareness.
        }
      }

      // Generic: extract all string values from params
      textsToScan.push(...extractStringValues(params));

      // Scan all collected text
      const combined = textsToScan.join("\n");
      if (!combined) return;

      const findings = scanText(combined, patterns, 10_240);
      if (findings.length === 0) return;

      // Block on CRITICAL findings
      const criticals = filterBySeverity(findings, "CRITICAL").filter(
        (f) => f.severity === "CRITICAL",
      );
      if (criticals.length > 0) {
        const reason = `ShieldClaw blocked ${toolName}: ${criticals[0].description} [${criticals[0].category}]`;
        api.logger.warn(`[shieldclaw] BLOCKED: ${reason}`);
        return { block: true, blockReason: reason };
      }

      // Log HIGH and MEDIUM findings
      for (const finding of findings) {
        if (finding.severity === "HIGH") {
          api.logger.warn(
            `[shieldclaw] ${finding.severity} in ${toolName} params: ${finding.description} [${finding.category}]`,
          );
        } else {
          api.logger.info(
            `[shieldclaw] ${finding.severity} in ${toolName} params: ${finding.description} [${finding.category}]`,
          );
        }
      }

      return;
    },
    { priority: 200 },
  );
}
