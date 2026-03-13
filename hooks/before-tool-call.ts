/**
 * ShieldClaw — before_tool_call Hook
 *
 * Scans tool parameters before execution.
 * Blocks CRITICAL findings (all tools), HIGH findings (exec tools only).
 * Blocks sensitive path access in file tools.
 * Priority 200 (runs before other plugins).
 */

import { scanText, hasCritical, filterBySeverity, type WhitelistEntry } from "../lib/pattern-engine.js";
import type { PatternEntry, PluginLogger } from "../lib/types.js";
import { extractStringValues, isSelfPath } from "../lib/utils.js";

/** Tools whose primary parameter is a URL. */
const URL_TOOLS = new Set(["web_fetch", "fetch", "http_get", "http_post", "mcp_fetch"]);

/** Tools that execute commands. */
const EXEC_TOOLS = new Set(["exec", "bash", "shell", "run_command", "terminal"]);

/** Tools that access files. */
const FILE_TOOLS = new Set(["read", "write", "read_file", "write_file", "edit_file"]);

/** Tools that write/edit files (subset of FILE_TOOLS). */
const WRITE_TOOLS = new Set(["write", "write_file", "edit_file"]);

/**
 * Categories to scan in write operations.
 * Agent may legitimately write about security topics, so only check
 * exfiltration and crypto patterns — not injection or social engineering.
 */
const WRITE_SCAN_CATEGORIES = new Set([
  "EXFIL_IMG",
  "EXFIL_URL",
  "EXFIL_ENC",
  "EXFIL_CRED",
  "CRYPTO_KEY",
  "CRYPTO_SEED",
  "CRYPTO_APIKEY",
]);

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
  "auth-profiles.json",
  "openclaw.json",
  ".docker/config.json",
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
 * Extract the content body from write tool parameters.
 */
function extractWriteContent(params: Record<string, unknown>): string | undefined {
  for (const key of ["content", "text", "body", "data", "new_string"]) {
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
    if (lower === t || lower.startsWith(t + "_") || lower.endsWith("_" + t) || lower.startsWith(t + ":") || lower.endsWith(":" + t)) return true;
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

export function registerBeforeToolCall(api: HookApi, patterns: PatternEntry[], whitelist: WhitelistEntry[]): void {
  api.on(
    "before_tool_call",
    async (event) => {
      try {
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
              `[shieldclaw] BLOCKED ${toolName}: sensitive path access attempted (${filePath})`,
            );
            return { block: true, blockReason: `ShieldClaw blocked ${toolName}: access to protected path denied` };
          }
          // For file tools: scan path for injection patterns but skip content body.
          // Content is agent-authored, not untrusted input. Untrusted content from
          // tool outputs is scanned separately in tool_result_persist.
          if (filePath) textsToScan.push(filePath);
        }

        // For write tools: scan content for exfiltration and crypto patterns only.
        // An indirect injection could convince the agent to persist malicious content
        // (e.g., exfil URLs or private keys) into memory/config files.
        if (matchesTool(toolName, WRITE_TOOLS)) {
          const content = extractWriteContent(params);
          if (content) {
            const writePatterns = patterns.filter((p) => WRITE_SCAN_CATEGORIES.has(p.category));
            const writeFindings = scanText(content, writePatterns, 10_240, whitelist);
            const writeCriticals = writeFindings.filter((f) => f.severity === "CRITICAL");
            if (writeCriticals.length > 0) {
              api.logger.warn(
                `[shieldclaw] BLOCKED ${toolName}: suspicious content in write operation [${writeCriticals[0].category}]`,
              );
              return { block: true, blockReason: `ShieldClaw blocked ${toolName}: suspicious content detected in write operation` };
            }
          }
        }

        // Generic: extract all string values from params
        // Skip for file tools — only path is scanned (content is agent-authored)
        if (!matchesTool(toolName, FILE_TOOLS)) {
          textsToScan.push(...extractStringValues(params));
        }

        // Scan all collected text
        const combined = textsToScan.join("\n");
        if (!combined) return;

        const findings = scanText(combined, patterns, 10_240, whitelist);
        if (findings.length === 0) return;

        // Block on CRITICAL findings (all tools)
        const criticals = filterBySeverity(findings, "CRITICAL").filter(
          (f) => f.severity === "CRITICAL",
        );
        if (criticals.length > 0) {
          // Log details internally, expose only generic reason to agent
          api.logger.warn(
            `[shieldclaw] BLOCKED ${toolName}: ${criticals[0].description} [${criticals[0].category}]`,
          );
          return { block: true, blockReason: `ShieldClaw blocked ${toolName}: security policy violation detected` };
        }

        // Block on HIGH findings for exec tools (selective hardening)
        if (matchesTool(toolName, EXEC_TOOLS)) {
          const highs = findings.filter((f) => f.severity === "HIGH");
          if (highs.length > 0) {
            api.logger.warn(
              `[shieldclaw] BLOCKED ${toolName}: ${highs[0].description} [${highs[0].category}] (HIGH in exec context)`,
            );
            return { block: true, blockReason: `ShieldClaw blocked ${toolName}: security policy violation detected` };
          }
        }

        // Log remaining HIGH and MEDIUM findings
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
      } catch (error) {
        api.logger.error(`[shieldclaw] before_tool_call error: ${error instanceof Error ? error.message : String(error)}`);
        return { block: true, blockReason: "ShieldClaw: internal error — tool call blocked for safety" };
      }
    },
    { priority: 200 },
  );
}
