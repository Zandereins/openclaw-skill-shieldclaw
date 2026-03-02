/**
 * ShieldClaw utility functions for string extraction and content processing.
 */

/** Maximum bytes to scan from a single tool output. */
export const MAX_SCAN_LENGTH = 10_240;

/**
 * Path fragments that identify ShieldClaw's own files.
 * Tool outputs from reading these paths are excluded from scanning
 * to prevent false positives from example attack patterns in docs.
 */
const SELF_PATH_FRAGMENTS = [
  "skills/shieldclaw/",
  "extensions/shieldclaw/",
  "openclaw-skill-shieldclaw/",
];

/**
 * Check if a tool call targets ShieldClaw's own files.
 * Returns true if the path matches known ShieldClaw locations.
 */
export function isSelfPath(params: Record<string, unknown>): boolean {
  for (const key of ["path", "file", "file_path", "filepath", "filename", "url"]) {
    const val = params[key];
    if (typeof val === "string") {
      for (const fragment of SELF_PATH_FRAGMENTS) {
        if (val.includes(fragment)) return true;
      }
    }
  }
  return false;
}

/**
 * Simple deduplication cache for findings.
 * Prevents the same finding from being logged multiple times within a short window.
 * Uses a Map with auto-expiry (TTL-based).
 */
export class FindingDedup {
  private seen = new Map<string, number>();
  private readonly ttlMs: number;

  constructor(ttlMs: number = 5_000) {
    this.ttlMs = ttlMs;
  }

  /** Returns true if this finding was already seen within the TTL window. */
  isDuplicate(key: string): boolean {
    const now = Date.now();
    // Clean expired entries (max 100 to avoid unbounded growth)
    if (this.seen.size > 100) {
      for (const [k, ts] of this.seen) {
        if (now - ts > this.ttlMs) this.seen.delete(k);
      }
    }
    const prev = this.seen.get(key);
    if (prev && now - prev < this.ttlMs) return true;
    this.seen.set(key, now);
    return false;
  }
}

/**
 * Truncate text to a maximum scan length using head+tail strategy.
 * For large content: scans first maxLen bytes + last tailLen bytes.
 * This catches payloads hidden beyond the head truncation boundary.
 */
export function truncateForScan(
  text: string,
  maxLen: number = MAX_SCAN_LENGTH,
  tailLen: number = 2_048,
): string {
  if (text.length <= maxLen) return text;
  // Head: cut at nearest newline
  const headEnd = text.lastIndexOf("\n", maxLen);
  const head = text.slice(0, headEnd > 0 ? headEnd : maxLen);
  // Tail: start at nearest newline
  const tailStart = text.indexOf("\n", text.length - tailLen);
  const tail = text.slice(tailStart > 0 ? tailStart + 1 : text.length - tailLen);
  return head + "\n[...truncated...]\n" + tail;
}

/**
 * Recursively extract all string values from a nested object.
 * Used to scan tool parameters regardless of structure.
 */
export function extractStringValues(obj: unknown, depth: number = 0): string[] {
  if (depth > 10) return []; // prevent infinite recursion
  if (typeof obj === "string") return [obj];
  if (Array.isArray(obj)) {
    return obj.flatMap((item) => extractStringValues(item, depth + 1));
  }
  if (obj !== null && typeof obj === "object") {
    return Object.values(obj).flatMap((val) => extractStringValues(val, depth + 1));
  }
  return [];
}

/**
 * Convert an unknown tool result to a scannable string.
 */
export function stringifyResult(result: unknown): string {
  if (typeof result === "string") return result;
  if (result === null || result === undefined) return "";
  try {
    return JSON.stringify(result);
  } catch {
    return String(result);
  }
}

/**
 * Extract text content from an AgentMessage for scanning.
 * Handles the message.content array structure used by OpenClaw.
 */
export function extractMessageText(message: unknown): string {
  if (!message || typeof message !== "object") return "";

  const msg = message as Record<string, unknown>;

  // Direct string content
  if (typeof msg.content === "string") return msg.content;

  // Array of content blocks (OpenClaw AgentMessage format)
  if (Array.isArray(msg.content)) {
    const parts: string[] = [];
    for (const block of msg.content) {
      if (typeof block === "string") {
        parts.push(block);
      } else if (block && typeof block === "object") {
        const b = block as Record<string, unknown>;
        // Text block
        if (typeof b.text === "string") parts.push(b.text);
        // Tool result block
        if (typeof b.content === "string") parts.push(b.content);
        // Nested content array
        if (Array.isArray(b.content)) {
          for (const inner of b.content) {
            if (typeof inner === "string") parts.push(inner);
            else if (inner && typeof inner === "object" && typeof (inner as Record<string, unknown>).text === "string") {
              parts.push((inner as Record<string, unknown>).text as string);
            }
          }
        }
      }
    }
    return parts.join("\n");
  }

  return "";
}

/**
 * Prepend a warning to an AgentMessage's content.
 * Preserves the message structure, only modifies text content.
 */
export function prependWarningToMessage(message: unknown, warning: string): unknown {
  if (!message || typeof message !== "object") return message;

  const msg = { ...(message as Record<string, unknown>) };

  if (typeof msg.content === "string") {
    msg.content = `${warning}\n\n${msg.content}`;
    return msg;
  }

  if (Array.isArray(msg.content) && msg.content.length > 0) {
    const newContent = [...msg.content];
    const first = newContent[0];

    if (typeof first === "string") {
      newContent[0] = `${warning}\n\n${first}`;
    } else if (first && typeof first === "object") {
      const block = { ...(first as Record<string, unknown>) };
      if (typeof block.text === "string") {
        block.text = `${warning}\n\n${block.text}`;
      } else if (typeof block.content === "string") {
        block.content = `${warning}\n\n${block.content}`;
      }
      newContent[0] = block;
    }

    msg.content = newContent;
    return msg;
  }

  return msg;
}
