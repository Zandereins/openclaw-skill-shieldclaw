/**
 * ShieldClaw Input Normalization Layer (Phase 1)
 *
 * Provides Unicode normalization and encoding detection to prevent
 * bypass attacks using character obfuscation or encoding tricks.
 * All functions are pure with no side effects.
 */

/**
 * Normalize text for scanning using NFKC and stripping invisible characters.
 *
 * NFKC handles: fullwidth ASCII, enclosed/circled chars, superscript/subscript,
 * mathematical alphanumeric symbols.
 *
 * Separate stripping handles: zero-width chars, tag characters, variation selectors,
 * soft hyphen, word joiner, Mongolian vowel separator, line/paragraph separators.
 *
 * NOT handled (by design, see AD-8): Cyrillic/Greek homoglyphs — deferred to LLM Classifier.
 */
export function normalizeForScan(text: string): string {
  return text
    .normalize("NFKC")
    .replace(/[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E\u2028\u2029]/g, "")
    .replace(/[\u{E0001}-\u{E007F}]/gu, "")
    .replace(/[\uFE00-\uFE0F]/g, "");
}

/**
 * Detect and decode base64-encoded payloads within text.
 *
 * Scoped to reduce false positives:
 * - Only strings 80+ chars (short strings are too noisy)
 * - Only appends decoded text if >80% printable ASCII (excludes binary/images)
 * - Skips data: URI prefixed strings (embedded images/media)
 *
 * Returns original text with decoded payloads appended (if any found).
 * Original text is always preserved for scanning.
 */
export function decodeBase64Payloads(text: string): string {
  const b64regex = /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])/g;
  let extra = "";

  for (const match of text.matchAll(b64regex)) {
    const candidate = match[0];

    // Skip data: URI prefixed strings (e.g., data:image/png;base64,...)
    const prefix = text.slice(Math.max(0, match.index - 5), match.index);
    if (prefix.includes("data:")) continue;

    try {
      const decoded = Buffer.from(candidate, "base64").toString("utf-8");

      // Only append if >80% printable ASCII (0x20-0x7E)
      const printable = [...decoded].filter((c) => {
        const code = c.charCodeAt(0);
        return code >= 0x20 && code <= 0x7e;
      }).length;

      if (decoded.length > 0 && printable / decoded.length > 0.8) {
        extra += "\n" + decoded;
      }
    } catch {
      /* ignore decode errors */
    }
  }

  return extra ? text + extra : text;
}
