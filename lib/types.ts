/**
 * ShieldClaw shared type definitions.
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM";

export type PatternEntry = {
  category: string;
  severity: Severity;
  regex: RegExp;
  description: string;
  source: string; // pattern file name
};

export type ScanFinding = {
  category: string;
  severity: Severity;
  description: string;
  match: string; // first matched substring
  source: string; // pattern file name
};

export type PluginLogger = {
  info: (message: string) => void;
  warn: (message: string) => void;
  error: (message: string) => void;
};

/** Severity sort order: CRITICAL first, then HIGH, then MEDIUM. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
};
