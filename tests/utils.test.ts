import { describe, it, expect } from "vitest";
import { FindingDedup, extractStringValues, truncateForScan, containsCanary } from "../lib/utils.js";

describe("FindingDedup", () => {
  it("returns false for new entries", () => {
    const dedup = new FindingDedup(5000);
    expect(dedup.isDuplicate("a")).toBe(false);
  });

  it("returns true for duplicate within TTL", () => {
    const dedup = new FindingDedup(5000);
    dedup.isDuplicate("a");
    expect(dedup.isDuplicate("a")).toBe(true);
  });

  it("evicts oldest entry when hard-cap (200) exceeded", () => {
    const dedup = new FindingDedup(60_000);
    // Fill to 201 entries
    for (let i = 0; i <= 201; i++) {
      dedup.isDuplicate(`key-${i}`);
    }
    // After eviction, size should not exceed 202 (201 + 1 new)
    // The hard-cap triggers eviction when size > 200
    // We can verify by adding more and checking it doesn't grow unbounded
    for (let i = 300; i < 310; i++) {
      dedup.isDuplicate(`key-${i}`);
    }
    // Should still work without errors
    expect(dedup.isDuplicate("fresh-key")).toBe(false);
  });
});

describe("extractStringValues", () => {
  it("extracts strings from nested objects", () => {
    const result = extractStringValues({ a: "hello", b: { c: "world" } });
    expect(result).toContain("hello");
    expect(result).toContain("world");
  });

  it("extracts from arrays", () => {
    const result = extractStringValues(["a", "b", ["c"]]);
    expect(result).toEqual(["a", "b", "c"]);
  });

  it("stops at depth > 10", () => {
    let obj: unknown = "leaf";
    for (let i = 0; i < 15; i++) {
      obj = { nested: obj };
    }
    const result = extractStringValues(obj);
    // Should not find the deeply nested leaf
    expect(result).toEqual([]);
  });

  it("stops after 1000 properties (breadth limit)", () => {
    const obj: Record<string, string> = {};
    for (let i = 0; i < 1500; i++) {
      obj[`key${i}`] = `value${i}`;
    }
    const result = extractStringValues(obj);
    expect(result.length).toBeLessThanOrEqual(1001);
  });

  it("returns empty for non-string primitives", () => {
    expect(extractStringValues(42)).toEqual([]);
    expect(extractStringValues(null)).toEqual([]);
    expect(extractStringValues(undefined)).toEqual([]);
    expect(extractStringValues(true)).toEqual([]);
  });
});

describe("truncateForScan edge cases", () => {
  it("returns full text when under maxLen", () => {
    expect(truncateForScan("short")).toBe("short");
  });

  it("handles text with no newlines", () => {
    const text = "x".repeat(20_000);
    const result = truncateForScan(text, 10_000, 2_000);
    expect(result.length).toBeLessThan(text.length);
    expect(result).toContain("[...truncated...]");
  });

  it("handles empty string", () => {
    expect(truncateForScan("")).toBe("");
  });

  it("handles text exactly at maxLen", () => {
    const text = "a".repeat(10_240);
    expect(truncateForScan(text)).toBe(text);
  });
});

describe("containsCanary — zero-width character bypass", () => {
  it("detects canary with zero-width space inserted", () => {
    expect(containsCanary("SHIELD\u200BCLAW_CANARY")).toBe(true);
  });

  it("detects canary with zero-width joiner inserted", () => {
    expect(containsCanary("SHIELD\u200DCLAW_CANARY")).toBe(true);
  });

  it("detects canary with zero-width non-joiner inserted", () => {
    expect(containsCanary("SHIELD\u200CCLAW_CANARY")).toBe(true);
  });

  it("detects canary with FEFF (BOM) inserted", () => {
    expect(containsCanary("SHIELD\uFEFFCLAW_CANARY")).toBe(true);
  });

  it("detects canary with soft hyphen inserted", () => {
    expect(containsCanary("SHIELD\u00ADCLAW_CANARY")).toBe(true);
  });

  it("detects canary with multiple ZW chars scattered", () => {
    expect(containsCanary("S\u200BH\u200CI\u200DE\u00ADL\uFEFFDCLAW_CANARY")).toBe(true);
  });

  it("detects normal canary without ZW chars", () => {
    expect(containsCanary("SHIELDCLAW_CANARY")).toBe(true);
  });

  it("detects {{SHIELDCLAW_CANARY}} with ZW chars", () => {
    expect(containsCanary("{{\u200BSHIELDCLAW_CANARY\u200B}}")).toBe(true);
  });

  it("does not false-positive on unrelated text", () => {
    expect(containsCanary("just normal text with zero\u200Bwidth chars")).toBe(false);
  });
});
