import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ThreatAccumulator, type ThreatEscalation } from "../lib/accumulator.js";

describe("ThreatAccumulator", () => {
  let acc: ThreatAccumulator;

  beforeEach(() => {
    acc = new ThreatAccumulator();
  });

  describe("ThreatScore", () => {
    it("single CRITICAL = score 10, not escalated", () => {
      const result = acc.recordFinding("session-1", "CRITICAL");
      expect(result).toBeNull();
      expect(acc.getScore("session-1")).toBe(10);
    });

    it("2 CRITICAL = score 20, escalated", () => {
      acc.recordFinding("session-1", "CRITICAL");
      const result = acc.recordFinding("session-1", "CRITICAL");
      expect(result).not.toBeNull();
      expect(result!.type).toBe("score_threshold");
      expect(result!.score).toBe(20);
      expect(result!.key).toBe("session-1");
    });

    it("4 HIGH = score 20, escalated", () => {
      acc.recordFinding("session-1", "HIGH");
      acc.recordFinding("session-1", "HIGH");
      acc.recordFinding("session-1", "HIGH");
      const result = acc.recordFinding("session-1", "HIGH");
      expect(result).not.toBeNull();
      expect(result!.type).toBe("score_threshold");
      expect(result!.score).toBe(20);
    });

    it("1 CRITICAL + 2 HIGH = score 20, escalated", () => {
      acc.recordFinding("session-1", "CRITICAL");
      acc.recordFinding("session-1", "HIGH");
      const result = acc.recordFinding("session-1", "HIGH");
      expect(result).not.toBeNull();
      expect(result!.type).toBe("score_threshold");
      expect(result!.score).toBe(20);
    });

    it("20 MEDIUM = score 20, escalated", () => {
      for (let i = 0; i < 19; i++) {
        const r = acc.recordFinding("session-1", "MEDIUM");
        expect(r).toBeNull();
      }
      const result = acc.recordFinding("session-1", "MEDIUM");
      expect(result).not.toBeNull();
      expect(result!.type).toBe("score_threshold");
      expect(result!.score).toBe(20);
    });

    it("window expiry — events older than 10min don't count", () => {
      vi.useFakeTimers();
      try {
        const now = Date.now();
        vi.setSystemTime(now);

        // Record 1 CRITICAL at t=0 (score 10)
        acc.recordFinding("session-1", "CRITICAL");
        expect(acc.getScore("session-1")).toBe(10);

        // Advance past the 10-minute window
        vi.setSystemTime(now + 600_001);

        // The old event should be expired
        expect(acc.getScore("session-1")).toBe(0);

        // A new CRITICAL should not escalate (only score 10, old one expired)
        const result = acc.recordFinding("session-1", "CRITICAL");
        expect(result).toBeNull();
        expect(acc.getScore("session-1")).toBe(10);
      } finally {
        vi.useRealTimers();
      }
    });

    it("hard cap — 50 events per run, new event evicts oldest when over cap", () => {
      // Fill with 50 MEDIUM events (score = 50)
      for (let i = 0; i < 50; i++) {
        acc.recordFinding("session-1", "MEDIUM");
      }
      // Score should be 50 (50 * 1)
      expect(acc.getScore("session-1")).toBe(50);

      // 51st event should evict oldest, keeping exactly 50
      acc.recordFinding("session-1", "MEDIUM");
      // Score remains 50 (one evicted, one added)
      expect(acc.getScore("session-1")).toBe(50);
    });

    it("max runs — 51st run evicts stalest run", () => {
      vi.useFakeTimers();
      try {
        const baseTime = Date.now();

        // Create 50 runs, each at a different time so we know which is stalest
        for (let i = 0; i < 50; i++) {
          vi.setSystemTime(baseTime + i * 100);
          acc.recordFinding(`run-${i}`, "MEDIUM");
        }
        expect(acc.activeRuns).toBe(50);

        // run-0 was created first (stalest)
        expect(acc.getScore("run-0")).toBe(1);

        // Create 51st run — should evict run-0
        vi.setSystemTime(baseTime + 50 * 100);
        acc.recordFinding("run-50", "MEDIUM");
        expect(acc.activeRuns).toBe(50);

        // run-0 should be gone (returns 0 for unknown key)
        // Note: getScore creates the key again, so check before calling
        // Actually getScore on a non-existing key returns 0 without creating
        expect(acc.getScore("run-0")).toBe(0);
        expect(acc.getScore("run-1")).toBe(1);
        expect(acc.getScore("run-50")).toBe(1);
      } finally {
        vi.useRealTimers();
      }
    });
  });

  describe("ToolSequence", () => {
    it("web_fetch then exec = CRITICAL chain detected", () => {
      acc.recordTool("session-1", "web_fetch");
      const result = acc.recordTool("session-1", "exec");
      expect(result).not.toBeNull();
      expect(result!.type).toBe("tool_chain");
      expect(result!.chain).toEqual(["web_fetch", "exec"]);
    });

    it("read_file then web_fetch = CRITICAL chain detected", () => {
      acc.recordTool("session-1", "read_file");
      const result = acc.recordTool("session-1", "web_fetch");
      expect(result).not.toBeNull();
      expect(result!.type).toBe("tool_chain");
      expect(result!.chain).toEqual(["read_file", "web_fetch"]);
    });

    it("web_fetch then write_file = HIGH chain detected", () => {
      acc.recordTool("session-1", "web_fetch");
      const result = acc.recordTool("session-1", "write_file");
      expect(result).not.toBeNull();
      expect(result!.type).toBe("tool_chain");
      expect(result!.chain).toEqual(["web_fetch", "write_file"]);
    });

    it("exec then web_fetch = HIGH chain detected", () => {
      acc.recordTool("session-1", "exec");
      const result = acc.recordTool("session-1", "web_fetch");
      expect(result).not.toBeNull();
      expect(result!.type).toBe("tool_chain");
      expect(result!.chain).toEqual(["exec", "web_fetch"]);
    });

    it("exec then read = NO chain detected (not in pattern list)", () => {
      acc.recordTool("session-1", "exec");
      const result = acc.recordTool("session-1", "read");
      expect(result).toBeNull();
    });

    it("web_fetch then read = NO chain detected", () => {
      acc.recordTool("session-1", "web_fetch");
      const result = acc.recordTool("session-1", "read");
      expect(result).toBeNull();
    });

    it("10 benign tools then exec = no false chain (ring buffer correctly aged out fetch)", () => {
      acc.recordTool("session-1", "web_fetch");
      // Fill ring buffer with 10 benign tools
      for (let i = 0; i < 10; i++) {
        acc.recordTool("session-1", "read_file");
      }
      // Now exec — the previous tool in the ring is read_file, not web_fetch
      // read_file -> exec is NOT a chain pattern
      const result = acc.recordTool("session-1", "exec");
      expect(result).toBeNull();
    });

    it("handles tool name prefixes (mcp_fetch -> exec)", () => {
      acc.recordTool("session-1", "mcp_fetch");
      const result = acc.recordTool("session-1", "exec");
      expect(result).not.toBeNull();
      expect(result!.type).toBe("tool_chain");
    });

    it("handles tool name suffixes (custom_bash -> web_fetch)", () => {
      acc.recordTool("session-1", "custom_bash");
      const result = acc.recordTool("session-1", "web_fetch");
      expect(result).not.toBeNull();
      expect(result!.type).toBe("tool_chain");
    });

    it("case-insensitive tool matching (WEB_FETCH -> EXEC)", () => {
      acc.recordTool("session-1", "WEB_FETCH");
      const result = acc.recordTool("session-1", "EXEC");
      expect(result).not.toBeNull();
      expect(result!.type).toBe("tool_chain");
    });

    it("colon-separated tool names (mcp:fetch -> exec)", () => {
      acc.recordTool("session-1", "mcp:fetch");
      const result = acc.recordTool("session-1", "exec");
      expect(result).not.toBeNull();
      expect(result!.type).toBe("tool_chain");
    });
  });

  describe("Combined scenarios", () => {
    it("3 HIGH findings + dangerous chain = score 15 + chain escalation", () => {
      acc.recordFinding("session-1", "HIGH");
      acc.recordFinding("session-1", "HIGH");
      acc.recordFinding("session-1", "HIGH");
      expect(acc.getScore("session-1")).toBe(15);

      // Tool chain should still trigger independently
      acc.recordTool("session-1", "web_fetch");
      const result = acc.recordTool("session-1", "exec");
      expect(result).not.toBeNull();
      expect(result!.type).toBe("tool_chain");
    });

    it("separate sessions don't interfere", () => {
      acc.recordFinding("session-a", "CRITICAL");
      acc.recordFinding("session-b", "CRITICAL");
      expect(acc.getScore("session-a")).toBe(10);
      expect(acc.getScore("session-b")).toBe(10);

      // Neither should be escalated individually
      const resultA = acc.recordFinding("session-a", "HIGH");
      expect(resultA).toBeNull();
      expect(acc.getScore("session-a")).toBe(15);
      expect(acc.getScore("session-b")).toBe(10);
    });
  });

  describe("getScore", () => {
    it("returns 0 for unknown key", () => {
      expect(acc.getScore("nonexistent")).toBe(0);
    });

    it("returns correct score after events", () => {
      acc.recordFinding("session-1", "CRITICAL");
      acc.recordFinding("session-1", "HIGH");
      expect(acc.getScore("session-1")).toBe(15);
    });
  });

  describe("activeRuns", () => {
    it("tracks number of active runs correctly", () => {
      expect(acc.activeRuns).toBe(0);

      acc.recordFinding("session-1", "MEDIUM");
      expect(acc.activeRuns).toBe(1);

      acc.recordFinding("session-2", "MEDIUM");
      expect(acc.activeRuns).toBe(2);

      acc.recordTool("session-3", "read");
      expect(acc.activeRuns).toBe(3);
    });

    it("does not double-count same key", () => {
      acc.recordFinding("session-1", "MEDIUM");
      acc.recordFinding("session-1", "HIGH");
      acc.recordTool("session-1", "exec");
      expect(acc.activeRuns).toBe(1);
    });
  });
});
