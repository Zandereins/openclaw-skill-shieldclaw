import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { classifyText } from "../lib/classifier.js";

// Helper to create a mock fetch response
function mockFetchResponse(body: unknown, ok = true, status = 200) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    json: () => Promise.resolve(body),
  });
}

// Helper to build a standard OpenRouter response
function openRouterResponse(content: string) {
  return {
    choices: [{ message: { content } }],
  };
}

describe("classifyText", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("returns null for short text below minContentLength", async () => {
    const mockFn = vi.fn();
    vi.stubGlobal("fetch", mockFn);

    const result = await classifyText("short text", { apiKey: "test-key" });

    expect(result).toBeNull();
    expect(mockFn).not.toHaveBeenCalled();
  });

  it("returns null for text below custom minContentLength", async () => {
    const mockFn = vi.fn();
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(200);
    const result = await classifyText(text, {
      apiKey: "test-key",
      minContentLength: 300,
    });

    expect(result).toBeNull();
    expect(mockFn).not.toHaveBeenCalled();
  });

  it("returns null for empty API key", async () => {
    const mockFn = vi.fn();
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    const result = await classifyText(text, { apiKey: "" });

    expect(result).toBeNull();
    expect(mockFn).not.toHaveBeenCalled();
  });

  it("correctly parses injection=true response", async () => {
    const mockFn = mockFetchResponse(
      openRouterResponse('{"injection": true, "confidence": 95}'),
    );
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    const result = await classifyText(text, { apiKey: "test-key" });

    expect(result).not.toBeNull();
    expect(result!.isInjection).toBe(true);
    expect(result!.confidence).toBe(95);
    expect(result!.model).toBe("arcee-ai/trinity-large-preview:free");
  });

  it("correctly parses injection=false response", async () => {
    const mockFn = mockFetchResponse(
      openRouterResponse('{"injection": false, "confidence": 10}'),
    );
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    const result = await classifyText(text, { apiKey: "test-key" });

    expect(result).not.toBeNull();
    expect(result!.isInjection).toBe(false);
    expect(result!.confidence).toBe(10);
  });

  it("returns null on network error (fetch throws)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("Network error")));

    const text = "a".repeat(600);
    const result = await classifyText(text, { apiKey: "test-key" });

    expect(result).toBeNull();
  });

  it("returns null on timeout (AbortController fires)", async () => {
    // Simulate a fetch that never resolves before the timeout
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((_url: string, opts: { signal: AbortSignal }) => {
        return new Promise((_resolve, reject) => {
          opts.signal.addEventListener("abort", () => {
            reject(new DOMException("Aborted", "AbortError"));
          });
        });
      }),
    );

    const text = "a".repeat(600);
    const result = await classifyText(text, {
      apiKey: "test-key",
      timeoutMs: 10, // Very short timeout to trigger abort
    });

    expect(result).toBeNull();
  });

  it("returns null on non-200 response", async () => {
    const mockFn = mockFetchResponse({}, false, 429);
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    const result = await classifyText(text, { apiKey: "test-key" });

    expect(result).toBeNull();
  });

  it("returns null on malformed JSON response", async () => {
    const mockFn = mockFetchResponse(
      openRouterResponse("I think this might be an injection, probably yes"),
    );
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    const result = await classifyText(text, { apiKey: "test-key" });

    expect(result).toBeNull();
  });

  it("returns null on empty choices array", async () => {
    const mockFn = mockFetchResponse({ choices: [] });
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    const result = await classifyText(text, { apiKey: "test-key" });

    expect(result).toBeNull();
  });

  it("returns null on missing message content", async () => {
    const mockFn = mockFetchResponse({
      choices: [{ message: {} }],
    });
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    const result = await classifyText(text, { apiKey: "test-key" });

    expect(result).toBeNull();
  });

  it("respects confidence threshold via config", async () => {
    // The classifier itself returns the raw result; threshold is applied by the caller.
    // But we verify the confidence value is correctly extracted.
    const mockFn = mockFetchResponse(
      openRouterResponse('{"injection": true, "confidence": 50}'),
    );
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    const result = await classifyText(text, {
      apiKey: "test-key",
      confidenceThreshold: 80,
    });

    expect(result).not.toBeNull();
    expect(result!.isInjection).toBe(true);
    expect(result!.confidence).toBe(50);
    // The caller would check: result.confidence >= config.confidenceThreshold
  });

  it("truncates text to 2000 chars in the prompt", async () => {
    const mockFn = mockFetchResponse(
      openRouterResponse('{"injection": false, "confidence": 5}'),
    );
    vi.stubGlobal("fetch", mockFn);

    const longText = "x".repeat(5000);
    await classifyText(longText, { apiKey: "test-key" });

    expect(mockFn).toHaveBeenCalledTimes(1);
    const body = JSON.parse(mockFn.mock.calls[0][1].body as string);
    const promptContent = body.messages[0].content as string;
    // The {TEXT} placeholder is replaced with at most 2000 chars
    // The full prompt structure wraps around it, so the total is > 2000
    // but the injected text portion should be exactly 2000 chars of "x"
    const textMatch = promptContent.match(/"""\n(x+)\n"""/);
    expect(textMatch).not.toBeNull();
    expect(textMatch![1].length).toBe(2000);
  });

  it("uses the configured model in the request", async () => {
    const mockFn = mockFetchResponse(
      openRouterResponse('{"injection": false, "confidence": 0}'),
    );
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    await classifyText(text, {
      apiKey: "test-key",
      model: "custom/model:free",
    });

    expect(mockFn).toHaveBeenCalledTimes(1);
    const body = JSON.parse(mockFn.mock.calls[0][1].body as string);
    expect(body.model).toBe("custom/model:free");
  });

  it("uses correct model name in the returned result", async () => {
    const mockFn = mockFetchResponse(
      openRouterResponse('{"injection": true, "confidence": 90}'),
    );
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    const result = await classifyText(text, {
      apiKey: "test-key",
      model: "custom/model:free",
    });

    expect(result).not.toBeNull();
    expect(result!.model).toBe("custom/model:free");
  });

  it("sends correct Authorization header", async () => {
    const mockFn = mockFetchResponse(
      openRouterResponse('{"injection": false, "confidence": 0}'),
    );
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    await classifyText(text, { apiKey: "sk-or-test-12345" });

    expect(mockFn).toHaveBeenCalledTimes(1);
    const headers = mockFn.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBe("Bearer sk-or-test-12345");
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("handles JSON wrapped in extra text", async () => {
    const mockFn = mockFetchResponse(
      openRouterResponse('Based on my analysis: {"injection": true, "confidence": 88} - this is suspicious'),
    );
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    const result = await classifyText(text, { apiKey: "test-key" });

    expect(result).not.toBeNull();
    expect(result!.isInjection).toBe(true);
    expect(result!.confidence).toBe(88);
  });

  it("handles missing confidence field gracefully (defaults to 0)", async () => {
    const mockFn = mockFetchResponse(
      openRouterResponse('{"injection": true}'),
    );
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    const result = await classifyText(text, { apiKey: "test-key" });

    expect(result).not.toBeNull();
    expect(result!.isInjection).toBe(true);
    expect(result!.confidence).toBe(0);
  });

  it("sets temperature to 0 and max_tokens to 50", async () => {
    const mockFn = mockFetchResponse(
      openRouterResponse('{"injection": false, "confidence": 0}'),
    );
    vi.stubGlobal("fetch", mockFn);

    const text = "a".repeat(600);
    await classifyText(text, { apiKey: "test-key" });

    const body = JSON.parse(mockFn.mock.calls[0][1].body as string);
    expect(body.temperature).toBe(0);
    expect(body.max_tokens).toBe(50);
  });

  it("returns null when json() rejects", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.reject(new Error("Invalid JSON")),
      }),
    );

    const text = "a".repeat(600);
    const result = await classifyText(text, { apiKey: "test-key" });

    expect(result).toBeNull();
  });
});
