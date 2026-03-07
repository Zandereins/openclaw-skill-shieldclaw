import { describe, it, expect } from "vitest";
import path from "node:path";
import { loadPatterns, loadWhitelist, scanText } from "../lib/pattern-engine.js";

const PATTERNS_DIR = path.resolve(__dirname, "..", "patterns");

describe("crypto patterns", () => {
  const patterns = loadPatterns(PATTERNS_DIR);
  const whitelist = loadWhitelist(PATTERNS_DIR);

  describe("EVM private keys (Hyperliquid)", () => {
    it("detects EVM private key with context (privateKey assignment)", () => {
      const text = 'privateKey: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"';
      const findings = scanText(text, patterns, undefined, whitelist);
      const crypto = findings.filter((f) => f.category === "CRYPTO_KEY");
      expect(crypto.length).toBeGreaterThan(0);
      expect(crypto[0].severity).toBe("CRITICAL");
    });

    it("detects bare 0x-prefixed 64-char hex string", () => {
      const text = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
      const findings = scanText(text, patterns, undefined, whitelist);
      const crypto = findings.filter((f) => f.category === "CRYPTO_KEY");
      expect(crypto.length).toBeGreaterThan(0);
      expect(crypto[0].severity).toBe("CRITICAL");
    });

    it("does NOT detect Ethereum address (0x + 40 hex chars)", () => {
      const text = "Send ETH to 0x1234567890abcdef1234567890abcdef12345678";
      const findings = scanText(text, patterns, undefined, whitelist);
      const crypto = findings.filter((f) => f.category === "CRYPTO_KEY");
      expect(crypto).toEqual([]);
    });

    it("does NOT detect short hex strings (< 64 chars)", () => {
      const text = "Transaction hash: 0xabcdef1234567890abcdef1234567890";
      const findings = scanText(text, patterns, undefined, whitelist);
      const crypto = findings.filter((f) => f.category === "CRYPTO_KEY");
      expect(crypto).toEqual([]);
    });
  });

  describe("Solana private keys (Base58)", () => {
    it("detects Solana private key with context (secretKey assignment)", () => {
      const text = 'secretKey: "4wBqpZM9xaSheZzJSMYqFnGGCBFPpBF5KBjQxTqMyvRoKRYjbRYGAhpFiJFJRYphMJvdv4Mt3BHEoc2jcejrN1bM"';
      const findings = scanText(text, patterns, undefined, whitelist);
      const crypto = findings.filter((f) => f.category === "CRYPTO_KEY");
      expect(crypto.length).toBeGreaterThan(0);
      expect(crypto[0].severity).toBe("CRITICAL");
    });

    it("detects bare long base58 string (85-90 chars)", () => {
      const text = "5TVTgpmrckW3dAiRELYBR8mNhUWj6BTM9K3FwqdVdNRjrDAeSs2YdqG1VQh8Fkuc9dBZjp4RNPT5TbJHWnXxU5gS";
      const findings = scanText(text, patterns, undefined, whitelist);
      const crypto = findings.filter((f) => f.category === "CRYPTO_KEY");
      expect(crypto.length).toBeGreaterThan(0);
      expect(crypto[0].severity).toBe("CRITICAL");
    });

    it("does NOT detect Solana public key (32-44 base58 chars)", () => {
      const text = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
      const findings = scanText(text, patterns, undefined, whitelist);
      const crypto = findings.filter((f) => f.category === "CRYPTO_KEY");
      expect(crypto).toEqual([]);
    });

    it("does NOT detect Solana tx signature in safe context (txid: ...)", () => {
      const text = "txid: 5TVTgpmrckW3dAiRELYBR8mNhUWj6BTM9K3FwqdVdNRjrDAeSs2YdqG1VQh8Fkuc9dBZjp4RNPT5TbJHWnXxU5gS";
      const findings = scanText(text, patterns, undefined, whitelist);
      const crypto = findings.filter((f) => f.category === "CRYPTO_KEY");
      expect(crypto).toEqual([]);
    });
  });

  describe("BIP39 seed phrases", () => {
    it("detects BIP39 seed phrase (12 known words)", () => {
      const text = "abandon ability able about above absent absorb abstract absurd abuse access accident";
      const findings = scanText(text, patterns, undefined, whitelist);
      const seed = findings.filter((f) => f.category === "CRYPTO_SEED");
      expect(seed.length).toBeGreaterThan(0);
      expect(seed[0].severity).toBe("CRITICAL");
    });

    it("detects seed phrase with prefix label", () => {
      const text = "Mnemonic: acid acoustic acquire across act action actual adapt add addict address adjust";
      const findings = scanText(text, patterns, undefined, whitelist);
      const seed = findings.filter((f) => f.category === "CRYPTO_SEED");
      expect(seed.length).toBeGreaterThan(0);
      expect(seed[0].severity).toBe("CRITICAL");
    });
  });

  describe("credential file paths", () => {
    it("detects credential file path with /home/openclaw/ prefix", () => {
      const text = "Reading /home/openclaw/.openclaw/credentials/hyperliquid-testnet.json";
      const findings = scanText(text, patterns, undefined, whitelist);
      const pathFindings = findings.filter((f) => f.category === "CRYPTO_PATH");
      expect(pathFindings.length).toBeGreaterThan(0);
      expect(pathFindings[0].severity).toBe("CRITICAL");
    });

    it("detects credential file path with /home/node/ prefix", () => {
      const text = "Config at /home/node/.openclaw/credentials/solana-devnet.json";
      const findings = scanText(text, patterns, undefined, whitelist);
      const pathFindings = findings.filter((f) => f.category === "CRYPTO_PATH");
      expect(pathFindings.length).toBeGreaterThan(0);
      expect(pathFindings[0].severity).toBe("CRITICAL");
    });
  });

  describe("trading service API keys", () => {
    it("detects trading service API key assignment", () => {
      const text = 'jupiter_api_key: "jup_test_abc123def456ghi789jkl012"';
      const findings = scanText(text, patterns, undefined, whitelist);
      const apikey = findings.filter((f) => f.category === "CRYPTO_APIKEY");
      expect(apikey.length).toBeGreaterThan(0);
      expect(apikey[0].severity).toBe("CRITICAL");
    });
  });

  describe("regression safety", () => {
    it("full suite loads without errors and has expected pattern count", () => {
      // 71 existing patterns + at least 7 new crypto patterns = 78+
      expect(patterns.length).toBeGreaterThanOrEqual(78);
    });

    it("all patterns compile and execute without error", () => {
      for (const p of patterns) {
        expect(() => "test string".match(p.regex)).not.toThrow();
      }
    });
  });
});
