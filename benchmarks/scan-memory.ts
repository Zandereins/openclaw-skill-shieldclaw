/**
 * ShieldClaw Memory Scanner — Phase 5
 * Scans workspace/memory/*.md files for injection patterns.
 * Run periodically to detect memory poisoning (OWASP ASI06).
 *
 * Usage: npx tsx benchmarks/scan-memory.ts [path]
 * Default path: /home/openclaw/.openclaw/workspace/memory/
 */

import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadPatterns, loadWhitelist, scanText } from "../lib/pattern-engine.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = join(__dirname, "..");

function scanMemoryFiles(memoryDir: string) {
  const patternsDir = join(projectRoot, "patterns");
  const patterns = loadPatterns(patternsDir);
  const whitelist = loadWhitelist(patternsDir);

  if (!existsSync(memoryDir)) {
    console.error(`Directory not found: ${memoryDir}`);
    process.exit(2);
  }

  const files = readdirSync(memoryDir).filter(f => f.endsWith(".md"));
  let totalFindings = 0;

  console.log(`Scanning ${files.length} memory files in ${memoryDir}\n`);

  for (const file of files) {
    const content = readFileSync(join(memoryDir, file), "utf-8");
    const findings = scanText(content, patterns, undefined, whitelist);

    if (findings.length > 0) {
      totalFindings += findings.length;
      console.log(`[!] ${file}: ${findings.length} finding(s)`);
      for (const f of findings) {
        console.log(`    ${f.severity} | ${f.category} | ${f.description}`);
        console.log(`    Match: "${f.match}"`);
      }
    }
  }

  if (totalFindings === 0) {
    console.log("No injection patterns found in memory files.");
  } else {
    console.log(`\n${totalFindings} finding(s) in ${files.length} files.`);
  }

  process.exit(totalFindings > 0 ? 1 : 0);
}

const memoryDir = process.argv[2] || "/home/openclaw/.openclaw/workspace/memory/";
scanMemoryFiles(memoryDir);
