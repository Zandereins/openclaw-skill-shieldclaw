/**
 * ShieldClaw Benchmark — Phase 0 Baseline Measurement
 *
 * Runs the pattern engine against the deepset/prompt-injections dataset
 * and reports TPR, FPR, F1, Precision, Recall.
 *
 * Usage: npx tsx benchmarks/run-benchmark.ts
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadPatterns, loadWhitelist, scanText } from "../lib/pattern-engine.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const projectRoot = join(__dirname, "..");

// --- CSV Parser (handles quoted fields with commas/newlines) ---

interface Sample {
  text: string;
  label: number; // 0 = benign, 1 = injection
}

function parseCSV(content: string): Sample[] {
  const samples: Sample[] = [];
  const lines = content.split("\n");
  let i = 1; // skip header

  while (i < lines.length) {
    const line = lines[i];
    if (!line || line.trim() === "") {
      i++;
      continue;
    }

    if (line.startsWith('"')) {
      // Quoted field — find the closing quote
      let text = "";
      let j = i;
      let raw = lines[j].slice(1); // remove opening quote

      while (j < lines.length) {
        const endQuote = raw.indexOf('",');
        if (endQuote !== -1) {
          text += raw.slice(0, endQuote);
          const rest = raw.slice(endQuote + 2).trim();
          const label = parseInt(rest, 10);
          if (!isNaN(label)) {
            samples.push({ text: text.replace(/""/g, '"'), label });
          }
          i = j + 1;
          break;
        }
        text += raw + "\n";
        j++;
        if (j < lines.length) {
          raw = lines[j];
        } else {
          i = j + 1;
          break;
        }
      }
      if (j >= lines.length) break;
    } else {
      // Unquoted field — simple split on last comma
      const lastComma = line.lastIndexOf(",");
      if (lastComma > 0) {
        const text = line.slice(0, lastComma);
        const label = parseInt(line.slice(lastComma + 1).trim(), 10);
        if (!isNaN(label)) {
          samples.push({ text, label });
        }
      }
      i++;
    }
  }
  return samples;
}

// --- Benchmark Runner ---

function runBenchmark() {
  // Load patterns and whitelist
  const patternsDir = join(projectRoot, "patterns");
  const patterns = loadPatterns(patternsDir);
  const whitelist = loadWhitelist(patternsDir);

  console.log(`Loaded ${patterns.length} patterns, ${whitelist.length} whitelist rules\n`);

  // Load dataset
  const csvPath = join(__dirname, "deepset-prompt-injections.csv");
  const csvContent = readFileSync(csvPath, "utf-8");
  const samples = parseCSV(csvContent);

  const totalInjections = samples.filter((s) => s.label === 1).length;
  const totalBenign = samples.filter((s) => s.label === 0).length;
  console.log(`Dataset: ${samples.length} samples (${totalInjections} injection, ${totalBenign} benign)\n`);

  // Run scanner on each sample
  let truePositives = 0; // injection correctly detected
  let falsePositives = 0; // benign incorrectly flagged
  let trueNegatives = 0; // benign correctly passed
  let falseNegatives = 0; // injection missed

  const missedInjections: { text: string; label: number }[] = [];
  const falseAlarms: { text: string; findings: string[] }[] = [];

  const startTime = Date.now();

  for (const sample of samples) {
    const findings = scanText(sample.text, patterns, 10_240, whitelist);
    const detected = findings.length > 0;

    if (sample.label === 1) {
      // Ground truth: injection
      if (detected) {
        truePositives++;
      } else {
        falseNegatives++;
        if (missedInjections.length < 20) {
          missedInjections.push(sample);
        }
      }
    } else {
      // Ground truth: benign
      if (detected) {
        falsePositives++;
        if (falseAlarms.length < 20) {
          falseAlarms.push({
            text: sample.text.slice(0, 120),
            findings: findings.map((f) => `${f.category}|${f.severity}`),
          });
        }
      } else {
        trueNegatives++;
      }
    }
  }

  const elapsed = Date.now() - startTime;

  // Calculate metrics
  const precision = truePositives / (truePositives + falsePositives) || 0;
  const recall = truePositives / (truePositives + falseNegatives) || 0;
  const f1 = (2 * precision * recall) / (precision + recall) || 0;
  const fpr = falsePositives / (falsePositives + trueNegatives) || 0;
  const accuracy = (truePositives + trueNegatives) / samples.length;

  // Report
  console.log("=== ShieldClaw v0.6.0 Benchmark Results ===\n");
  console.log("Confusion Matrix:");
  console.log(`  True Positives:  ${truePositives} (injections correctly detected)`);
  console.log(`  False Positives: ${falsePositives} (benign incorrectly flagged)`);
  console.log(`  True Negatives:  ${trueNegatives} (benign correctly passed)`);
  console.log(`  False Negatives: ${falseNegatives} (injections missed)\n`);

  console.log("Metrics:");
  console.log(`  Precision:  ${(precision * 100).toFixed(1)}%`);
  console.log(`  Recall:     ${(recall * 100).toFixed(1)}%`);
  console.log(`  F1 Score:   ${(f1 * 100).toFixed(1)}%`);
  console.log(`  FPR:        ${(fpr * 100).toFixed(1)}%`);
  console.log(`  Accuracy:   ${(accuracy * 100).toFixed(1)}%`);
  console.log(`  Scan time:  ${elapsed}ms (${(elapsed / samples.length).toFixed(2)}ms/sample)\n`);

  if (missedInjections.length > 0) {
    console.log(`--- Missed Injections (first ${missedInjections.length}) ---`);
    for (const m of missedInjections) {
      console.log(`  "${m.text.slice(0, 100)}${m.text.length > 100 ? "..." : ""}"`);
    }
    console.log();
  }

  if (falseAlarms.length > 0) {
    console.log(`--- False Positives (first ${falseAlarms.length}) ---`);
    for (const fa of falseAlarms) {
      console.log(`  "${fa.text}${fa.text.length >= 120 ? "..." : ""}" -> [${fa.findings.join(", ")}]`);
    }
    console.log();
  }

  // Machine-readable summary
  console.log("--- JSON Summary ---");
  console.log(
    JSON.stringify(
      {
        version: "0.6.0",
        dataset: "deepset/prompt-injections",
        samples: samples.length,
        injections: totalInjections,
        benign: totalBenign,
        tp: truePositives,
        fp: falsePositives,
        tn: trueNegatives,
        fn: falseNegatives,
        precision: Math.round(precision * 1000) / 1000,
        recall: Math.round(recall * 1000) / 1000,
        f1: Math.round(f1 * 1000) / 1000,
        fpr: Math.round(fpr * 1000) / 1000,
        accuracy: Math.round(accuracy * 1000) / 1000,
        scanTimeMs: elapsed,
      },
      null,
      2,
    ),
  );
}

runBenchmark();
