// src/scanner/engine.ts

import * as fs from 'fs';
import {
  Finding,
  ScanConfig,
  ScanResult,
  ScanSummary,
  ScanRule,
  Severity,
  FindingCategory,
  Confidence,
  RuleContext,
} from '../types';
import { traverseDirectory } from '../utils/fileTraversal';
import { allRules } from '../patterns';
import { MultiLineRule, scanWithMultiLineRules } from './multiLineScanner';
import { parseSuppressions, isLineSuppressed } from '../utils/suppressionParser';

const CONTEXT_LINES = 2;

function redactMatch(match: string): string {
  if (match.length <= 8) return '****';
  return `${match.substring(0, 6)}...****`;
}

function extractSnippet(lines: string[], lineIndex: number): string {
  const start = Math.max(0, lineIndex - CONTEXT_LINES);
  const end = Math.min(lines.length - 1, lineIndex + CONTEXT_LINES);
  return lines
    .slice(start, end + 1)
    .map((line, i) => {
      const lineNum = start + i + 1;
      const marker = start + i === lineIndex ? '→ ' : '  ';
      return `${marker}${String(lineNum).padStart(4)}: ${line}`;
    })
    .join('\n');
}

function isTestFile(filePath: string): boolean {
  return (
    filePath.includes('.test.') ||
    filePath.includes('.spec.') ||
    filePath.includes('__tests__') ||
    filePath.includes('/test/') ||
    filePath.includes('/tests/')
  );
}

function ruleAppliesToFile(rule: ScanRule, ext: string): boolean {
  if (!rule.fileExtensions?.length) return true;
  return rule.fileExtensions.includes(ext.toLowerCase());
}

function filterRules(rules: ScanRule[], config: ScanConfig): ScanRule[] {
  return rules.filter(rule => {
    if (config.severities?.length && !config.severities.includes(rule.severity)) return false;
    if (config.categories?.length && !config.categories.includes(rule.category)) return false;
    if (rule.highFalsePositiveRate && !config.includeHighFalsePositives) return false;
    return true;
  });
}

function scanFileContent(
  content: string,
  relativePath: string,
  rules: ScanRule[],
  fileExtension: string,
): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');
  const suppressionInfo = parseSuppressions(lines);
  const testFile = isTestFile(relativePath);

  // Separate rules into standard (line-by-line) and multi-line
  const standardRules = rules.filter(r => !(r as MultiLineRule).windowSize || (r as MultiLineRule).windowSize <= 1);
  const multiLineRules = rules.filter(r => (r as MultiLineRule).windowSize > 1) as MultiLineRule[];

  // ── Standard line-by-line scanning ──────────────────────────────────
  for (const rule of standardRules) {
    if (!ruleAppliesToFile(rule, fileExtension)) continue;

    // File-existence rules (pattern is /.*/)
    if (rule.pattern.source === '.*' && rule.fileExtensions?.length) {
      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        category: rule.category,
        severity: rule.severity,
        confidence: (rule as any).confidence ?? 'high',
        filePath: relativePath,
        line: 1,
        column: 0,
        matchedText: relativePath,
        redactedText: relativePath,
        message: rule.description,
        remediation: rule.remediation,
        codeSnippet: lines.slice(0, 3).join('\n'),
        suppressed: false,
      });
      continue;
    }

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];
      rule.pattern.lastIndex = 0;
      const match = rule.pattern.exec(line);
      if (!match) continue;

      const lineNumber = lineIndex + 1;
      const suppressed = isLineSuppressed(lineNumber, suppressionInfo);

      // Skip suppressed findings unless the config asks to include them
      if (suppressed) continue;

      // Run context check if the rule has one
      if ((rule as any).contextCheck) {
        const context: RuleContext = {
          matchedLine: line,
          lineIndex,
          allLines: lines,
          filePath: relativePath,
          fileExtension,
          isTestFile: testFile,
        };
        const result = (rule as any).contextCheck(context);
        if (result === false) continue;
      }

      const confidence: Confidence =
        testFile && ((rule as any).confidence === 'high')
          ? 'medium'
          : ((rule as any).confidence ?? 'high');

      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        category: rule.category,
        severity: rule.severity,
        confidence,
        filePath: relativePath,
        line: lineNumber,
        column: match.index,
        matchedText: match[0],
        redactedText: redactMatch(match[0]),
        message: `${rule.name} detected`,
        remediation: rule.remediation,
        codeSnippet: extractSnippet(lines, lineIndex),
        suppressed: false,
      });
    }
  }

  // ── Multi-line scanning ──────────────────────────────────────────────
  const multiLineFindings = scanWithMultiLineRules(
    lines,
    relativePath,
    multiLineRules,
    fileExtension,
    suppressionInfo,
  );

  findings.push(...multiLineFindings);
  return findings;
}

function buildSummary(findings: Finding[]): ScanSummary {
  const bySeverity: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  const byCategory: Record<FindingCategory, number> = {
    secret: 0, vulnerability: 0, hygiene: 0,
  };
  const byConfidence: Record<Confidence, number> = {
    high: 0, medium: 0, low: 0,
  };
  const affectedFiles = new Set<string>();
  let suppressedCount = 0;

  for (const f of findings) {
    if (f.suppressed) {
      suppressedCount++;
      continue; // Don't count suppressed findings in the main tallies
    }
    bySeverity[f.severity]++;
    byCategory[f.category]++;
    byConfidence[f.confidence]++;
    affectedFiles.add(f.filePath);
  }

  return {
    total: findings.filter(f => !f.suppressed).length,
    bySeverity,
    byCategory,
    byConfidence,
    affectedFiles: affectedFiles.size,
    suppressedCount,
  };
}


function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter(finding => {
    // A finding is unique by: which rule, which file, which line
    const key = `${finding.ruleId}::${finding.filePath}::${finding.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
export async function scan(config: ScanConfig): Promise<ScanResult> {
  const startTime = Date.now();
  const findings: Finding[] = [];
  const skippedReasons: Record<string, number> = {};

  const rules = filterRules(allRules, config);

  const traversalResult = traverseDirectory(
    config.targetPath,
    config.maxFileSizeBytes,
    config.ignorePatterns,
  );

  for (const skipped of traversalResult.skipped) {
    skippedReasons[skipped.reason] = (skippedReasons[skipped.reason] ?? 0) + 1;
  }

  for (const fileInfo of traversalResult.files) {
    let content: string;
    try {
      content = fs.readFileSync(fileInfo.absolutePath, 'utf-8');
    } catch {
      skippedReasons['unreadable'] = (skippedReasons['unreadable'] ?? 0) + 1;
      continue;
    }

    findings.push(
      ...scanFileContent(content, fileInfo.relativePath, rules, fileInfo.extension)
    );
  }

  // Filter out suppressed findings unless config says to include them
  const deduplicated = deduplicateFindings(findings);
  // Filter out suppressed findings unless config says to include them
  const outputFindings = config.includeSuppressed
    ? deduplicated
    : deduplicated.filter(f => !f.suppressed);

  return {
    scannedAt: new Date(),
    targetPath: config.targetPath,
    durationMs: Date.now() - startTime,
    filesScanned: traversalResult.files.length,
    filesSkipped: traversalResult.skipped.length,
    skippedReasons,
    findings: outputFindings,
    summary: buildSummary(deduplicated), // summary uses deduplicated too
  };
}