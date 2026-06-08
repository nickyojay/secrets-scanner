// src/scanner/multiLineScanner.ts

import { ScanRule, Finding, RuleContext } from '../types';
import { SuppressionInfo, isLineSuppressed } from '../utils/suppressionParser';

export interface MultiLineRule extends ScanRule {
  // How many lines to include in each window
  // Default is 1 (single line)
  windowSize: number;
}

// Redact helper (mirrors the version in engine.ts)
function redactMatch(match: string): string {
  if (match.length <= 8) return '****';
  return `${match.substring(0, 6)}...****`;
}

function extractSnippet(lines: string[], centerIndex: number, radius = 2): string {
  const start = Math.max(0, centerIndex - radius);
  const end = Math.min(lines.length - 1, centerIndex + radius);
  return lines
    .slice(start, end + 1)
    .map((line, i) => {
      const lineNum = start + i + 1;
      const marker = start + i === centerIndex ? '→ ' : '  ';
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

export function scanWithMultiLineRules(
  lines: string[],
  relativePath: string,
  rules: MultiLineRule[],
  fileExtension: string,
  suppressionInfo: SuppressionInfo,
): Finding[] {
  const findings: Finding[] = [];
  const testFile = isTestFile(relativePath);

  for (const rule of rules) {
    // Skip rules that don't apply to this extension
    if (rule.fileExtensions?.length && !rule.fileExtensions.includes(fileExtension)) {
      continue;
    }

    const windowSize = rule.windowSize ?? 1;

    // Slide the window over the file
    for (let i = 0; i < lines.length; i++) {
      // Build the window: grab up to windowSize lines starting at i
      const windowLines = lines.slice(i, i + windowSize);
      const windowText = windowLines.join('\n');

      rule.pattern.lastIndex = 0;
      const match = rule.pattern.exec(windowText);
      if (!match) continue;

      // Find which actual line the match starts on
      // by counting newlines before the match position
      const textBeforeMatch = windowText.substring(0, match.index);
      const newlinesBeforeMatch = (textBeforeMatch.match(/\n/g) || []).length;
      const matchLineIndex = i + newlinesBeforeMatch;
      const matchLineNumber = matchLineIndex + 1; // 1-indexed

      // Check suppression
      if (isLineSuppressed(matchLineNumber, suppressionInfo)) {
        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          category: rule.category,
          severity: rule.severity,
          confidence: rule.confidence,
          filePath: relativePath,
          line: matchLineNumber,
          column: match.index,
          matchedText: match[0],
          redactedText: redactMatch(match[0]),
          message: `${rule.name} detected`,
          remediation: rule.remediation,
          codeSnippet: extractSnippet(lines, matchLineIndex),
          suppressed: true,
          suppressionReason: suppressionInfo.reasons.get(matchLineNumber),
        });
        continue;
      }

      // Run the context check if the rule has one
      const context: RuleContext = {
        matchedLine: lines[matchLineIndex] ?? '',
        lineIndex: matchLineIndex,
        allLines: lines,
        filePath: relativePath,
        fileExtension,
        isTestFile: testFile,
      };

      if (rule.contextCheck) {
        const result = rule.contextCheck(context);

        // false = suppress this finding entirely
        if (result === false) continue;
      }

      // Reduce confidence for test files
      // A vulnerable pattern in a test is often testing the vulnerability itself
      const confidence =
        testFile && rule.confidence === 'high' ? 'medium' : rule.confidence;

      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        category: rule.category,
        severity: rule.severity,
        confidence,
        filePath: relativePath,
        line: matchLineNumber,
        column: match.index,
        matchedText: match[0],
        redactedText: redactMatch(match[0]),
        message: `${rule.name} detected`,
        remediation: rule.remediation,
        codeSnippet: extractSnippet(lines, matchLineIndex),
        suppressed: false,
      });
    }
  }

  return findings;
}