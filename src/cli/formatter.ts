// src/cli/formatter.ts

import chalk from 'chalk';
import { ScanResult, Finding, Severity, Confidence } from '../types';

// ── Severity styling ──────────────────────────────────────────────────────

const SEVERITY_STYLE: Record<Severity, (text: string) => string> = {
  critical: (t) => chalk.bgRed.white.bold(t),
  high:     (t) => chalk.red.bold(t),
  medium:   (t) => chalk.yellow(t),
  low:      (t) => chalk.cyan(t),
  info:     (t) => chalk.gray(t),
};

const SEVERITY_ICON: Record<Severity, string> = {
  critical: '✖',
  high:     '●',
  medium:   '▲',
  low:      '◆',
  info:     '·',
};

const CONFIDENCE_DISPLAY: Record<Confidence, string> = {
  high:   chalk.green('◆ HIGH'),
  medium: chalk.yellow('◇ MEDIUM'),
  low:    chalk.gray('◌ LOW'),
};

// ── Individual finding ────────────────────────────────────────────────────

function printFinding(finding: Finding, index: number): void {
  const styleFunc = SEVERITY_STYLE[finding.severity];
  const icon = SEVERITY_ICON[finding.severity];
  const severityBadge = styleFunc(` ${icon} ${finding.severity.toUpperCase()} `);
  const confidence = CONFIDENCE_DISPLAY[finding.confidence];

  // Header line
  console.log();
  console.log(
    `${chalk.bold(`#${index + 1}`)}  ${severityBadge}  ${chalk.bold(finding.ruleName)}  ${confidence}`
  );

  // Location
  console.log(
    `    ${chalk.dim('file:')}  ${chalk.underline(finding.filePath)}${chalk.dim(`:${finding.line}:${finding.column}`)}`
  );

  // Category and rule ID
  console.log(
    `    ${chalk.dim('rule:')}  ${finding.ruleId}  ${chalk.dim(`[${finding.category}]`)}`
  );

  // What was matched (redacted)
  console.log(
    `    ${chalk.dim('match:')} ${chalk.yellow(finding.redactedText)}`
  );

  // Code snippet
  if (finding.codeSnippet) {
    console.log();
    const snippetLines = finding.codeSnippet.split('\n');
    for (const line of snippetLines) {
      // Lines starting with → are the actual match line
      if (line.trimStart().startsWith('→')) {
        console.log(`    ${chalk.red(line)}`);
      } else {
        console.log(`    ${chalk.dim(line)}`);
      }
    }
  }

  // Remediation advice
  console.log();
  console.log(`    ${chalk.dim('fix:')} ${chalk.green(finding.remediation)}`);

  // Divider
  console.log(chalk.dim('    ' + '─'.repeat(72)));
}

// ── Summary table ─────────────────────────────────────────────────────────

function printSummary(result: ScanResult): void {
  const { summary } = result;
  const duration = (result.durationMs / 1000).toFixed(2);

  console.log();
  console.log(chalk.bold('━'.repeat(76)));
  console.log(chalk.bold('  SCAN SUMMARY'));
  console.log(chalk.bold('━'.repeat(76)));
  console.log();

  // Scan metadata
  console.log(`  ${chalk.dim('target:')}   ${result.targetPath}`);
  console.log(`  ${chalk.dim('scanned:')}  ${result.filesScanned} files in ${duration}s`);
  console.log(`  ${chalk.dim('skipped:')}  ${result.filesSkipped} files`);

  // Show skip breakdown if any
  if (Object.keys(result.skippedReasons).length > 0) {
    for (const [reason, count] of Object.entries(result.skippedReasons)) {
      console.log(`             ${chalk.dim(`${count} ${reason}`)}`);
    }
  }

  if (summary.suppressedCount > 0) {
    console.log(`  ${chalk.dim('suppressed:')} ${summary.suppressedCount} findings hidden by scanner-disable comments`);
  }

  console.log();

  // Findings count with color
  if (summary.total === 0) {
    console.log(`  ${chalk.green.bold('✔ No findings detected')}`);
  } else {
    console.log(`  ${chalk.bold('Findings:')} ${chalk.bold(String(summary.total))} across ${summary.affectedFiles} file(s)`);
    console.log();

    // By severity
    const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    for (const sev of severities) {
      const count = summary.bySeverity[sev];
      if (count === 0) continue;
      const bar = '█'.repeat(Math.min(count, 30));
      const styleFunc = SEVERITY_STYLE[sev];
      console.log(
        `  ${styleFunc(` ${SEVERITY_ICON[sev]} ${sev.padEnd(10)}`)}  ${bar} ${count}`
      );
    }

    console.log();

    // By category
    console.log(`  ${chalk.dim('by category:')}`);
    for (const [cat, count] of Object.entries(summary.byCategory)) {
      if (count === 0) continue;
      console.log(`    ${cat.padEnd(16)} ${count}`);
    }

    console.log();

    // By confidence
    console.log(`  ${chalk.dim('by confidence:')}`);
    const confidences: Confidence[] = ['high', 'medium', 'low'];
    for (const conf of confidences) {
      const count = summary.byConfidence[conf];
      if (count === 0) continue;
      console.log(`    ${CONFIDENCE_DISPLAY[conf].padEnd(20)}  ${count}`);
    }
  }

  console.log();
  console.log(chalk.bold('━'.repeat(76)));
  console.log();
}

// ── Main export ───────────────────────────────────────────────────────────

export function formatResult(result: ScanResult): void {
  if (result.findings.length === 0) {
    printSummary(result);
    return;
  }

  // Group findings by file for cleaner output
  const byFile = new Map<string, Finding[]>();
  for (const finding of result.findings) {
    const existing = byFile.get(finding.filePath) ?? [];
    existing.push(finding);
    byFile.set(finding.filePath, existing);
  }

  // Print file header then findings for each file
  let index = 0;
  for (const [filePath, findings] of byFile) {
    console.log();
    console.log(chalk.bold.underline(`  ${filePath}`) + chalk.dim(`  (${findings.length} finding${findings.length > 1 ? 's' : ''})`));
    for (const finding of findings) {
      printFinding(finding, index++);
    }
  }

  printSummary(result);
}