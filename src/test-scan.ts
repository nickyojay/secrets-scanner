import { scan } from './scanner/engine';
import { Finding, Severity } from './types';

const COLORS: Record<Severity, string> = {
  critical: '\x1b[31m',   // red
  high:     '\x1b[91m',   // bright red
  medium:   '\x1b[33m',   // yellow
  low:      '\x1b[36m',   // cyan
  info:     '\x1b[37m',   // white
};
const RESET = '\x1b[0m';
const BOLD  = '\x1b[1m';
const DIM   = '\x1b[2m';

function printFinding(finding: Finding, index: number): void {
  const color = COLORS[finding.severity];
  console.log(`\n${BOLD}Finding #${index + 1}${RESET}`);
  console.log(`  ${color}[${finding.severity.toUpperCase()}]${RESET} ${BOLD}${finding.ruleName}${RESET}`);
  console.log(`  ${DIM}File:${RESET}  ${finding.filePath}:${finding.line}`);
  console.log(`  ${DIM}Match:${RESET} ${finding.redactedText}`);
  console.log(`  ${DIM}Fix:${RESET}   ${finding.remediation.split('.')[0]}.`);

  if (finding.codeSnippet) {
    console.log(`\n  ${DIM}Context:${RESET}`);
    finding.codeSnippet.split('\n').forEach(line => {
      console.log(`    ${DIM}${line}${RESET}`);
    });
  }
}

async function main() {
  console.log(`${BOLD}🔍 Secrets Scanner — Phase 1 Test${RESET}\n`);

  const result = await scan({
    targetPath: './test-fixtures',
    includeHighFalsePositives: true,
  });

  if (result.findings.length === 0) {
    console.log('No findings — something is wrong with the scanner or fixtures!');
    process.exit(1);
  }

  result.findings.forEach((f, i) => printFinding(f, i));

  console.log(`\n${'─'.repeat(60)}`);
  console.log(`${BOLD}SUMMARY${RESET}`);
  console.log(`${'─'.repeat(60)}`);
  console.log(`Files scanned:  ${result.filesScanned}`);
  console.log(`Files skipped:  ${result.filesSkipped}`);
  console.log(`Total findings: ${BOLD}${result.summary.total}${RESET}\n`);

  const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  for (const sev of severities) {
    const count = result.summary.bySeverity[sev];
    if (count > 0) {
      console.log(`  ${COLORS[sev]}${sev.padEnd(10)}${RESET} ${count}`);
    }
  }

  console.log('\n✅ Scanner engine working!\n');
}

main().catch(err => {
  console.error('Scanner crashed:', err);
  process.exit(1);
});