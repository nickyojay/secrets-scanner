#!/usr/bin/env node

import * as path from 'path';
import { scan } from '../scanner/engine';
import { ScanConfig, Severity, FindingCategory } from '../types';
import { formatResult } from './formatter';
import { formatJson } from './jsonOutput';

// ── Help text ─────────────────────────────────────────────────────────────

const HELP = `
secrets-scan — scan files and directories for secrets and vulnerabilities

USAGE
  secrets-scan <path> [options]

OPTIONS
  --severity <levels>     Comma-separated severities to include
                          Values: critical, high, medium, low, info
                          Example: --severity critical,high

  --category <types>      Comma-separated categories to include
                          Values: secret, vulnerability, hygiene
                          Example: --category secret,vulnerability

  --format <format>       Output format (default: text)
                          Values: text, json

  --fail-on <severity>    Exit with code 1 if findings at this severity
                          or above are found. Useful for CI/CD pipelines.
                          Example: --fail-on critical

  --show-suppressed       Include findings silenced by scanner-disable comments

  --include-all           Include high false-positive rate rules

  --max-file-size <bytes> Maximum file size to scan in bytes (default: 1048576)

  --help                  Show this help message

EXAMPLES
  secrets-scan .
  secrets-scan ./src --severity critical,high
  secrets-scan ./src --format json > findings.json
  secrets-scan ./src --fail-on high --format json
  secrets-scan ./src --category secret
`;

// ── Argument parsing ──────────────────────────────────────────────────────

interface CliArgs {
  targetPath: string;
  severities: Severity[] | undefined;
  categories: FindingCategory[] | undefined;
  format: 'text' | 'json';
  failOn: Severity | undefined;
  showSuppressed: boolean;
  includeAll: boolean;
  maxFileSize: number | undefined;
  help: boolean;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high:     4,
  medium:   3,
  low:      2,
  info:     1,
};

const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const VALID_CATEGORIES = new Set(['secret', 'vulnerability', 'hygiene']);

// Returns all severities at or above the given level
// e.g. severitiesAbove('high') → ['critical', 'high']
function severitiesAtOrAbove(level: Severity): Severity[] {
  return (Object.keys(SEVERITY_ORDER) as Severity[]).filter(
    s => SEVERITY_ORDER[s] >= SEVERITY_ORDER[level]
  );
}

function parseArgs(argv: string[]): CliArgs {
  // argv[0] = node, argv[1] = script path, argv[2+] = our args
  const args = argv.slice(2);

  const result: CliArgs = {
    targetPath: '.',
    severities: undefined,
    categories: undefined,
    format: 'text',
    failOn: undefined,
    showSuppressed: false,
    includeAll: false,
    maxFileSize: undefined,
    help: false,
  };

  // First non-flag argument is the target path
  if (args.length > 0 && !args[0].startsWith('--')) {
    result.targetPath = args[0];
  }

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h') {
      result.help = true;
      continue;
    }

    if (arg === '--show-suppressed') {
      result.showSuppressed = true;
      continue;
    }

    if (arg === '--include-all') {
      result.includeAll = true;
      continue;
    }

    // Flags that take a value
    const nextArg = args[i + 1];

    if (arg === '--severity') {
      if (!nextArg) {
        console.error('Error: --severity requires a value (e.g. --severity critical,high)');
        process.exit(1);
      }
      const parsed = nextArg.split(',').map(s => s.trim());
      const invalid = parsed.filter(s => !VALID_SEVERITIES.has(s));
      if (invalid.length > 0) {
        console.error(`Error: unrecognised severity value(s): ${invalid.join(', ')}`);
        console.error(`Valid values are: critical, high, medium, low, info`);
        console.error(`Separate multiple values with commas, not dots: --severity critical,high`);
        process.exit(1);
      }
      result.severities = parsed as Severity[];
      i++;
      continue;
    }

    if (arg === '--category') {
      if (!nextArg) {
        console.error('Error: --category requires a value (e.g. --category secret,vulnerability)');
        process.exit(1);
      }
      const parsed = nextArg.split(',').map(s => s.trim());
      const invalid = parsed.filter(s => !VALID_CATEGORIES.has(s));
      if (invalid.length > 0) {
        console.error(`Error: unrecognised category value(s): ${invalid.join(', ')}`);
        console.error(`Valid values are: secret, vulnerability, hygiene`);
        process.exit(1);
      }
      result.categories = parsed as FindingCategory[];
      i++;
      continue;
    }

    if (arg === '--fail-on') {
      if (!nextArg) {
        console.error('Error: --fail-on requires a severity (e.g. --fail-on critical)');
        process.exit(1);
      }
      result.failOn = nextArg as Severity;
      i++;
      continue;
    }

    if (arg === '--max-file-size') {
      if (!nextArg || isNaN(Number(nextArg))) {
        console.error('Error: --max-file-size requires a number (bytes)');
        process.exit(1);
      }
      result.maxFileSize = Number(nextArg);
      i++;
      continue;
    }
    // Warn on any unrecognised flag rather than silently ignoring it
    if (arg.startsWith('--')) {
      console.error(`Error: unrecognised option "${arg}"`);
      console.error(`Run with --help to see available options`);
      process.exit(1);
    }
  }

  return result;
}

// ── Main ──────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = parseArgs(process.argv);

  if (args.help) {
    console.log(HELP);
    process.exit(0);
  }

  // Resolve the target path relative to where the command was run
  const targetPath = path.resolve(process.cwd(), args.targetPath);

  const config: ScanConfig = {
    targetPath,
    severities: args.severities,
    categories: args.categories,
    maxFileSizeBytes: args.maxFileSize,
    includeSuppressed: args.showSuppressed,
    includeHighFalsePositives: args.includeAll,
  };

  // Show a spinner-like message so the user knows it's running
  // (only in text mode — JSON output should be pure JSON)
  if (args.format === 'text') {
    process.stderr.write(`\nScanning ${targetPath}...\n`);
  }

  try {
    const result = await scan(config);

    // Output the results
    if (args.format === 'json') {
      console.log(formatJson(result));
    } else {
      formatResult(result);
    }

    // Handle --fail-on exit code
    if (args.failOn) {
      const threshold = SEVERITY_ORDER[args.failOn];
      const hasFailingFindings = result.findings.some(
        f => SEVERITY_ORDER[f.severity] >= threshold
      );
      if (hasFailingFindings) {
        if (args.format === 'text') {
          process.stderr.write(
            `\nExiting with code 1 — findings at or above "${args.failOn}" severity detected.\n\n`
          );
        }
        process.exit(1);
      }
    }

    process.exit(0);

  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`\nError: ${message}\n`);
    process.exit(1);
  }
}

main();