// src/cli/jsonOutput.ts

import { ScanResult, Finding } from '../types';

// A cleaned up version of Finding safe for JSON output
// We explicitly omit matchedText so raw secrets never appear in JSON logs
interface JsonFinding {
  ruleId: string;
  ruleName: string;
  category: string;
  severity: string;
  confidence: string;
  filePath: string;
  line: number;
  column: number;
  redactedText: string;
  message: string;
  remediation: string;
  suppressed: boolean;
  suppressionReason?: string;
}

interface JsonOutput {
  meta: {
    scannedAt: string;
    targetPath: string;
    durationMs: number;
    filesScanned: number;
    filesSkipped: number;
    skippedReasons: Record<string, number>;
  };
  summary: {
    total: number;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
    byConfidence: Record<string, number>;
    affectedFiles: number;
    suppressedCount: number;
  };
  findings: JsonFinding[];
}

function toJsonFinding(finding: Finding): JsonFinding {
  return {
    ruleId: finding.ruleId,
    ruleName: finding.ruleName,
    category: finding.category,
    severity: finding.severity,
    confidence: finding.confidence,
    filePath: finding.filePath,
    line: finding.line,
    column: finding.column,
    redactedText: finding.redactedText,
    message: finding.message,
    remediation: finding.remediation,
    suppressed: finding.suppressed,
    suppressionReason: finding.suppressionReason,
  };
}

export function formatJson(result: ScanResult): string {
  const output: JsonOutput = {
    meta: {
      scannedAt: result.scannedAt.toISOString(),
      targetPath: result.targetPath,
      durationMs: result.durationMs,
      filesScanned: result.filesScanned,
      filesSkipped: result.filesSkipped,
      skippedReasons: result.skippedReasons,
    },
    summary: result.summary,
    findings: result.findings.map(toJsonFinding),
  };

  return JSON.stringify(output, null, 2);
}