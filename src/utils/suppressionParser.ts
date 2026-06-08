// src/utils/suppressionParser.ts

export interface SuppressionInfo {
  // Set of 1-indexed line numbers that are suppressed
  suppressedLines: Set<number>;
  // Map from line number to the reason given (if any)
  reasons: Map<number, string>;
}

// Matches:
//   // scanner-disable
//   // scanner-disable: this is intentional because XYZ
//   /* scanner-disable */
const SUPPRESSION_PATTERN = /\/\/\s*scanner-disable(?:\s*:\s*(.+))?|\/\*\s*scanner-disable(?:\s*:\s*(.+?))?\s*\*\//i;

export function parseSuppressions(lines: string[]): SuppressionInfo {
  const suppressedLines = new Set<number>();
  const reasons = new Map<number, string>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const match = SUPPRESSION_PATTERN.exec(line);

    if (!match) continue;

    const reason = (match[1] || match[2] || '').trim();
    const lineNumber = i + 1; // 1-indexed

    // The suppression comment can be:
    // 1. On the same line as the finding (inline suppression)
    // 2. On the line ABOVE the finding (next-line suppression)
    suppressedLines.add(lineNumber);       // same line
    suppressedLines.add(lineNumber + 1);   // next line

    if (reason) {
      reasons.set(lineNumber, reason);
      reasons.set(lineNumber + 1, reason);
    }
  }

  return { suppressedLines, reasons };
}

// Helper — checks if a given 1-indexed line number is suppressed
export function isLineSuppressed(
  lineNumber: number,
  suppressionInfo: SuppressionInfo,
): boolean {
  return suppressionInfo.suppressedLines.has(lineNumber);
}