// src/types/index.ts

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingCategory = 'secret' | 'vulnerability' | 'hygiene';

// NEW in Phase 2
// How certain are we this is a real issue?
// high   = very specific pattern, almost always correct (e.g. AKIA[0-9A-Z]{16})
// medium = good signal but could be a false positive in some contexts
// low    = heuristic-based, check manually
export type Confidence = 'high' | 'medium' | 'low';

export interface Finding {
  ruleId: string;
  ruleName: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;       // NEW

  filePath: string;
  line: number;
  column: number;

  matchedText: string;
  redactedText: string;
  message: string;
  remediation: string;
  codeSnippet?: string;

  suppressed: boolean;          // NEW — true if a scanner-disable comment was found
  suppressionReason?: string;   // NEW — what the developer wrote in the disable comment
}

// NEW in Phase 2
// Passed to context-aware rules so they can inspect surroundings
export interface RuleContext {
  // The line that matched
  matchedLine: string;
  lineIndex: number;

  // The full file split into lines (for looking at surrounding context)
  allLines: string[];

  // Metadata about the file
  filePath: string;
  fileExtension: string;

  // Is this likely a test file? (affects confidence for some rules)
  isTestFile: boolean;
}

export interface ScanRule {
  id: string;
  name: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;       // NEW
  description: string;
  remediation: string;
  pattern: RegExp;
  fileExtensions?: string[];
  highFalsePositiveRate?: boolean;

  // NEW — optional hook that runs after a regex match
  // Return false to suppress the finding (e.g. "this looks like a test")
  // Return a string to override the message
  // Return true (or undefined) to accept the finding as-is
  contextCheck?: (context: RuleContext) => boolean | string;
}

export interface ScanConfig {
  targetPath: string;
  severities?: Severity[];
  categories?: FindingCategory[];
  maxFileSizeBytes?: number;
  ignorePatterns?: string[];
  includeHighFalsePositives?: boolean;
  includeSuppressed?: boolean;  // NEW — show suppressed findings in output
}

export interface ScanResult {
  scannedAt: Date;
  targetPath: string;
  durationMs: number;
  filesScanned: number;
  filesSkipped: number;
  skippedReasons: Record<string, number>;
  findings: Finding[];
  summary: ScanSummary;
}

export interface ScanSummary {
  total: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<FindingCategory, number>;
  byConfidence: Record<Confidence, number>;   // NEW
  affectedFiles: number;
  suppressedCount: number;                    // NEW
}