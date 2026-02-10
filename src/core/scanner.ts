/**
 * PromptArmor Scanner Engine
 * 
 * Core scanning logic for detecting prompt injection vulnerabilities
 */

import { injectionRules, type DetectionRule, type Severity } from '../rules/injection-patterns.js';

export interface ScanMatch {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  category: string;
  description: string;
  match: string;
  position: {
    start: number;
    end: number;
    line: number;
    column: number;
  };
  fix?: string;
}

export interface ScanResult {
  file?: string;
  content: string;
  matches: ScanMatch[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  score: number; // 0-100, higher = more vulnerable
  passed: boolean;
}

export interface ScanOptions {
  /** Minimum severity to report */
  minSeverity?: Severity;
  /** Categories to include (empty = all) */
  categories?: string[];
  /** Custom rules to add */
  customRules?: DetectionRule[];
  /** Skip specific rule IDs */
  skipRules?: string[];
  /** Threshold score for pass/fail (default: 50) */
  threshold?: number;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 1,
};

/**
 * Get line and column from character position
 */
function getLineAndColumn(content: string, position: number): { line: number; column: number } {
  const lines = content.substring(0, position).split('\n');
  return {
    line: lines.length,
    column: lines[lines.length - 1].length + 1,
  };
}

/**
 * Check if a severity meets the minimum threshold
 */
function meetsSeverityThreshold(severity: Severity, minSeverity: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[minSeverity];
}

/**
 * Main scanner class
 */
export class PromptScanner {
  private rules: DetectionRule[];
  private options: ScanOptions;

  constructor(options: ScanOptions = {}) {
    this.options = {
      minSeverity: 'low',
      threshold: 50,
      ...options,
    };

    // Build rule set
    let rules = [...injectionRules];

    // Add custom rules
    if (options.customRules) {
      rules = [...rules, ...options.customRules];
    }

    // Filter by category
    if (options.categories && options.categories.length > 0) {
      rules = rules.filter(rule => options.categories!.includes(rule.category));
    }

    // Skip specific rules
    if (options.skipRules && options.skipRules.length > 0) {
      rules = rules.filter(rule => !options.skipRules!.includes(rule.id));
    }

    // Filter by severity
    if (options.minSeverity) {
      rules = rules.filter(rule => 
        meetsSeverityThreshold(rule.severity, options.minSeverity!)
      );
    }

    this.rules = rules;
  }

  /**
   * Scan content for prompt injection vulnerabilities
   */
  scan(content: string, file?: string): ScanResult {
    const matches: ScanMatch[] = [];

    for (const rule of this.rules) {
      // Reset regex lastIndex for global patterns
      rule.pattern.lastIndex = 0;

      let match: RegExpExecArray | null;
      
      // Handle global regex
      if (rule.pattern.global) {
        while ((match = rule.pattern.exec(content)) !== null) {
          const position = getLineAndColumn(content, match.index);
          matches.push({
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            category: rule.category,
            description: rule.description,
            match: match[0],
            position: {
              start: match.index,
              end: match.index + match[0].length,
              ...position,
            },
            fix: rule.fix,
          });
        }
      } else {
        match = rule.pattern.exec(content);
        if (match) {
          const position = getLineAndColumn(content, match.index);
          matches.push({
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            category: rule.category,
            description: rule.description,
            match: match[0],
            position: {
              start: match.index,
              end: match.index + match[0].length,
              ...position,
            },
            fix: rule.fix,
          });
        }
      }
    }

    // Calculate summary
    const summary = {
      total: matches.length,
      critical: matches.filter(m => m.severity === 'critical').length,
      high: matches.filter(m => m.severity === 'high').length,
      medium: matches.filter(m => m.severity === 'medium').length,
      low: matches.filter(m => m.severity === 'low').length,
      info: matches.filter(m => m.severity === 'info').length,
    };

    // Calculate vulnerability score (0-100)
    const score = Math.min(100, matches.reduce((acc, m) => {
      return acc + SEVERITY_WEIGHTS[m.severity];
    }, 0));

    // Determine pass/fail
    const passed = score < (this.options.threshold ?? 50);

    return {
      file,
      content,
      matches,
      summary,
      score,
      passed,
    };
  }

  /**
   * Quick check if content contains any vulnerabilities
   */
  hasVulnerabilities(content: string): boolean {
    for (const rule of this.rules) {
      rule.pattern.lastIndex = 0;
      if (rule.pattern.test(content)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Get loaded rules
   */
  getRules(): DetectionRule[] {
    return [...this.rules];
  }
}

/**
 * Create a scanner with default options
 */
export function createScanner(options?: ScanOptions): PromptScanner {
  return new PromptScanner(options);
}

/**
 * Quick scan function for simple use cases
 */
export function scan(content: string, options?: ScanOptions): ScanResult {
  const scanner = createScanner(options);
  return scanner.scan(content);
}
