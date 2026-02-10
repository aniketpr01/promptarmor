/**
 * PromptArmor CLI
 * 
 * Command-line interface for scanning prompts for injection vulnerabilities
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import { glob } from 'glob';
import { createScanner, type ScanResult, type ScanMatch } from '../core/scanner.js';
import type { Severity } from '../rules/injection-patterns.js';

const VERSION = '0.1.0';

const program = new Command();

// Severity colors
const severityColors: Record<Severity, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

const severityIcons: Record<Severity, string> = {
  critical: '🚨',
  high: '⚠️',
  medium: '⚡',
  low: 'ℹ️',
  info: '💡',
};

/**
 * Format a single match for CLI output
 */
function formatMatch(match: ScanMatch, content: string): string {
  const lines: string[] = [];
  const color = severityColors[match.severity];
  const icon = severityIcons[match.severity];
  
  // Header
  lines.push(`  ${icon} ${color(match.severity.toUpperCase())} ${chalk.bold(match.ruleName)} ${chalk.dim(`(${match.ruleId})`)}`);
  
  // Location
  lines.push(`     ${chalk.dim('at')} line ${match.position.line}, column ${match.position.column}`);
  
  // Description
  lines.push(`     ${chalk.dim(match.description)}`);
  
  // Matched text (truncated)
  const matchText = match.match.length > 60 
    ? match.match.substring(0, 60) + '...' 
    : match.match;
  lines.push(`     ${chalk.dim('match:')} ${chalk.cyan(`"${matchText}"`)}`);
  
  // Fix suggestion
  if (match.fix) {
    lines.push(`     ${chalk.green('fix:')} ${match.fix}`);
  }
  
  return lines.join('\n');
}

/**
 * Format scan result for CLI output
 */
function formatResult(result: ScanResult): string {
  const lines: string[] = [];
  
  // File header
  if (result.file) {
    lines.push(chalk.bold.underline(`\n${result.file}`));
  }
  
  if (result.matches.length === 0) {
    lines.push(chalk.green('  ✓ No vulnerabilities detected'));
    return lines.join('\n');
  }
  
  // Group matches by severity
  const grouped: Record<Severity, ScanMatch[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: [],
  };
  
  for (const match of result.matches) {
    grouped[match.severity].push(match);
  }
  
  // Output matches by severity
  const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  for (const severity of severityOrder) {
    const matches = grouped[severity];
    if (matches.length > 0) {
      lines.push('');
      for (const match of matches) {
        lines.push(formatMatch(match, result.content));
      }
    }
  }
  
  return lines.join('\n');
}

/**
 * Format summary for CLI output
 */
function formatSummary(results: ScanResult[]): string {
  const lines: string[] = [];
  
  const totals = {
    files: results.length,
    vulnerabilities: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    passed: 0,
    failed: 0,
  };
  
  for (const result of results) {
    totals.vulnerabilities += result.summary.total;
    totals.critical += result.summary.critical;
    totals.high += result.summary.high;
    totals.medium += result.summary.medium;
    totals.low += result.summary.low;
    totals.info += result.summary.info;
    if (result.passed) {
      totals.passed++;
    } else {
      totals.failed++;
    }
  }
  
  lines.push('\n' + chalk.bold('═'.repeat(50)));
  lines.push(chalk.bold('Summary'));
  lines.push(chalk.bold('═'.repeat(50)));
  
  lines.push(`Files scanned:    ${totals.files}`);
  lines.push(`Vulnerabilities:  ${totals.vulnerabilities}`);
  
  if (totals.vulnerabilities > 0) {
    lines.push('');
    if (totals.critical > 0) lines.push(`  ${severityColors.critical(' CRITICAL ')} ${totals.critical}`);
    if (totals.high > 0) lines.push(`  ${severityColors.high('HIGH')}      ${totals.high}`);
    if (totals.medium > 0) lines.push(`  ${severityColors.medium('MEDIUM')}    ${totals.medium}`);
    if (totals.low > 0) lines.push(`  ${severityColors.low('LOW')}       ${totals.low}`);
    if (totals.info > 0) lines.push(`  ${severityColors.info('INFO')}      ${totals.info}`);
  }
  
  lines.push('');
  if (totals.failed > 0) {
    lines.push(chalk.red.bold(`✗ ${totals.failed} file(s) failed security check`));
  } else {
    lines.push(chalk.green.bold('✓ All files passed security check'));
  }
  
  return lines.join('\n');
}

/**
 * Scan command handler
 */
async function handleScan(patterns: string[], options: {
  output?: string;
  severity?: string;
  threshold?: string;
  json?: boolean;
  quiet?: boolean;
}) {
  const spinner = ora('Scanning for vulnerabilities...').start();
  
  try {
    // Expand glob patterns
    let files: string[] = [];
    
    for (const pattern of patterns) {
      // Check if it's a file or directory
      if (existsSync(pattern)) {
        const stat = statSync(pattern);
        if (stat.isDirectory()) {
          // Scan directory for common prompt files
          const dirFiles = await glob(`${pattern}/**/*.{txt,md,json,yaml,yml,prompt}`, {
            ignore: ['**/node_modules/**', '**/dist/**', '**/.git/**'],
          });
          files.push(...dirFiles);
        } else {
          files.push(pattern);
        }
      } else {
        // Treat as glob pattern
        const matched = await glob(pattern, {
          ignore: ['**/node_modules/**', '**/dist/**', '**/.git/**'],
        });
        files.push(...matched);
      }
    }
    
    // Remove duplicates
    files = [...new Set(files)];
    
    if (files.length === 0) {
      spinner.fail('No files found matching the pattern');
      process.exit(1);
    }
    
    spinner.text = `Scanning ${files.length} file(s)...`;
    
    // Create scanner
    const scanner = createScanner({
      minSeverity: (options.severity as Severity) || 'low',
      threshold: options.threshold ? parseInt(options.threshold, 10) : 50,
    });
    
    // Scan files
    const results: ScanResult[] = [];
    
    for (const file of files) {
      const content = readFileSync(file, 'utf-8');
      const result = scanner.scan(content, relative(process.cwd(), file));
      results.push(result);
    }
    
    spinner.stop();
    
    // Output results
    if (options.json) {
      console.log(JSON.stringify(results, null, 2));
    } else {
      // CLI output
      if (!options.quiet) {
        console.log(chalk.bold('\n🛡️  PromptArmor Scan Results\n'));
        
        for (const result of results) {
          console.log(formatResult(result));
        }
        
        console.log(formatSummary(results));
      }
    }
    
    // Exit with error if any files failed
    const failed = results.some(r => !r.passed);
    process.exit(failed ? 1 : 0);
    
  } catch (error) {
    spinner.fail(`Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    process.exit(1);
  }
}

/**
 * Check command handler - scan from stdin
 */
async function handleCheck(options: { json?: boolean }) {
  const chunks: Buffer[] = [];
  
  process.stdin.on('data', (chunk) => chunks.push(chunk));
  
  process.stdin.on('end', () => {
    const content = Buffer.concat(chunks).toString('utf-8');
    
    if (!content.trim()) {
      console.error(chalk.red('Error: No input provided'));
      process.exit(1);
    }
    
    const scanner = createScanner();
    const result = scanner.scan(content);
    
    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(chalk.bold('\n🛡️  PromptArmor Check Results\n'));
      console.log(formatResult(result));
      
      if (result.matches.length > 0) {
        console.log(`\n${chalk.bold('Score:')} ${result.score}/100 (threshold: 50)`);
        console.log(result.passed 
          ? chalk.green('✓ Passed') 
          : chalk.red('✗ Failed')
        );
      }
    }
    
    process.exit(result.passed ? 0 : 1);
  });
}

// CLI setup
program
  .name('promptarmor')
  .description('Prompt injection security scanner for LLM applications')
  .version(VERSION);

program
  .command('scan')
  .description('Scan files for prompt injection vulnerabilities')
  .argument('<patterns...>', 'File patterns to scan (supports globs)')
  .option('-o, --output <file>', 'Write results to file')
  .option('-s, --severity <level>', 'Minimum severity to report (critical|high|medium|low|info)', 'low')
  .option('-t, --threshold <score>', 'Vulnerability score threshold for pass/fail (0-100)', '50')
  .option('-j, --json', 'Output results as JSON')
  .option('-q, --quiet', 'Suppress output (exit code only)')
  .action(handleScan);

program
  .command('check')
  .description('Check content from stdin')
  .option('-j, --json', 'Output results as JSON')
  .action(handleCheck);

program
  .command('rules')
  .description('List available detection rules')
  .option('-c, --category <name>', 'Filter by category')
  .action((options) => {
    const scanner = createScanner();
    const rules = scanner.getRules();
    
    const filtered = options.category 
      ? rules.filter(r => r.category === options.category)
      : rules;
    
    console.log(chalk.bold('\n🛡️  PromptArmor Detection Rules\n'));
    
    // Group by category
    const categories = new Map<string, typeof rules>();
    for (const rule of filtered) {
      if (!categories.has(rule.category)) {
        categories.set(rule.category, []);
      }
      categories.get(rule.category)!.push(rule);
    }
    
    for (const [category, categoryRules] of categories) {
      console.log(chalk.bold.underline(`\n${category}`));
      for (const rule of categoryRules) {
        const color = severityColors[rule.severity];
        console.log(`  ${color(rule.severity.padEnd(8))} ${rule.id.padEnd(10)} ${rule.name}`);
      }
    }
    
    console.log(`\n${chalk.dim(`Total: ${filtered.length} rules`)}\n`);
  });

// Parse and run
program.parse();
