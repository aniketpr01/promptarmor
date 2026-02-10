/**
 * PromptArmor VS Code Extension
 * 
 * Real-time prompt injection detection for LLM applications
 */

import * as vscode from 'vscode';

// Inline scanner to avoid dependency issues during development
// In production, this would import from 'promptarmor'

interface ScanMatch {
  ruleId: string;
  ruleName: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
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

interface DetectionRule {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  fix?: string;
}

// Core detection rules (subset for extension)
const rules: DetectionRule[] = [
  {
    id: 'INJ001',
    name: 'Ignore Instructions',
    description: 'Attempts to make the AI ignore previous instructions',
    category: 'instruction-override',
    severity: 'critical',
    pattern: /ignore\s+(all\s+)?(previous|above|prior|earlier|preceding)\s+(instructions?|prompts?|rules?|guidelines?|constraints?)/gi,
    fix: 'Remove or sanitize user input that attempts to override system instructions',
  },
  {
    id: 'INJ002',
    name: 'Forget Instructions',
    description: 'Attempts to make the AI forget its instructions',
    category: 'instruction-override',
    severity: 'critical',
    pattern: /forget\s+(all\s+)?(your\s+)?(previous|above|prior|earlier|the)?\s*(instructions?|prompts?|rules?|programming|training|guidelines?)/gi,
    fix: 'Validate input does not contain instruction manipulation attempts',
  },
  {
    id: 'INJ005',
    name: 'System Override',
    description: 'Attempts to override system-level settings',
    category: 'instruction-override',
    severity: 'critical',
    pattern: /\[?\s*(system|admin|root|sudo)\s*\]?\s*:|\b(admin|root|sudo)\s+(override|command|mode)/gi,
    fix: 'Sanitize inputs that mimic system-level commands',
  },
  {
    id: 'ROLE001',
    name: 'Role Assignment',
    description: 'Attempts to assign a new role to the AI',
    category: 'role-manipulation',
    severity: 'high',
    pattern: /(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\'?re)|roleplay\s+as|play\s+the\s+role\s+of|imagine\s+you\'?re)\s+(a\s+)?(\w+)/gi,
    fix: 'Block role reassignment attempts in user input',
  },
  {
    id: 'ROLE002',
    name: 'DAN Pattern',
    description: 'Attempts to use the "Do Anything Now" jailbreak',
    category: 'role-manipulation',
    severity: 'critical',
    pattern: /\b(DAN|do\s+anything\s+now|jailbreak|uncensored|unfiltered|no\s+restrictions?)\b/gi,
    fix: 'Block known jailbreak patterns',
  },
  {
    id: 'EXFIL001',
    name: 'System Prompt Leak',
    description: 'Attempts to extract the system prompt',
    category: 'data-exfiltration',
    severity: 'high',
    pattern: /(reveal|show|display|print|output|tell\s+me|what\s+(is|are))\s+(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+prompt|hidden\s+instructions?|secret\s+instructions?)/gi,
    fix: 'Do not expose system prompts to users',
  },
  {
    id: 'JAIL001',
    name: 'Hypothetical Scenario',
    description: 'Uses hypothetical framing to bypass restrictions',
    category: 'jailbreak',
    severity: 'medium',
    pattern: /(hypothetically|in\s+theory|theoretically|imagine\s+if|what\s+if|let\'?s\s+say|pretend\s+that|assume\s+that)[,\s]+.{0,50}(how\s+(would|to|could)|make|create|build|hack|break|bypass)/gi,
    fix: 'Apply same restrictions to hypothetical scenarios',
  },
  {
    id: 'ENC001',
    name: 'Base64 Encoded Content',
    description: 'Detects Base64 encoded content that may hide injections',
    category: 'encoding-bypass',
    severity: 'medium',
    pattern: /([A-Za-z0-9+/]{20,}={0,2})/g,
    fix: 'Decode and scan Base64 content before processing',
  },
  {
    id: 'DELIM001',
    name: 'Fake Delimiter',
    description: 'Attempts to inject fake system/user delimiters',
    category: 'delimiter-confusion',
    severity: 'high',
    pattern: /(```\s*(system|assistant|user)\s*```|<\|?(system|user|assistant|im_start|im_end)\|?>|\[\[(system|user|assistant)\]\]|###\s*(system|user|assistant)\s*:)/gi,
    fix: 'Escape or remove delimiter-like patterns from user input',
  },
  {
    id: 'CTX002',
    name: 'Conversation Hijack',
    description: 'Attempts to hijack the conversation flow',
    category: 'context-manipulation',
    severity: 'medium',
    pattern: /(from\s+now\s+on|going\s+forward|henceforth|starting\s+now|from\s+this\s+point)\s*.*(you\s+will|you\s+must|you\s+should|always|never)/gi,
    fix: 'Block persistent state manipulation attempts',
  },
];

// Severity to diagnostic severity mapping
const severityMap: Record<string, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

// Diagnostic collection
let diagnosticCollection: vscode.DiagnosticCollection;

// Debounce timer
let debounceTimer: NodeJS.Timeout | undefined;

/**
 * Scan text for prompt injection vulnerabilities
 */
function scanText(text: string): ScanMatch[] {
  const matches: ScanMatch[] = [];
  
  for (const rule of rules) {
    rule.pattern.lastIndex = 0;
    
    let match: RegExpExecArray | null;
    while ((match = rule.pattern.exec(text)) !== null) {
      const lines = text.substring(0, match.index).split('\n');
      const line = lines.length;
      const column = lines[lines.length - 1].length + 1;
      
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
          line,
          column,
        },
        fix: rule.fix,
      });
    }
  }
  
  return matches;
}

/**
 * Update diagnostics for a document
 */
function updateDiagnostics(document: vscode.TextDocument): void {
  const config = vscode.workspace.getConfiguration('promptarmor');
  
  if (!config.get('enable', true)) {
    diagnosticCollection.delete(document.uri);
    return;
  }
  
  const minSeverity = config.get('severity', 'low') as string;
  const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
  const minSeverityIndex = severityOrder.indexOf(minSeverity);
  
  const text = document.getText();
  const matches = scanText(text);
  
  const diagnostics: vscode.Diagnostic[] = matches
    .filter(m => severityOrder.indexOf(m.severity) >= minSeverityIndex)
    .map(match => {
      const startPos = document.positionAt(match.position.start);
      const endPos = document.positionAt(match.position.end);
      const range = new vscode.Range(startPos, endPos);
      
      const diagnostic = new vscode.Diagnostic(
        range,
        `[${match.ruleId}] ${match.ruleName}: ${match.description}`,
        severityMap[match.severity]
      );
      
      diagnostic.source = 'PromptArmor';
      diagnostic.code = match.ruleId;
      
      return diagnostic;
    });
  
  diagnosticCollection.set(document.uri, diagnostics);
}

/**
 * Debounced update for real-time scanning
 */
function debouncedUpdate(document: vscode.TextDocument): void {
  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }
  
  debounceTimer = setTimeout(() => {
    updateDiagnostics(document);
  }, 300);
}

/**
 * Extension activation
 */
export function activate(context: vscode.ExtensionContext): void {
  console.log('PromptArmor extension activated');
  
  // Create diagnostic collection
  diagnosticCollection = vscode.languages.createDiagnosticCollection('promptarmor');
  context.subscriptions.push(diagnosticCollection);
  
  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('promptarmor.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        updateDiagnostics(editor.document);
        vscode.window.showInformationMessage('PromptArmor: Scan complete');
      }
    })
  );
  
  context.subscriptions.push(
    vscode.commands.registerCommand('promptarmor.scanSelection', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor && !editor.selection.isEmpty) {
        const text = editor.document.getText(editor.selection);
        const matches = scanText(text);
        
        if (matches.length === 0) {
          vscode.window.showInformationMessage('PromptArmor: No vulnerabilities found in selection');
        } else {
          vscode.window.showWarningMessage(
            `PromptArmor: Found ${matches.length} vulnerabilities in selection`
          );
        }
      }
    })
  );
  
  context.subscriptions.push(
    vscode.commands.registerCommand('promptarmor.scanWorkspace', async () => {
      const config = vscode.workspace.getConfiguration('promptarmor');
      const patterns = config.get('filePatterns', ['**/*.txt', '**/*.md']) as string[];
      
      let totalVulns = 0;
      let filesScanned = 0;
      
      for (const pattern of patterns) {
        const files = await vscode.workspace.findFiles(pattern, '**/node_modules/**');
        
        for (const file of files) {
          const document = await vscode.workspace.openTextDocument(file);
          updateDiagnostics(document);
          
          const diagnostics = diagnosticCollection.get(document.uri);
          if (diagnostics) {
            totalVulns += diagnostics.length;
          }
          filesScanned++;
        }
      }
      
      vscode.window.showInformationMessage(
        `PromptArmor: Scanned ${filesScanned} files, found ${totalVulns} vulnerabilities`
      );
    })
  );
  
  // Scan on document open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(document => {
      updateDiagnostics(document);
    })
  );
  
  // Scan on document save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(document => {
      const config = vscode.workspace.getConfiguration('promptarmor');
      if (config.get('scanOnSave', true)) {
        updateDiagnostics(document);
      }
    })
  );
  
  // Real-time scanning
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(event => {
      const config = vscode.workspace.getConfiguration('promptarmor');
      if (config.get('scanOnType', true)) {
        debouncedUpdate(event.document);
      }
    })
  );
  
  // Scan all open documents
  vscode.workspace.textDocuments.forEach(document => {
    updateDiagnostics(document);
  });
}

/**
 * Extension deactivation
 */
export function deactivate(): void {
  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }
}
