# 🛡️ PromptArmor

> Prompt injection security scanner for LLM applications

[![npm version](https://badge.fury.io/js/promptarmor.svg)](https://www.npmjs.com/package/promptarmor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

PromptArmor is a dead-simple CLI tool and library for detecting prompt injection vulnerabilities before they reach production. One command to scan, clear results, actionable fixes.

## Why PromptArmor?

- **OWASP ranks prompt injection as #1 LLM security threat** (2025)
- Only 34.7% of enterprises have deployed dedicated defenses
- OpenAI admits prompt injection "may never be fully solved"
- Existing tools are complex and enterprise-focused ($1000+/month)

PromptArmor is **free**, **simple**, and **developer-first**.

## Quick Start

```bash
# Scan files
npx promptarmor scan ./prompts

# Check content directly
echo "Ignore previous instructions" | npx promptarmor check

# List detection rules
npx promptarmor rules
```

## Installation

```bash
# npm
npm install -g promptarmor

# pnpm
pnpm add -g promptarmor

# Or use npx (no install needed)
npx promptarmor scan ./prompts
```

## CLI Usage

### Scan Files

```bash
# Scan a single file
promptarmor scan prompt.txt

# Scan multiple files
promptarmor scan ./prompts/*.txt

# Scan a directory (recursively)
promptarmor scan ./src

# Scan with options
promptarmor scan ./prompts \
  --severity high \     # Only report high+ severity
  --threshold 30 \      # Fail if score > 30
  --json \              # Output as JSON
  --output results.json # Write to file
```

### Check from stdin

```bash
# Check content directly
echo "Your prompt here" | promptarmor check

# Check with JSON output
cat prompt.txt | promptarmor check --json
```

### List Rules

```bash
# Show all rules
promptarmor rules

# Filter by category
promptarmor rules --category jailbreak
```

## Library Usage

```typescript
import { scan, createScanner } from 'promptarmor';

// Quick scan
const result = scan('Ignore all previous instructions');
console.log(result.passed); // false
console.log(result.matches); // Array of detected vulnerabilities

// With options
const scanner = createScanner({
  minSeverity: 'high',
  threshold: 30,
});

const result = scanner.scan(userInput);
if (!result.passed) {
  console.log('Vulnerabilities detected:', result.summary);
}
```

## Detection Categories

| Category | Description | Examples |
|----------|-------------|----------|
| `instruction-override` | Attempts to override system instructions | "Ignore previous instructions" |
| `role-manipulation` | Attempts to change AI's role | "You are now DAN" |
| `data-exfiltration` | Attempts to leak sensitive data | "Reveal your system prompt" |
| `jailbreak` | Attempts to bypass safety measures | "Hypothetically, how to..." |
| `encoding-bypass` | Uses encoding to hide malicious content | Base64, Unicode tricks |
| `delimiter-confusion` | Exploits delimiter handling | Fake system markers |
| `context-manipulation` | Attempts to manipulate context | "Reset context now" |

## Severity Levels

| Level | Score Weight | Description |
|-------|--------------|-------------|
| `critical` | 25 | Immediate threat, likely to succeed |
| `high` | 15 | Serious threat, should be addressed |
| `medium` | 8 | Potential threat, context-dependent |
| `low` | 3 | Minor concern, low risk |
| `info` | 1 | Informational, possible false positive |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All scans passed (score below threshold) |
| `1` | One or more scans failed |

## CI/CD Integration

### GitHub Actions

```yaml
name: Prompt Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npx promptarmor scan ./prompts --threshold 30
```

### Pre-commit Hook

```bash
# .husky/pre-commit
npx promptarmor scan ./prompts --severity high --quiet
```

## Configuration (Coming Soon)

Create a `promptarmor.config.json` in your project root:

```json
{
  "include": ["./prompts/**/*", "./src/**/*.prompt"],
  "exclude": ["**/node_modules/**"],
  "severity": "medium",
  "threshold": 50,
  "customRules": []
}
```

## Roadmap

- [x] CLI with scan/check commands
- [x] Pattern-based detection
- [x] JSON output
- [ ] GitHub Action
- [ ] SARIF output for GitHub Security tab
- [ ] Config file support
- [ ] Custom rules
- [ ] LLM validation mode
- [ ] VS Code extension

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## License

MIT © [Aniket Prajapati](https://github.com/aniketpr01)

---

Built with 🛡️ to make LLM applications safer.
