# PromptArmor - Project Mountain Document
> Complete documentation of planning, execution, implementation, and testing

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Market Analysis](#market-analysis)
3. [Architecture & Design](#architecture--design)
4. [Data Flow & Workflow](#data-flow--workflow)
5. [Implementation Progress](#implementation-progress)
6. [Testing Strategy](#testing-strategy)
7. [Value Proposition](#value-proposition)
8. [Roadmap](#roadmap)

---

## 🎯 Project Overview

### What is PromptArmor?

PromptArmor is an open-source CLI tool and library for detecting prompt injection vulnerabilities in LLM applications. It scans prompts, system instructions, and user inputs to identify potential security risks before they reach production.

### Problem Statement

- **Prompt injection is the #1 LLM security threat** (OWASP 2025)
- Only **34.7%** of enterprises have deployed dedicated defenses
- OpenAI admits prompt injection "may never be fully solved"
- Existing tools are either:
  - Enterprise-focused ($1000+/month)
  - Complex to set up
  - Lack CI/CD integration

### Solution

A dead-simple, developer-first security scanner that:
- Works as a CLI (`promptarmor scan <file>`)
- Integrates with CI/CD (GitHub Actions)
- Provides actionable vulnerability reports
- Is free for open-source projects

### Target Users

1. **Solo developers** building AI apps
2. **Startups** shipping LLM features
3. **Security-conscious teams** wanting pre-deployment checks

---

## 📊 Market Analysis

### Competitive Landscape

| Tool | Type | Stars | Weakness |
|------|------|-------|----------|
| promptfoo | Open Source | 10.4K | Complex setup, enterprise focus |
| garak | Open Source | 7K | NVIDIA-backed, heavy |
| guardrails-ai | Open Source | 6.4K | Output validation, not scanning |
| NeMo Guardrails | Open Source | 5.6K | Runtime, not pre-deployment |
| Lakera Guard | Commercial | N/A | Acquired by Check Point, enterprise |
| Prompt Security | Commercial | N/A | Acquired by SentinelOne, enterprise |

### Our Differentiation

1. **Simplicity**: One command to scan
2. **Speed**: Fast pattern matching + optional deep analysis
3. **CI/CD First**: GitHub Action out of the box
4. **Free Tier**: Unlimited for public repos
5. **Actionable**: Clear fix suggestions, not just alerts

### Market Opportunity

- AI Agents Market: $7.6B (2025) → $103.6B (2032)
- 45.8% CAGR
- Every AI app needs prompt security
- Regulatory pressure increasing

---

## 🏗️ Architecture & Design

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      PromptArmor CLI                        │
├─────────────────────────────────────────────────────────────┤
│  Commands: scan | check | init | report                     │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                     Scanner Engine                           │
├──────────────────┬──────────────────┬───────────────────────┤
│  Pattern Matcher │  Heuristic Analyzer │  LLM Validator     │
│  (Fast, Local)   │  (Scoring)          │  (Optional, Deep)  │
└──────────────────┴──────────────────┴───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                     Detection Rules                          │
├─────────────────────────────────────────────────────────────┤
│  • Instruction Override Patterns                             │
│  • Role Manipulation Attempts                                │
│  • Data Exfiltration Signatures                              │
│  • Jailbreak Patterns                                        │
│  • Encoding Bypass Attempts (Base64, Unicode)                │
│  • Delimiter Confusion                                       │
│  • Context Manipulation                                      │
└─────────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                     Report Generator                         │
├─────────────────────────────────────────────────────────────┤
│  Formats: CLI Table | JSON | Markdown | SARIF (CI/CD)        │
└─────────────────────────────────────────────────────────────┘
```

### Component Breakdown

#### 1. CLI Layer (`src/cli/`)
- Command parsing (Commander.js)
- Input handling (files, stdin, glob patterns)
- Output formatting
- Exit codes for CI/CD

#### 2. Scanner Engine (`src/core/`)
- **PatternMatcher**: Regex-based detection for known injection patterns
- **HeuristicAnalyzer**: Scoring based on structural analysis
- **LLMValidator**: Optional deep analysis using local/API models

#### 3. Detection Rules (`src/rules/`)
- Modular rule definitions
- Severity levels: Critical, High, Medium, Low, Info
- Custom rule support

#### 4. Report Generator (`src/utils/`)
- Multiple output formats
- SARIF for GitHub Security tab integration
- Fix suggestions

### Technology Stack

| Layer | Technology | Rationale |
|-------|------------|-----------|
| Language | TypeScript | Type safety, npm ecosystem |
| CLI Framework | Commander.js | Industry standard |
| Pattern Matching | Native RegExp | Performance |
| Testing | Vitest | Fast, modern |
| Build | tsup | Simple, fast bundling |
| Package Manager | pnpm | Fast, disk efficient |

---

## 🔄 Data Flow & Workflow

### Scan Flow

```
User Input                Processing                    Output
─────────────────────────────────────────────────────────────────

┌──────────┐         ┌─────────────────┐         ┌─────────────┐
│ File(s)  │────────▶│ Content Loader  │────────▶│ Normalized  │
│ or stdin │         │ - Read files    │         │ Text        │
└──────────┘         │ - Detect format │         └──────┬──────┘
                     └─────────────────┘                │
                                                        ▼
                     ┌─────────────────┐         ┌─────────────┐
                     │ Pattern Scanner │◀────────│ Rule Engine │
                     │ - Regex match   │         │ - Load rules│
                     │ - Position track│         │ - Severity  │
                     └────────┬────────┘         └─────────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │ Heuristic Score │
                     │ - Structural    │
                     │ - Contextual    │
                     └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │ LLM Validation  │ (if --deep flag)
                     │ - Ollama/API    │
                     └────────┬────────┘
                              │
                              ▼
                     ┌─────────────────┐         ┌─────────────┐
                     │ Report Builder  │────────▶│ CLI Output  │
                     │ - Aggregate     │         │ JSON File   │
                     │ - Format        │         │ SARIF       │
                     └─────────────────┘         └─────────────┘
```

### CI/CD Integration Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  PR Created │───▶│  GitHub     │───▶│ PromptArmor │───▶│  PR Comment │
│             │    │  Action     │    │  Scan       │    │  + Checks   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                                              │
                                              ▼
                                      ┌─────────────┐
                                      │  SARIF      │───▶ GitHub Security Tab
                                      │  Upload     │
                                      └─────────────┘
```

---

## 📈 Implementation Progress

### Phase 1: Foundation ✅ IN PROGRESS
- [x] Project structure
- [x] Documentation framework
- [ ] Core pattern matcher
- [ ] Basic CLI
- [ ] Initial rule set

### Phase 2: Core Features
- [ ] Heuristic analyzer
- [ ] JSON/Markdown output
- [ ] File glob support
- [ ] Config file support

### Phase 3: CI/CD Integration
- [ ] GitHub Action
- [ ] SARIF output
- [ ] Exit codes
- [ ] PR comment template

### Phase 4: Advanced Features
- [ ] LLM validation mode
- [ ] Custom rules
- [ ] VS Code extension
- [ ] Dashboard (future)

---

## 🧪 Testing Strategy

### Test Categories

1. **Unit Tests** (`tests/unit/`)
   - Pattern matcher accuracy
   - Rule evaluation
   - Scoring algorithms

2. **Integration Tests** (`tests/integration/`)
   - CLI command execution
   - File processing
   - Output format validation

3. **Detection Tests** (`tests/detection/`)
   - Known injection patterns
   - Edge cases
   - False positive rate

4. **Benchmark Tests** (`tests/bench/`)
   - Scan speed
   - Memory usage
   - Large file handling

### Test Data

- Curated dataset of known prompt injections
- Benign prompts for false positive testing
- Edge cases (Unicode, encoding, etc.)

### Coverage Goals

- Unit tests: 90%+
- Detection accuracy: 95%+
- False positive rate: <5%

---

## 💎 Value Proposition

### For Solo Developers

> "I just want to know if my prompts are safe"

- One command: `npx promptarmor scan ./prompts`
- Clear yes/no with details
- Free forever for personal use

### For Startups

> "We need security but can't afford enterprise tools"

- Affordable ($15/month for private repos)
- CI/CD integration
- Compliance-ready reports

### For Security Teams

> "We need to audit AI applications"

- Comprehensive rule set
- SARIF integration
- Custom rule support

### Why PromptArmor?

| Need | Enterprise Tools | PromptArmor |
|------|-----------------|-------------|
| Quick scan | ❌ Complex setup | ✅ One command |
| CI/CD | ❌ Integration project | ✅ Drop-in Action |
| Cost | $1000+/month | Free / $15/month |
| Open Source | ❌ Proprietary | ✅ MIT License |
| Learning Curve | Steep | Minimal |

---

## 🗺️ Roadmap

### v0.1.0 (MVP) - Current
- CLI with scan command
- Pattern-based detection
- JSON output
- Basic rule set

### v0.2.0
- GitHub Action
- SARIF output
- Config file
- More rules

### v0.3.0
- Heuristic scoring
- Fix suggestions
- Markdown reports

### v0.4.0
- LLM validation mode
- Custom rules
- API mode

### v1.0.0
- Stable API
- VS Code extension
- Dashboard preview

---

## 📁 Project Structure

```
promptarmor/
├── src/
│   ├── cli/           # CLI commands
│   ├── core/          # Scanner engine
│   ├── rules/         # Detection rules
│   └── utils/         # Helpers, formatters
├── tests/
│   ├── unit/          # Unit tests
│   ├── integration/   # Integration tests
│   ├── detection/     # Detection accuracy tests
│   └── fixtures/      # Test data
├── docs/
│   ├── planning/      # Planning documents
│   ├── architecture/  # Design docs
│   ├── progress/      # Progress updates
│   └── testing/       # Test documentation
├── examples/          # Usage examples
├── .github/
│   └── workflows/     # GitHub Actions
├── package.json
├── tsconfig.json
└── README.md
```

---

## 📝 Progress Log

### 2026-02-11 - Project Kickoff

- Created project structure
- Wrote PROJECT_MOUNTAIN.md (this document)
- Defined architecture and data flow
- Set up documentation framework
- Beginning implementation...

### 2026-02-11 - v0.1.0 Complete

**Phase 1 Complete:**
- ✅ Core scanner engine with pattern matching
- ✅ 25 base detection rules
- ✅ CLI with scan/check/rules commands
- ✅ JSON output support
- ✅ 29 passing tests

**Phase 2 Complete:**
- ✅ 30+ advanced rules added (50+ total)
- ✅ Categories: multi-turn, agent-exploit, multi-modal, logic-exploit, etc.
- ✅ GitHub Actions CI/CD workflow
- ✅ Reusable GitHub Action for scanning
- ✅ VS Code extension (real-time scanning)

**Pushed to GitHub:** https://github.com/aniketpr01/promptarmor

**Pending:**
- npm publish (requires `npm login`)
- VS Code marketplace publish (requires publisher account)

---

*This document is continuously updated as the project evolves.*
