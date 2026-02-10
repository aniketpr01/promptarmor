# 🛡️ PromptArmor for VS Code

Real-time prompt injection detection for LLM applications.

![Demo](images/demo.gif)

## Features

- **Real-time scanning** - See vulnerabilities as you type
- **Squiggly lines** - Visual indicators for issues
- **Multiple severity levels** - Critical, High, Medium, Low, Info
- **Context menu** - Right-click to scan selection
- **Workspace scanning** - Scan all files at once

## Installation

Search for "PromptArmor" in the VS Code Extensions marketplace.

Or install from command line:
```bash
code --install-extension aniketpr01.promptarmor-vscode
```

## Usage

### Automatic Scanning
The extension scans files automatically as you type and on save. Vulnerabilities appear as squiggly underlines with hover information.

### Commands

- `PromptArmor: Scan Current File` - Scan the active file
- `PromptArmor: Scan Selection` - Scan selected text
- `PromptArmor: Scan Workspace` - Scan all matching files

Access commands via:
- Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`)
- Right-click context menu

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `promptarmor.enable` | `true` | Enable/disable the extension |
| `promptarmor.severity` | `low` | Minimum severity to report |
| `promptarmor.scanOnSave` | `true` | Scan files on save |
| `promptarmor.scanOnType` | `true` | Real-time scanning |
| `promptarmor.filePatterns` | `["**/*.txt", "**/*.md", ...]` | File patterns to scan |

## Detection Categories

- **Instruction Override** - "Ignore previous instructions"
- **Role Manipulation** - "You are now DAN"
- **Data Exfiltration** - "Reveal your system prompt"
- **Jailbreak** - "Hypothetically, how to..."
- **Encoding Bypass** - Base64, Unicode tricks
- **Delimiter Confusion** - Fake system markers
- **Context Manipulation** - "From now on..."

## Severity Levels

| Icon | Severity | VS Code Display |
|------|----------|-----------------|
| 🚨 | Critical | Error (red) |
| ⚠️ | High | Error (red) |
| ⚡ | Medium | Warning (yellow) |
| ℹ️ | Low | Information (blue) |
| 💡 | Info | Hint (gray) |

## Related

- [PromptArmor CLI](https://github.com/aniketpr01/promptarmor) - Command-line scanner
- [npm package](https://www.npmjs.com/package/promptarmor) - Use in your projects

## License

MIT © [Aniket Prajapati](https://github.com/aniketpr01)
