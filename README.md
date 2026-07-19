<h1 align="center">Skill Security Scan</h1>

<p align="center">
  <strong>English</strong> | <a href="README.zh.md">繁體中文</a>
</p>

<p align="center">
  <a href="https://github.com/joneshong-skills/skill-security-scan/blob/main/LICENSE"><img src="https://img.shields.io/github/license/joneshong-skills/skill-security-scan?style=flat-square" alt="License"></a>
  <a href="https://github.com/joneshong-skills/skill-security-scan/stargazers"><img src="https://img.shields.io/github/stars/joneshong-skills/skill-security-scan?style=flat-square" alt="GitHub Stars"></a>
</p>

<p align="center">Comprehensive security scanning for Claude skill files — detect 6 threat categories from prompt injection to cross-skill contamination.</p>

---

## Features

- **6 Threat Categories** — Prompt Injection (S1), Privilege Escalation (S2), Data Exfiltration (S3), Bias Injection (S4), Dependency Confusion (S5), Cross-Skill Contamination (S6)
- **Two-Phase Analysis** — Quick Scan (S1-S3) via static pattern matching, Deep Scan (S4-S6) via LLM semantic analysis
- **Batch Mode** — Scan all skills at once with `--all`; static pass first, then deep analysis only on flagged skills
- **Structured Reports** — PASS / WARN / BLOCK verdicts with per-finding severity, file:line references, and remediation steps
- **ast-grep Integration** — Structural code pattern detection supplements regex-based scanning
- **Continuous Learning** — Post-scan reflection loop updates `known-patterns.md` and `lessons.md` over time

## Usage

### Trigger Phrases

> "scan skill security", "check skill for injection", "security audit", "skill-security-scan smart-search"

### Examples

```bash
# Scan a single skill (Quick: S1-S3)
/skill-security-scan smart-search

# Deep scan a skill (S1-S6)
/skill-security-scan smart-search --deep

# Scan all skills in batch
/skill-security-scan --all

# Scan an arbitrary directory
/skill-security-scan --path /path/to/skill-dir

# Run the static scanner directly
~/.local/bin/python3 ~/.claude/skills/skill-security-scan/scripts/security-scan.py ~/.claude/skills/smart-search/
```

## Workflow

1. **Resolve Target** — Map skill name to full path, or expand `--all` to inventory
2. **Inventory Files** — List all files; flag unexpected types (`.exe`, `.so`, `.dylib`) as S2 findings
3. **Quick Scan (S1-S3)** — Run `security-scan.py` for static pattern matching (injection, privilege escalation, exfiltration)
4. **Deep Scan (S4-S6)** — LLM semantic analysis for bias injection, dependency confusion, and cross-skill contamination
5. **Cross-Reference** — Compare findings against `known-patterns.md` to filter false positives
6. **Generate Report** — Structured Markdown report with verdict, findings table, and recommendations

## Integration

| System | Relationship |
|--------|-------------|
| **skill-security-gate** (hook) | Shares S1-S3 patterns; gate blocks on install, this skill audits on demand |
| **skill-lifecycle** | Phase 2 invokes this scan as a hard gate before promotion |
| **skill-tester** | Can delegate T6 (Security) test category to this skill |
| **create-skill** | Post-creation validation trigger |

## Installation

1. Clone or copy the skill directory to `~/.claude/skills/skill-security-scan/`
2. Ensure `scripts/security-scan.py` is executable: `chmod +x ~/.claude/skills/skill-security-scan/scripts/security-scan.py`
3. Optional: install `ast-grep` for structural scanning: `brew install ast-grep`

### Dependencies

- Python 3.12 (stdlib only)
- ast-grep (`sg`) — optional, for structural pattern detection
- Claude Code — required for S4-S6 semantic analysis (Deep Scan)

## License

[MIT](LICENSE)
