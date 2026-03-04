#!/usr/bin/env python3
"""
security-scan.py — Static S1-S3 security scanner for Claude skills.

Scans all files in a skill directory for prompt injection, privilege escalation,
and data exfiltration patterns. Shares pattern definitions with the gate hook.

Usage:
  python3 security-scan.py ~/.claude/skills/{skill-name}/
  python3 security-scan.py --batch                          # scan all skills
  python3 security-scan.py --json ~/.claude/skills/{name}/  # JSON output

Exit codes:
  0 = clean (no findings)
  1 = findings detected
  2 = error
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# --- Patterns (kept in sync with skill-security-gate.py) ---

S1_PATTERNS = [
    (r"ignore\s+(all\s+)?previous\s+instructions", "S1", "Prompt override"),
    (r"you\s+are\s+now\s+a", "S1", "Identity hijack"),
    (r"system\s*prompt\s*override", "S1", "System prompt override"),
    (r"(?:forget|disregard)\s+(?:everything|all|your|the)", "S1", "Memory wipe"),
    (r"new\s+instructions?\s*:", "S1", "Instruction injection"),
    (r"<\s*/?system\s*>", "S1", "XML tag injection"),
    (r"]\s*}\s*}\s*{", "S1", "JSON structure escape"),
    (r"(?:act|behave)\s+as\s+(?:if|though)", "S1", "Behavior override (medium)"),
    (r"(?:pretend|imagine)\s+you\s+are", "S1", "Identity pretend (medium)"),
    (r"do\s+not\s+follow\s+(?:any|the)\s+(?:rules|guidelines)", "S1", "Rule bypass (medium)"),
]

S2_PATTERNS = [
    (r"\bdangerouslyDisableSandbox\b", "S2", "Sandbox disable"),
    (r"\bsudo\s+", "S2", "Privileged execution"),
    (r"\bchmod\s+777\b", "S2", "World-writable permission"),
    (r"--no-verify\b", "S2", "Git hook bypass"),
    (r"\.claude/settings\.json", "S2", "Settings file reference"),
    (r"\.claude/hooks/", "S2", "Hooks directory reference"),
    (r"\.claude/rules/", "S2", "Rules directory reference"),
    (r"\bkill\s+.*claude", "S2", "Process termination"),
    (r"\bpkill\s+.*claude", "S2", "Process termination"),
    (r"\bgit\s+push\s+--force\b", "S2", "Force push"),
    (r"\bgit\s+reset\s+--hard\b", "S2", "Hard reset"),
    (r"\bchmod\s+[0-7]*[67][0-7]{2}\b", "S2", "Permissive chmod (medium)"),
    (r"\bcrontab\b", "S2", "Crontab manipulation (medium)"),
]

S3_PATTERNS = [
    (r"\bcurl\s+(?!.*(?:localhost|127\.0\.0\.1|0\.0\.0\.0))", "S3", "External curl"),
    (r"\bwget\s+(?!.*(?:localhost|127\.0\.0\.1))", "S3", "External wget"),
    (r"\.env\b(?!\.d\.ts)", "S3", ".env file access"),
    (r"\.ssh/", "S3", "SSH directory access"),
    (r"\.aws/", "S3", "AWS credentials access"),
    (r"\bcredentials\b(?!.*(?:\.md|documentation|example))", "S3", "Credentials access"),
    (r"(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"][^'\"]{8,}", "S3", "Hardcoded secret"),
    (r"base64\s*(?:encode|decode).*(?:curl|wget|http)", "S3", "Base64 + HTTP exfil"),
]

ALL_PATTERNS = S1_PATTERNS + S2_PATTERNS + S3_PATTERNS

ALLOWLIST_CONTEXTS = [
    r"(?:detect|scan|check|pattern|warn|block|deny|example|e\.g\.|blacklist|NEVER|DON'T)",
    r"(?:flag|signal|target|reference|attempt|mention|modify|access|write\s+to)",
    r"\b(?:technique|vector|attack|method|goal|override|hijack|inject|payload|exfil)\b",
    r"`[^`]+`",
    r"#\s+",
    r"^\|",
    r"^\*\*",
    r"^-\s+\*\*",
    r"^\d+\.\s+",
    r'^"[^"]+"\s*$',
]

SUSPICIOUS_EXTENSIONS = {".exe", ".so", ".dylib", ".bin", ".dll", ".com", ".bat", ".cmd"}


def scan_file(filepath: str) -> list[dict]:
    """Scan a single file for S1-S3 patterns."""
    findings = []

    ext = os.path.splitext(filepath)[1].lower()
    if ext in SUSPICIOUS_EXTENSIONS:
        findings.append({
            "file": filepath,
            "line": 0,
            "level": "S2",
            "category": "Suspicious binary",
            "content": f"Unexpected file type: {ext}",
            "severity": "High",
        })
        return findings

    # Only scan text-based files (.md, .json, .yaml, .yml)
    # Python/shell scripts need AST-level analysis (deep scan)
    scannable = {".md", ".json", ".yaml", ".yml", ".txt"}
    if ext not in scannable:
        return findings

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return findings

    lines = content.split("\n")
    in_code_fence = False

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("```"):
            in_code_fence = not in_code_fence
            continue
        if in_code_fence:
            continue

        is_allowlisted = any(
            re.search(ctx, stripped, re.IGNORECASE) for ctx in ALLOWLIST_CONTEXTS
        )
        if is_allowlisted:
            continue

        for pattern, level, category in ALL_PATTERNS:
            if re.search(pattern, stripped, re.IGNORECASE):
                severity = "Critical" if level in ("S1", "S2", "S3") else "High"
                findings.append({
                    "file": os.path.basename(filepath),
                    "line": line_num,
                    "level": level,
                    "category": category,
                    "content": stripped[:120],
                    "severity": severity,
                })

    return findings


def scan_skill(skill_dir: str) -> dict:
    """Scan an entire skill directory. Returns scan result dict."""
    skill_dir = os.path.expanduser(skill_dir)
    skill_name = os.path.basename(skill_dir.rstrip("/"))

    if not os.path.isdir(skill_dir):
        return {"error": f"Not a directory: {skill_dir}"}

    all_findings = []
    files_scanned = 0

    for root, _dirs, files in os.walk(skill_dir):
        # Skip hidden dirs WITHIN the skill dir (not parent path components)
        rel = os.path.relpath(root, skill_dir)
        if rel != "." and any(part.startswith(".") for part in Path(rel).parts):
            continue
        for filename in files:
            filepath = os.path.join(root, filename)
            findings = scan_file(filepath)
            all_findings.extend(findings)
            files_scanned += 1

    critical_count = sum(1 for f in all_findings if f["severity"] == "Critical")
    if critical_count > 0:
        result = "BLOCK"
    elif all_findings:
        result = "WARN"
    else:
        result = "PASS"

    return {
        "skill": skill_name,
        "scan_level": "Quick (S1-S3)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_scanned": files_scanned,
        "result": result,
        "findings_count": len(all_findings),
        "critical_count": critical_count,
        "findings": all_findings,
    }


def format_report(scan: dict) -> str:
    """Format scan result as markdown report."""
    lines = [
        f"# Security Scan Report: {scan['skill']}",
        "",
        f"**Scan Level**: {scan['scan_level']}",
        f"**Timestamp**: {scan['timestamp']}",
        f"**Files Scanned**: {scan['files_scanned']}",
        f"**Result**: {scan['result']} ({scan['findings_count']} findings, {scan['critical_count']} critical)",
        "",
    ]

    if scan["findings"]:
        lines.append("## Findings")
        lines.append("")
        lines.append("| # | Level | Category | File:Line | Content | Severity |")
        lines.append("|---|-------|----------|-----------|---------|----------|")

        for i, f in enumerate(scan["findings"], 1):
            content = f["content"][:60].replace("|", "\\|")
            lines.append(
                f"| {i} | {f['level']} | {f['category']} | "
                f"{f['file']}:{f['line']} | {content} | {f['severity']} |"
            )
        lines.append("")
    else:
        lines.append("No findings. Skill passed S1-S3 static analysis.")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Skill security scanner (S1-S3)")
    parser.add_argument("path", nargs="?", help="Skill directory to scan")
    parser.add_argument("--batch", action="store_true", help="Scan all skills")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    if args.batch:
        skills_dir = os.path.expanduser("~/.claude/skills")
        results = []
        for entry in sorted(os.listdir(skills_dir)):
            skill_path = os.path.join(skills_dir, entry)
            if os.path.isdir(skill_path) and not entry.startswith(("_", ".")):
                scan = scan_skill(skill_path)
                results.append(scan)

        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print("# Batch Security Scan Results")
            print(f"\n**Timestamp**: {datetime.now(timezone.utc).isoformat()}")
            print(f"**Skills Scanned**: {len(results)}\n")
            print("| Skill | Result | Findings | Critical |")
            print("|-------|--------|----------|----------|")
            for r in results:
                print(f"| {r['skill']} | {r['result']} | {r['findings_count']} | {r['critical_count']} |")

            flagged = [r for r in results if r["result"] != "PASS"]
            if flagged:
                print(f"\n## Flagged Skills ({len(flagged)})\n")
                for r in flagged:
                    print(format_report(r))

        sys.exit(1 if any(r["result"] == "BLOCK" for r in results) else 0)

    elif args.path:
        scan = scan_skill(args.path)
        if args.json:
            print(json.dumps(scan, indent=2))
        else:
            print(format_report(scan))
        sys.exit(1 if scan["result"] == "BLOCK" else 0)

    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
