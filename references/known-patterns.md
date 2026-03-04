# Known Security Patterns for Skill Scanning

## S1: Prompt Injection Patterns

### High-Confidence (very low false positive rate)

```regex
ignore\s+(all\s+)?previous\s+instructions
you\s+are\s+now\s+a
system\s*prompt\s*override
(?:forget|disregard)\s+(?:everything|all|your|the)
new\s+instructions?\s*:
<\s*/?system\s*>
]\s*}\s*}\s*{
---\s*\n.*?role\s*:\s*system
```

### Medium-Confidence (context-dependent)

```regex
(?:act|behave)\s+as\s+(?:if|though)
(?:pretend|imagine)\s+you\s+are
do\s+not\s+follow\s+(?:any|the)\s+(?:rules|guidelines)
(?:secret|hidden)\s+(?:mode|instruction)
```

## S2: Privilege Escalation Patterns

### High-Confidence

```regex
\bdangerouslyDisableSandbox\b
\bchmod\s+777\b
--no-verify\b
\.claude/settings\.json
\.claude/hooks/
\.claude/rules/
\bkill\s+.*claude
\bpkill\s+.*claude
\bgit\s+push\s+--force\b
\bgit\s+reset\s+--hard\b
```

### Medium-Confidence

```regex
\bchmod\s+[0-7]*[67][0-7]{2}\b
\bchown\b.*root
\bsetuid\b
\bcrontab\b
\blaunchctl\b.*load
```

## S3: Data Exfiltration Patterns

### High-Confidence

```regex
\bcurl\s+(?!.*(?:localhost|127\.0\.0\.1|0\.0\.0\.0))
\bwget\s+(?!.*(?:localhost|127\.0\.0\.1))
\.ssh/
\.aws/
(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['"][^'"]{8,}
base64\s*(?:encode|decode).*(?:curl|wget|http)
```

### Medium-Confidence

```regex
\.env\b(?!\.d\.ts)
\bcredentials\b
\btoken\b.*\bsend\b
\bupload\b.*\bexternal\b
```

## S5: Dependency Confusion — Known Typosquats

Common typosquatting targets (Levenshtein distance 1-2):

| Real Package | Known Typosquats |
|-------------|-----------------|
| requests | reqeusts, requets, request |
| numpy | numppy, numpi |
| pandas | panda, pandass |
| flask | flaask, flaskk |
| django | djang, djangoo |
| cryptography | cyptography, crytography |
| beautifulsoup4 | beautifulsoup, beautfulsoap |
| selenium | selnium, selemium |

## Known False Positives

### Legitimate uses that trigger patterns

| Pattern | False Positive Context | Why It's OK |
|---------|----------------------|-------------|
| `.env` | Configuration setup docs | Documentation about environment |
| external `curl` | API testing examples | Example commands in docs |
| `.ssh/` | SSH key setup guides | Setup documentation |
| `chmod` | Permission guides | Educational content |

### Allowlist Heuristics

Lines matching these patterns are likely documentation, not threats:
- Inside code fence blocks (triple backtick)
- Contains backtick-quoted inline code references
- Part of a markdown table row
- Contains documentation keywords (see gate hook allowlist)
- Part of a numbered or bulleted list describing techniques
