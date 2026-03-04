# Skill Security Threat Model

## Overview

Claude skills (SKILL.md + scripts + references) are executable instruction sets that can
direct Claude to run Bash commands, read/write files, make HTTP requests, and modify
Claude's own configuration. This makes skills a high-value surface comparable to browser
extensions.

## Threat Actors

| Actor | Motivation | Entry Point |
|-------|-----------|-------------|
| Malicious skill author | Data theft, system compromise | Published skill with hidden payloads |
| Supply chain compromise | Persistence, lateral movement | Compromised dependency or shared infra |
| Prompt injection via content | Behavior manipulation | Injected instructions in skill text |
| Insider (accidental) | Unintentional damage | Overly broad permissions, hardcoded secrets |

## Surface Analysis

### SKILL.md — Highest Risk
- Direct instructions to Claude — most powerful vector
- Can contain hidden prompt injections in seemingly innocent text
- Can instruct Claude to alter its own hooks, rules, or settings

### scripts/ — High Risk
- Executed via Bash — full system access within sandbox limits
- Can download and execute remote payloads
- Can read environment variables containing secrets

### references/ — Medium Risk
- Read by Claude for context — can influence decision-making
- Lower direct execution risk but can carry injection payloads

## S1-S6 Category Details

### S1: Prompt Injection — Critical

Techniques: direct instruction override, identity reassignment,
XML/JSON structure escape, base64 obfuscation, unicode homoglyphs,
YAML frontmatter role assignment.

### S2: Privilege Escalation — Critical

Techniques: sandbox disable requests, writing to hook/rule/settings paths,
process termination targeting Claude, force push, hard reset,
world-writable file permissions.

### S3: Data Exfiltration — Critical

Techniques: external HTTP requests with sensitive data, DNS tunneling,
credential file harvesting, staged encoding plus HTTP POST,
error message side-channels.

### S4: Bias Injection — High

Techniques: vendor lock-in directives, competitive exclusion rules,
platform-specific assumptions without justification,
recommendations disguised as best practices.

### S5: Dependency Confusion — Medium

Techniques: typosquatting package names, namespace hijacking,
remote script inclusion from untrusted URLs, unpinned version ranges.

### S6: Cross-Skill Contamination — Medium

Techniques: writing to other skill directories, shared infra tampering,
hook injection affecting all skills, agent definition modification.
