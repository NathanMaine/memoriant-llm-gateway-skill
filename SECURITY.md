# Security Policy

## What This Plugin Does

This plugin consists entirely of markdown instruction files (SKILL.md and agent .md files). It contains:
- No executable code
- No shell scripts
- No network calls
- No file system modifications beyond what Claude Code normally does

All operations (reading policy YAML files, reading audit trail JSONL, writing evidence packages) are performed by Claude Code itself using its standard tools, not by any code in this plugin.

## Sensitive Content Handling

This plugin helps users work with compliance-sensitive systems. Key security properties:

- The skill explicitly instructs Claude never to suggest storing raw prompt or response content — only hashed values
- Policy files written by this skill may contain rule names that reference PII, PHI, or CUI categories — this is normal and expected
- API keys referenced in gateway configurations are always referenced as environment variable names, never as literal values

## Audit Trail Guidance

When this skill helps verify audit trail integrity, it reads JSONL entries provided by the user. The skill:
- Never transmits audit trail content externally
- Only performs hash verification logic in Claude's reasoning context
- Instructs the user on remediation steps if tampering is detected

## Reporting a Vulnerability

If you discover a security issue, please email nathan@memoriant.com (do not open a public issue).

We will respond within 48 hours and provide a fix timeline.

## Auditing This Plugin

This plugin is easy to audit:
1. All files are markdown — readable in any text editor
2. No `node_modules`, no Python packages, no compiled binaries
3. Review `skills/llm-gateway/SKILL.md` to see exactly what instructions are given to the AI
