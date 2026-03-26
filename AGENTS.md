# Memoriant LLM Gateway Skill

Compliance-first LLM gateway configuration and audit skills for coding agents.

## Available Skills

### llm-gateway
Design policy-as-code rules (YAML/JSON), verify tamper-evident hash-chain audit trails, configure PII detection, design rate limits and token budgets, and generate SOC2/HIPAA/CMMC compliance evidence packages.

Skill file: `skills/llm-gateway/SKILL.md`

## Available Agents

### llm-gateway-auditor
Compliance engineering specialist. Authors and reviews gateway policies, verifies audit trail integrity, interprets policy decision patterns, and generates structured evidence packages mapped to specific compliance controls.

Agent file: `agents/llm-gateway-auditor.md`

## Usage

### Claude Code
```bash
/install NathanMaine/memoriant-llm-gateway-skill
/llm-gateway
```

### OpenAI Codex CLI
```bash
git clone https://github.com/NathanMaine/memoriant-llm-gateway-skill.git ~/.codex/skills/llm-gateway
codex --enable skills
```

### Gemini CLI
```bash
gemini extensions install https://github.com/NathanMaine/memoriant-llm-gateway-skill.git --consent
```
