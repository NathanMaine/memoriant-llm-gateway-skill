<p align="center">
  <img src="https://img.shields.io/badge/claude--code-plugin-8A2BE2" alt="Claude Code Plugin" />
  <img src="https://img.shields.io/badge/skills-1-blue" alt="1 Skill" />
  <img src="https://img.shields.io/badge/agents-1-green" alt="1 Agent" />
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License" />
</p>

# Memoriant LLM Gateway Skill

A Claude Code plugin for designing, auditing, and generating compliance evidence for a governed LLM gateway. Write policy-as-code rules, verify tamper-evident audit trails, configure PII detection, and produce SOC2/HIPAA/CMMC evidence packages.

The LLM gateway space has mature routing tools. None of them answer the question a CISO asks before approving LLM usage in a regulated environment: **"How do we prove to auditors that every LLM interaction was authorized, logged immutably, and compliant with our policies?"** This plugin answers that question.

**No servers. No Docker. Just install and use.**

## Install

```bash
/install NathanMaine/memoriant-llm-gateway-skill
```

## Cross-Platform Support

### Claude Code (Primary)
```bash
/install NathanMaine/memoriant-llm-gateway-skill
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

## Skills

| Skill | Command | What It Does |
|-------|---------|-------------|
| **LLM Gateway** | `/llm-gateway` | Write policy rules, verify audit trails, configure PII detection, generate compliance evidence packages |

## Agent

| Agent | Best Model | Specialty |
|-------|-----------|-----------|
| **LLM Gateway Auditor** | Opus 4.6 | Policy authoring, audit trail verification, compliance control mapping, evidence package generation |

## Quick Start

```bash
# Configure a gateway policy
/llm-gateway

# Or trigger directly
"Write a HIPAA-compliant gateway policy that blocks PII and requires approval for PHI."

# Audit an existing deployment
"Verify this audit trail hasn't been tampered with." [paste JSONL entries]

# Generate compliance evidence
"Generate a SOC2 CC7.1 evidence package for Q1 2025."
```

## Policy-as-Code

Policies are YAML files evaluated on every request before it reaches any LLM provider:

```yaml
rules:
  - name: block-pii-in-prompts
    description: Deny requests containing SSN, credit card, email, or phone patterns
    action: DENY
    conditions:
      pii_detected: true

  - name: require-approval-phi
    description: PHI data requires human approval before any LLM dispatch
    action: REQUIRE_APPROVAL
    conditions:
      data_classification:
        - PHI

  - name: eu-residency-review
    description: EU jurisdiction requests require data residency review
    action: REQUIRE_APPROVAL
    conditions:
      jurisdiction:
        - EU
```

## Compliance Differentiators

| Capability | This Skill |
|------------|-----------|
| Tamper-evident audit trail | Hash-chain JSONL — every entry links to the previous |
| Policy-before-dispatch | DENY = prompt never leaves your infrastructure |
| PII never stored raw | Only SHA-256 hashes logged |
| SOC2/HIPAA evidence export | Structured packages mapped to specific controls |
| Audit trail verification | Detects any modification, insertion, or deletion |

## Compliance Control Mapping

| Framework | Control | What the Gateway Proves |
|-----------|---------|------------------------|
| SOC2 CC6.1 | Logical Access Controls | Per-client auth, policy-gated access |
| SOC2 CC7.1 | Detection and Monitoring | Complete audit trail of all interactions |
| HIPAA 164.312(b) | Audit Controls | Immutable hash-chain audit trail |
| HIPAA 164.312(c)(1) | Integrity | Merkle tree verification |
| HIPAA 164.312(e)(1) | Transmission Security | Content hashing (never stored raw) |

## Using the Actual Tool

This plugin includes the full source code from [NathanMaine/governed-llm-gateway](https://github.com/NathanMaine/governed-llm-gateway). You can deploy and run the gateway directly.

### Install

```bash
cd src/
pip install -r requirements.txt
```

**Requirements:** Python 3.10+, FastAPI, uvicorn, PyYAML, pydantic

### Run the Gateway

```bash
cd src/
uvicorn src.app:app --reload
```

The gateway starts on `http://127.0.0.1:8000`.

### Send a Request

```bash
curl -X POST http://127.0.0.1:8000/v1/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: test-key-1" \
  -d '{
    "client_id": "dev-local-1",
    "model": "default-chat",
    "messages": [{"role": "user", "content": "Explain rate limiting."}],
    "data_classification": "public",
    "jurisdiction": "US"
  }'
```

### Policy Enforcement

Requests containing PII are blocked before reaching any LLM provider:

```bash
curl -X POST http://127.0.0.1:8000/v1/chat \
  -H "Content-Type: application/json" \
  -d '{"client_id": "dev-local-1", "model": "default-chat",
       "messages": [{"role": "user", "content": "SSN 123-45-6789"}]}'
# Returns: {"error": {"type": "policy_denied", ...}}
```

### Configuration

Edit `src/config/example.config.json` to set providers, API keys, rate limits, and policy file path. Set provider API keys as environment variables:

```bash
export OPENAI_API_KEY=sk-your-key-here
```

Customize policy rules in `src/config/policies/default.yaml`.

### Generate Compliance Evidence

```python
from src.src.audit import AuditTrail
from src.src.compliance import generate_evidence_package, export_evidence_package

trail = AuditTrail("src/logs/audit.jsonl")
entries = trail.read_entries()

package = generate_evidence_package(
    entries=entries,
    control_id="164.312(b)",
    framework="HIPAA",
    date_start="2025-01-01T00:00:00Z",
    date_end="2025-03-31T23:59:59Z",
)
export_evidence_package(package, "evidence/hipaa-q1-2025.json")
```

### Run Tests

```bash
cd src/
python3 -m pytest tests/ -v
```

103 tests covering all modules: app, audit, auth, compliance, config, limiter, policy, and router.

### Project Structure (src/)

```
src/
  src/
    app.py          - FastAPI app with /v1/chat endpoint
    config.py       - Configuration loader
    models.py       - Request/response Pydantic models
    provider.py     - Provider adapter (OpenAI-compatible, with stub mode)
    router.py       - Model alias -> provider routing
    limiter.py      - In-memory per-client rate limiter
    telemetry.py    - Structured logging to stdout + log file
    audit.py        - Immutable hash-chain audit trail
    policy.py       - Policy-as-code engine (YAML rules)
    compliance.py   - Compliance evidence collector (SOC2/HIPAA)
  config/
    example.config.json     - Sample configuration
    policies/default.yaml   - Default policy rules
  tests/                    - 103 tests covering all modules
  logs/                     - Append-only log output
```

## Source

Built from [NathanMaine/governed-llm-gateway](https://github.com/NathanMaine/governed-llm-gateway) — a production-ready compliance gateway with 103 tests.

## License

MIT
