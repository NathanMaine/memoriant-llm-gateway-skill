---
name: llm-gateway
description: Design, configure, and audit a compliance-first LLM gateway. Policy-as-code enforcement (YAML/JSON rules), tamper-evident hash-chain audit trails, PII detection and redaction, rate limiting, token budget enforcement, and compliance evidence export for SOC2/HIPAA/CMMC auditors.
---

# Governed LLM Gateway Skill

## Purpose

This skill helps design, configure, audit, and generate compliance evidence for a policy-governed LLM gateway. It addresses the core compliance gap in the LLM space: proving to auditors that every LLM interaction was authorized, logged immutably, and compliant with organizational policy.

The underlying gateway is a FastAPI application that intercepts every LLM request, evaluates it against policy rules before dispatch, routes approved requests to LLM providers, and logs all outcomes to a tamper-evident JSONL audit trail with hash-chain linking.

This skill covers: policy authoring, audit trail interpretation, PII detection rule configuration, rate limit/token budget design, and compliance evidence package generation.

## When to Use This Skill

Use this skill when the user wants to:
- Write or review gateway policy rules (YAML) for a regulated deployment
- Design PII detection patterns for prompts entering an LLM
- Understand the audit trail format and verify chain integrity
- Generate a compliance evidence package for a SOC2, HIPAA, or CMMC audit
- Configure rate limiting or token budgets to enforce usage controls
- Review a gateway deployment configuration for security gaps
- Map gateway capabilities to specific compliance controls

## Architecture Overview

```
Client Request
    ↓
[1] Request Validation (auth, schema)
    ↓
[2] Policy Engine → ALLOW / DENY / REQUIRE_APPROVAL
    ↓ (only if ALLOW)
[3] Rate Limiter (per-client, RPM + TPM)
    ↓
[4] Provider Dispatch → LLM Provider
    ↓
[5] Response returned to client
    ↓
[6] Audit Trail Entry appended (hash-chain linked)
```

**Critical compliance properties:**
- Policy is evaluated BEFORE the request leaves the infrastructure. A DENY means the prompt never reaches any external provider.
- Prompts and responses are SHA-256 hashed before logging. The audit trail proves that a request happened and what policy decision was made, without storing sensitive content raw.
- Every audit entry includes the SHA-256 hash of the previous entry. Tampering with any historical entry breaks the chain.

## Policy-as-Code: Writing Gateway Rules

Policies are YAML files with named rules. Each rule has an action (ALLOW, DENY, REQUIRE_APPROVAL) and one or more conditions.

### Policy Rule Structure

```yaml
rules:
  - name: <rule-identifier>
    description: <human readable explanation>
    action: DENY | ALLOW | REQUIRE_APPROVAL
    conditions:
      pii_detected: true | false
      data_classification:
        - PHI
        - PCI
        - CUI
        - <custom>
      jurisdiction:
        - EU
        - US
        - <custom>
      blocked_models:
        - <model-alias>
      blocked_clients:
        - <client-id>
      blocked_keywords:
        - <keyword or phrase>
      max_prompt_length: <character count>
```

### Policy Decision Precedence

When multiple rules could match a request:
1. DENY rules take precedence over all others
2. REQUIRE_APPROVAL rules take precedence over ALLOW
3. First matching REQUIRE_APPROVAL rule wins
4. If no rule matches, the default action applies (configurable: ALLOW or DENY)

**Recommendation for regulated environments:** Set the default action to DENY (allowlist model). This means new request types are blocked until a policy rule explicitly permits them.

### Condition Reference

| Condition | What it checks | Example |
|-----------|---------------|---------|
| `pii_detected` | Scans prompt for SSN, credit card, email, phone number patterns using regex | Block prompts with SSNs |
| `data_classification` | Matches the `data_classification` field in the request JSON | Require approval for PHI |
| `jurisdiction` | Matches the `jurisdiction` field in the request JSON | Flag EU requests for residency review |
| `blocked_models` | Denies access to specific model aliases | Block GPT-4 for certain clients |
| `blocked_clients` | Denies access to specific client IDs | Block a compromised client key |
| `blocked_keywords` | Scans prompt for literal strings | Block competitor mentions |
| `max_prompt_length` | Flags prompts exceeding character limit | Block prompts > 50,000 chars |

### Example Policy Files

**Minimal compliant policy (healthcare):**
```yaml
rules:
  - name: block-pii-in-prompts
    description: Deny requests containing PII patterns
    action: DENY
    conditions:
      pii_detected: true

  - name: require-approval-phi
    description: PHI data requires human approval workflow
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

**Defense/CMMC policy:**
```yaml
rules:
  - name: block-cui-to-external-models
    description: CUI must not be sent to external LLM providers
    action: DENY
    conditions:
      data_classification:
        - CUI
      blocked_models:
        - gpt-4o
        - claude-sonnet
        - gemini-pro

  - name: block-pii
    action: DENY
    conditions:
      pii_detected: true

  - name: block-large-data-dumps
    description: Prevent bulk data extraction via oversized prompts
    action: DENY
    conditions:
      max_prompt_length: 20000
```

**Production security note:** Use opaque rule identifiers (e.g., `POL-001`, `R-4a2f`) instead of descriptive names in production. Descriptive names leak internal policy structure in error responses visible to clients.

## Audit Trail: Structure and Verification

The gateway writes one JSONL entry per request to an append-only audit log. The log must never be modified or truncated.

### Audit Entry Fields

```json
{
  "entry_index": 42,
  "request_id": "gw-a1b2c3d4e5f6",
  "ts": "2025-03-25T14:30:00Z",
  "client_id": "finance-team-1",
  "model_alias": "default-chat",
  "provider": "openai",
  "policy_decision": "ALLOW",
  "triggered_rules": [],
  "prompt_hash": "sha256:<64-char-hex>",
  "response_hash": "sha256:<64-char-hex>",
  "prompt_tokens": 47,
  "completion_tokens": 215,
  "total_tokens": 262,
  "prev_hash": "sha256:<hash of previous entry>",
  "chain_hash": "sha256:<hash of this entire entry>"
}
```

### Verifying Chain Integrity

To verify the audit trail has not been tampered with:

1. Read all entries in order
2. For each entry N: compute SHA-256 of entries 1..N-1 and compare to entry N's `prev_hash`
3. If any `prev_hash` doesn't match, the entry at position N was modified or an entry was inserted/deleted

A Merkle tree root can be computed across all `chain_hash` values for efficient integrity verification of large audit logs.

**Telling auditors:** The audit trail proves WHAT policy decision was made for EVERY request, WHEN it was made, and that the log has not been altered since. Content is never stored raw — only hashed — so the log itself does not constitute a PII exposure risk.

## PII Detection

The gateway scans prompt text for the following patterns before policy evaluation:

| PII Type | Pattern |
|----------|---------|
| US SSN | `\d{3}-\d{2}-\d{4}` |
| Credit card | 13-16 digit sequences (Luhn-valid) |
| Email address | Standard RFC 5322 email pattern |
| US phone number | Various formats: `(XXX) XXX-XXXX`, `XXX-XXX-XXXX` |

If `pii_detected: true` is a condition in any DENY rule and any of these patterns match, the request is blocked before dispatch.

**Extending PII detection:** To add custom patterns, add them to the gateway's `src/policy.py` PII scanner. Common additions: passport numbers, NHS numbers (UK), IBAN bank accounts, medical record numbers.

**Redaction (not blocking):** For use cases where PII must be allowed but redacted before reaching the LLM, implement a pre-processing step that replaces matched patterns with `[REDACTED-SSN]`, `[REDACTED-EMAIL]`, etc. The original prompt hash is still logged; the redacted prompt is what's dispatched.

## Rate Limiting and Token Budgets

### Per-Client Rate Limiting

Configure in `config.json`:
```json
"rate_limit": {
  "requests_per_minute": 60,
  "tokens_per_minute": 100000
}
```

Rate limiting is applied per `client_id` in the request. If a client exceeds the limit, the gateway returns HTTP 429 and logs the rate-limit event to the audit trail.

**Designing rate limits for compliance:**
- Set `requests_per_minute` low enough to prevent bulk data exfiltration (e.g., a client making 1000 requests in a minute to extract CUI piecemeal)
- Set `tokens_per_minute` to enforce cost controls and prevent prompt injection attacks that try to consume large context windows
- Use separate rate limit tiers for different client roles (e.g., service accounts vs. human users)

### Token Budget Enforcement

```json
"max_prompt_tokens": 4000
```

Approximate word count cap on incoming prompts. Prompts exceeding this limit are blocked with a 400 error. This:
- Prevents prompt injection via massive context injection
- Controls costs for unpredictable workloads
- Creates a hard boundary on data exfiltration volume

## Compliance Evidence Packages

For audit purposes, generate a structured evidence package for a specific compliance control and time period.

### Evidence Package Format

```json
{
  "framework": "HIPAA",
  "control_id": "164.312(b)",
  "control_title": "Audit Controls",
  "period_start": "2025-01-01T00:00:00Z",
  "period_end": "2025-03-31T23:59:59Z",
  "generated_at": "2025-03-25T14:30:00Z",
  "summary": {
    "total_requests": 4821,
    "policy_allowed": 4710,
    "policy_denied": 89,
    "policy_approval_required": 22,
    "chain_integrity_verified": true,
    "chain_entries": 4821
  },
  "evidence_entries": [...]
}
```

### SOC 2 Control Mapping

| Control | Title | Gateway Evidence |
|---------|-------|-----------------|
| CC6.1 | Logical Access Controls | Per-client auth, policy-gated access logs |
| CC6.6 | System Boundaries | DENY decisions for unauthorized request types |
| CC6.8 | Malicious Software Controls | Keyword/PII blocking decisions |
| CC7.1 | Detection and Monitoring | Complete audit trail of all interactions |
| CC7.2 | Monitoring System Components | Hash-chain verified request log |
| CC8.1 | Change Management | Approval workflow decisions |

### HIPAA Control Mapping

| Control | Title | Gateway Evidence |
|---------|-------|-----------------|
| 164.312(a)(1) | Access Control | Client-based auth + policy enforcement |
| 164.312(a)(2)(i) | Unique User Identification | Per-request client_id and request_id |
| 164.312(b) | Audit Controls | Immutable hash-chain audit trail |
| 164.312(c)(1) | Integrity | Merkle tree verification |
| 164.312(d) | Authentication | Client auth on every request |
| 164.312(e)(1) | Transmission Security | Content hashing (never stored raw) |

## Step-by-Step Procedure

### Authoring a New Policy

1. Ask the user: What data classifications need special handling? What jurisdictions are in scope? What behaviors must be blocked outright vs. require approval?
2. Map each requirement to a rule with an appropriate action and conditions.
3. Determine the default action (recommend DENY for regulated environments).
4. Review the policy for gaps: are there request types that would slip through without a rule?
5. Add opaque rule identifiers for production use.
6. Output the complete YAML policy file.

### Auditing an Existing Deployment

1. Read the audit log JSONL (or have the user provide a sample).
2. Verify hash chain integrity: check that each `prev_hash` matches the hash of the preceding entry.
3. Identify any DENY or REQUIRE_APPROVAL decisions and explain the triggered rule.
4. Flag anomalies: entries with missing fields, gaps in `entry_index`, or broken chain links.
5. Summarize the audit period: total requests, allow/deny/approval breakdown, any PII-triggered denials.

### Generating a Compliance Evidence Package

1. Ask: Which framework? (SOC2, HIPAA, CMMC, other) Which control ID? What date range?
2. Filter audit log entries to the specified date range.
3. Verify chain integrity for those entries.
4. Compute summary statistics.
5. Generate the evidence package JSON.
6. Map findings to the specific control's requirements.
7. Output the package and an auditor-facing narrative.

## Examples

### Example 1: Writing a healthcare policy

**User:** "We're deploying an LLM in a HIPAA environment. We need to block PHI from going to any external model."

**Claude should:**
1. Ask: What models are available? What data_classification labels does the system use? Is there an internal/compliant model available?
2. Write rules: block-pii (DENY), block-phi-external (DENY on PHI classification), require-approval-high-sensitivity (REQUIRE_APPROVAL for PHI + approved internal model), eu-residency (if EU users in scope)
3. Set default action to DENY
4. Note that PHI should only be allowed to compliant internal endpoints if any are configured

### Example 2: Verifying audit trail integrity

**User:** "Here's our audit log from last quarter. Can you verify it hasn't been tampered with?"

**Claude should:**
1. Parse each JSONL entry
2. For each entry N, verify: `prev_hash` matches SHA-256 of the raw JSON of entry N-1
3. If any entry fails: report the exact index, the expected hash vs. found hash, and note this constitutes evidence of tampering or log corruption
4. If all entries pass: confirm the chain is intact, report total entries and date range

### Example 3: Rate limit design for a financial services deployment

**User:** "We have 50 internal users. What rate limits make sense for a SOC2 audit?"

**Claude should:**
Recommend:
- `requests_per_minute`: 20 per user (prevents bulk extraction; a human generates far fewer)
- `tokens_per_minute`: 40,000 per user (generous for legitimate use, limits bulk extraction)
- `max_prompt_tokens`: 8,000 (fits typical document analysis, blocks massive data dumps)
- Note: rate limit events should be logged and reviewed; a burst of 429 errors from one client_id is an indicator of automated misuse

## Error Handling

| Situation | Response |
|-----------|----------|
| Policy file has syntax errors | Flag the specific YAML parsing error and line number |
| Audit log has a broken hash chain | Report the exact entry index where the chain breaks and what the discrepancy is |
| User asks about storing prompt content | Explain the security model: only hashes are stored. Raw content is never logged. |
| User wants to ALLOW everything by default | Advise against for regulated environments. If they proceed, note the compliance risk. |
| Evidence package requested for unknown control | Ask for the framework and control description, then map to gateway capabilities |

## Version History

- 1.0.0 — Initial release. Policy authoring, audit trail verification, PII detection configuration, rate limit design, SOC2/HIPAA evidence package generation.
