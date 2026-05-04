# Policy Model

## Overview

The MCPIDS policy model converts raw inspection signals into a concrete enforcement decision (a **Verdict**) for every MCP message. It has three layers:

```
Raw signals (rules, semantic, diff, risk, graph)
        ↓
   Policy Engine   ← tenant-level policies + rules
        ↓
      Verdict      ← Decision + Severity + Reasons + Redactions
        ↓
  Gateway action   ← allow / deny / hide / redact / quarantine / require_approval
```

---

## Verdicts

Every intercepted message receives a **Verdict**. Verdicts contain:

| Field | Type | Description |
|-------|------|-------------|
| `Decision` | `Decision` | The enforcement action to take |
| `Severity` | `Severity` | info \| low \| medium \| high \| critical |
| `Reasons` | `[]string` | Human-readable explanation per signal |
| `MatchedRules` | `[]string` | IDs of rules that fired |
| `SemanticLabels` | `[]string` | Classifier output labels |
| `Confidence` | `float64` | 0.0–1.0 aggregate confidence |
| `RequiresApproval` | `bool` | True when human review is needed |
| `Redactions` | `[]Redaction` | Field paths and replacement values |
| `IncidentCandidate` | `bool` | True when the event should open an incident |
| `EvidenceRefs` | `[]string` | Audit event IDs for traceability |

### Decision Types

| Decision | Gateway Action |
|----------|---------------|
| `allow` | Forward message unchanged |
| `monitor_only` | Forward unchanged, emit detection event |
| `hide` | Remove tool from `tools/list` response |
| `redact` | Scrub matched content before forwarding |
| `require_approval` | Hold message, notify admin, block until decided |
| `deny` | Return JSON-RPC error `-32001` to caller |
| `quarantine` | Freeze entire session; deny all subsequent calls |

### Decision Precedence

When multiple interceptors contribute partial verdicts, the most restrictive wins:

```
quarantine > deny > require_approval > redact > hide > monitor_only > allow
```

### Severity Bands

Severity is derived from the aggregate risk score:

| Score Range | Severity |
|-------------|----------|
| 0.0 – 0.20 | `info` |
| 0.20 – 0.40 | `low` |
| 0.40 – 0.60 | `medium` |
| 0.60 – 0.80 | `high` |
| 0.80 – 1.00 | `critical` |

---

## Rules

Rules are the primary policy instrument. Each rule has:

```yaml
id: block-injection-phrases
name: "Block tool descriptions with injection phrases"
priority: 10          # lower = higher priority
enabled: true
scope:
  methods: [tools/list]
  directions: [outbound]
  tenant_ids: []      # empty = all tenants
  server_ids: []      # empty = all servers
conditions:
  - field: "tool.description"
    op: phrase_match
    value: suspicious_tool_phrases
action:
  decision: hide
severity: high
tags: [prompt-injection, tool-integrity]
```

### Scope Filtering

A rule only applies if the message matches **all** scope filters:

| Field | Description |
|-------|-------------|
| `methods` | MCP method names: `tools/list`, `tools/call`, `prompts/list`, etc. |
| `directions` | `inbound` (client→server) or `outbound` (server→client) |
| `tenant_ids` | Restrict to specific tenants (empty = all) |
| `server_ids` | Restrict to specific MCP servers (empty = all) |

### Condition Operators

| Operator | Applies To | Description |
|----------|-----------|-------------|
| `eq` | string, bool | Exact equality |
| `contains` | string | Substring match |
| `regex` | string | RE2 regular expression |
| `regex_any` | string array | Any element matches regex |
| `phrase_match` | string | Aho-Corasick multi-phrase scan (O(n)) |
| `secret_pattern` | string | Regex scan against secret pattern set |
| `schema_violation` | object | JSON Schema validation failure |
| `tool_name_match` | string | Tool name in allowlist/denylist |
| `in` | string | Value is in a list |
| `gt` / `lt` | number | Numeric comparison |
| `exists` | any | Field is present and non-null |
| `jsonpath` | any | JSONPath expression evaluation |

### Condition Fields

Fields use dot-notation paths into the intercepted message context:

| Field Path | Available In | Description |
|-----------|-------------|-------------|
| `tool.name` | tools/list, tools/call | Tool name |
| `tool.description` | tools/list | Tool description text |
| `tool.input_schema` | tools/list | Tool JSON Schema |
| `args.*` | tools/call (inbound) | Tool call argument values |
| `result.content[*].text` | tools/call (outbound) | Response content text |
| `diff.tool_is_new` | tools/list | Tool not seen before |
| `diff.description_changed` | tools/list | Description changed since snapshot |
| `diff.schema_widened` | tools/list | Input schema became more permissive |
| `risk.score` | any | Aggregate 0.0–1.0 risk score |
| `session.call_count` | any | Number of calls in this session |
| `session.state` | any | Session FSM state |

### Built-in Rules

MCPIDS ships built-in rules loaded at startup from `internal/policy/rules/builtins.go`. They cannot be deleted but can be disabled:

| Rule ID | Trigger | Decision |
|---------|---------|---------|
| `builtin:block-ignore-prev-instructions` | Phrases: "ignore previous instructions", "disregard system prompt" | `hide` |
| `builtin:block-exfil-phrases` | Phrases: "send to", "POST to", "exfiltrate", "without alerting" | `deny` |
| `builtin:block-dangerous-shell-args` | Tool args matching shell escape patterns | `deny` |
| `builtin:redact-aws-keys` | AWS access key pattern in response | `redact` |
| `builtin:redact-github-tokens` | GitHub PAT pattern in response | `redact` |
| `builtin:redact-openai-keys` | OpenAI API key pattern in response | `redact` |
| `builtin:redact-slack-tokens` | Slack token pattern in response | `redact` |
| `builtin:redact-jwt` | JWT token pattern in response | `redact` |
| `builtin:redact-pem-blocks` | PEM private key blocks in response | `redact` |

### Rule Evaluation Order

Rules are evaluated in ascending `priority` order (lower number = evaluated first). Evaluation **short-circuits** when a `deny` or `quarantine` decision is reached.

---

## Signals and the Risk Engine

The risk engine aggregates signals from all interceptors into a single `0.0–1.0` score. Weights are configurable:

| Signal | Default Weight | Source |
|--------|---------------|--------|
| `rules` | 0.35 | Number and severity of matched rules |
| `semantic` | 0.25 | Semantic classifier confidence score |
| `diff` | 0.20 | Severity of capability changes since snapshot |
| `graph` | 0.15 | Lateral movement / chain depth |
| `frequency` | 0.05 | Anomalous call frequency |

A trust score modifier amplifies risk for low-trust servers:
- Server trust score 0.0–0.3 (untrusted): risk amplified 1.5×
- Server trust score 0.3–0.7 (neutral): no amplification
- Server trust score 0.7–1.0 (trusted): risk reduced 0.8×

First-seen tools add a flat 0.15 to the risk score.

---

## Policy Engine Decision Process

```
1. Collect partial verdicts from all interceptors
2. Apply precedence: merge into single worst-case Decision
3. Aggregate risk score → severity
4. If risk_score ≥ tenant_threshold.require_approval:
       upgrade decision to require_approval (unless already deny/quarantine)
5. If risk_score ≥ tenant_threshold.quarantine:
       upgrade decision to quarantine
6. If policy.monitor_only OR policy.dry_run:
       downgrade any blocking decision to monitor_only
7. Return final Verdict
```

---

## Policy Modes

### Enforce (default)

All decisions are applied. Deny returns error to client; quarantine freezes session.

### Monitor-Only

All blocking decisions (`deny`, `quarantine`, `require_approval`) are converted to `monitor_only`. Traffic flows through unimpeded, but detections are still recorded. Use for:
- Initial rollout ("shadow mode")
- Testing new rules before enforcement

Enable per-deployment:
```yaml
gateway:
  pipeline:
    monitor_only: true
```

Or per-policy:
```yaml
mode: monitor_only
```

### Dry-Run

Same as monitor-only but also disables approval notifications. Useful for CI environments that want verdict logging without side effects.

---

## Tenant Policies

Each tenant can have multiple policies. The policy with the highest `priority` (lowest number) that matches a request is applied. Within a policy, rules are applied in `priority` order.

```yaml
# Example: Strict policy for production tenant, permissive for dev
policies:
  - id: prod-strict
    tenant_id: tenant-prod
    priority: 1
    default_decision: allow
    risk_thresholds:
      require_approval: 0.6
      quarantine: 0.85

  - id: dev-permissive
    tenant_id: tenant-dev
    priority: 1
    default_decision: allow
    mode: monitor_only
```

If no policy matches, the system falls back to `default_decision: allow` with built-in rules active.

---

## Writing Custom Rules

### YAML Rule File

Place custom rule files in `policies/` or configure the gateway to load them from `rules.yaml_paths`:

```yaml
# policies/my-rules.yaml
rules:
  - id: block-rm-rf-tool
    name: "Block tools that run rm -rf"
    priority: 5
    scope:
      methods: [tools/call]
      directions: [inbound]
    conditions:
      - field: "args.command"
        op: regex
        value: "rm\\s+-[rRfF]{2,}"
    action:
      decision: deny
    severity: critical
    tags: [destructive, shell]

  - id: require-approval-external-url
    name: "Require approval for tools posting to external URLs"
    priority: 15
    scope:
      methods: [tools/call]
      directions: [inbound]
    conditions:
      - field: "args.url"
        op: regex
        value: "^https?://"
      - field: "tool.name"
        op: contains
        value: "post"
    action:
      decision: require_approval
    severity: high
```

### Rule Conditions: Logical AND

All conditions within a rule's `conditions` array are evaluated as **AND** - the rule fires only when every condition is true.

For **OR** logic, create multiple rules with the same action.

### Redaction Rules

Redaction rules specify which fields to scrub and the replacement value:

```yaml
action:
  decision: redact
  redactions:
    - field: "result.content[*].text"
      pattern: "(?i)sk-[A-Za-z0-9]{32,}"
      replacement: "[OPENAI-KEY-REDACTED]"
    - field: "result.content[*].text"
      pattern: "ghp_[A-Za-z0-9]{36}"
      replacement: "[GITHUB-TOKEN-REDACTED]"
```

Multiple redactions are applied in order to the same content.

---

## Approvals Workflow

When a verdict is `require_approval`:

1. Gateway holds the `tools/call` request in a Redis pub/sub channel
2. Control plane notifies admin via webhook (or Slack, email - configurable)
3. Admin reviews the request at `GET /api/v1/approvals/{id}`
4. Admin submits decision at `POST /api/v1/approvals/{id}/decide` with `{"status": "approved", "decided_by": "alice@example.com"}`
5. Redis publishes decision; gateway receives it and either forwards or denies the original request
6. If no decision arrives before `approval_timeout` (default: 10 minutes), the request is denied

### Approval payload

The approval record includes the full original `tools/call` request payload so the admin can review it before deciding.

---

## Policy Precedence Reference

```
Scope match: tenant + server + method + direction
        ↓
Rule evaluation (ascending priority, short-circuit on deny/quarantine)
        ↓
Risk score aggregation
        ↓
Threshold checks (require_approval, quarantine)
        ↓
Mode override (monitor_only, dry_run)
        ↓
Final Verdict
```

When in doubt, the system is **fail-closed**: pipeline timeout → deny.
