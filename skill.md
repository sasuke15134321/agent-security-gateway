# Agent Security Gateway Skill

## Purpose
Use Agent Security Gateway before an AI agent calls an external API, processes untrusted input, or triggers an x402 / USDC / JPYC payment.

## When to use
- About to call an external API with untrusted input
- Processing user input or content from external sources
- About to trigger an x402 payment with user-provided data
- Input originates from untrusted source

## When not to use
- Replace a firewall or network-level security system
- Detect malware or viruses in files
- Perform legal security audits
- Scan trusted internal API calls

## Main endpoint
POST /api/security/scan (0.05 USDC)

## Decision logic
- safe: true → proceed to next step (e.g., Budget Guard)
- safe: false → block request, do not proceed
- risk_level: critical → immediately block and log incident

---

## Agent Safety Checks v0.1

### POST /api/tool/dry-run-validate (0.01 USDC)

**When to use**
- Before executing any tool with destructive potential
- Tool name contains: delete / remove / deploy / pay / secret / reset / kill / terminate
- Before file operations, payment actions, or memory writes

**When not to use**
- Safe read-only tool calls (get / list / search / query)
- Internal trusted tools with no side effects

---

### POST /api/tool/response-sanitize (0.01 USDC)

**When to use**
- After receiving any tool response from external source
- Before agent reads or acts on web search / API response / external data
- Tool response content is unpredictable or user-influenced

**When not to use**
- Responses from internal trusted services
- Simple numeric or boolean responses with no text content

---

### POST /api/schema/drift-check (0.01 USDC)

**When to use**
- Before accepting tool or MCP schema update from external server
- When schema version changes during agent execution
- Before registering new tool from untrusted source

**When not to use**
- Schema updates from internal version-controlled repositories
- Initial schema load on startup (trusted version)

---

### POST /api/identity/scope-check (0.01 USDC)

**When to use**
- Before privileged action: delete / deploy / admin / payment / credential access
- Agent role or scopes are declared at runtime
- Subagents delegate actions to other agents

**When not to use**
- Simple read actions with no side effects
- Agents with statically verified scopes in trusted environment

---

### POST /api/quota/check (0.01 USDC)

**When to use**
- Before each tool call, LLM call, or payment in multi-step workflow
- At start of each agent loop iteration
- Before spawning a subagent

**When not to use**
- Single-shot agents with no loop risk or resource constraints

---

## Recommended Safety Chain

```
task received
  ↓
quota/check (within limits?)
  ↓
tool/dry-run-validate (safe to execute?)
  ↓
identity/scope-check (has permission?)
  ↓
execute tool
  ↓
tool/response-sanitize (safe to read?)
  ↓
process result
  ↓
schema/drift-check (if schema changed)
```

---

## POST /api/security/metadata-sanitize (0.05 USDC) — JP Metadata Sanitizer v0.1

**When to use**
- Before sending x402 / JPYC / USDC / A2A payment metadata to an external service
- When payment metadata includes fields from user input, external APIs, or AI-generated content
- Before storing metadata in a facilitator, ledger, or external audit service
- Any time you need `safe_to_send_to_payment_metadata: true` confirmation

**When not to use**
- After payment is already sent
- For scanning prompt content (use /api/security/scan instead)
- For budget or quota checking (use Agent Budget Guard)

**What it detects**
- email, phone, address (PII) → flagged
- api_key, private_key, password, auth_token (credentials) → blocked
- invoice_number, contract_id, bank_account (financial identifiers) → flagged
- external_url → flagged
- suspicious_instruction (hidden directives) → flagged or blocked

**Key output field**
`safe_to_send_to_payment_metadata: true` means metadata is clean to transmit.

**Constraints**
- Metadata content is never stored or logged (does_not_store_metadata)
- No legal or compliance judgement is made

---

## Pre-Payment Safety Chain

```
before x402 / USDC / JPYC payment:
  ↓
metadata-sanitize (metadata clean?)
  ↓
pre-payment check (URL/amount safe?)
  ↓
execute payment
```

## Related APIs

- Agent Budget Guard: https://agent-budget-guard.onrender.com
- Agent Memory API: https://agent-memory-api-bix5.onrender.com

## Skill: Agent Action Atom

### Use this when
- security scan decision recording
- metadata sanitization outcome
- boundary check (allowed / blocked / review required)
- fuse allow / block / escalate decision
- policy boundary match or violation
- evidence attachment for security audit

### Do not use this as
- a payment protocol
- a wallet or settlement layer
- a legal liability engine
- a compliance guarantee
- an implemented API unless explicitly provided

### Minimal record fields
atom_id / actor / action / target / source / policy / meaning / state / proof / time / relation

### Purpose
Make one AI-agent security decision externally explainable and auditable, especially for boundary control and fuse decision flows.
- Agent Evolution Engine: https://agent-evolution-engine.onrender.com

---

## Skill: Tool Permission Policy Builder

Tool Permission Policy Builder is a free experimental stateless builder that creates external policy material for AI-agent tool and API permission decisions.

### Use this when
- an AI agent needs tool permission rules before using external APIs
- an AI agent needs boundaries before reading memory or accessing network resources
- a developer needs external permission material for AI-agent tool use
- a system needs a policy that can feed into Spending Policy, Budget Check, Agent Action Atom, Payment Action Record, and Evidence Packet workflows

### It can define
- allowed tools
- blocked tools
- approval rules
- risk boundaries
- context state
- Atom-compatible action reference

### Endpoint
POST /api/tool-permission-policy/build (free, no x402 required)

### Output
permission_policy_id / allowed_tools / blocked_tools / approval_rules / risk_boundaries / context_state / agent_action_atom / can_feed_into / created_at / non_goals

### Can feed into
- Agent Spending Policy
- Budget Check
- Agent Action Atom
- Agent Payment Action Record
- Payment Control Evidence Packet
- Decision Cost Trace
- Tool Permission Boundary

### Do not use this as
- a sandbox
- a model provider
- a wallet
- a payment protocol
- a settlement layer
- a legal compliance system
- an official standard

## Skill: Command Execution Gate Builder

### Use this when
An AI agent is about to execute a shell command that originated from external data (tool output, API response, observability data, user input).

Typical cases:
- AI agent receives a command from a tool output and needs to assess it before running
- CI/CD agent is about to run a command derived from an external source
- Automation agent needs external control material before shell execution

### Do not use this as
- a shell executor
- a sandbox runtime
- a model provider
- a wallet or payment protocol
- a legal compliance system
- an official standard

### Live endpoint
POST https://agent-security-gateway.onrender.com/api/command-execution-gate/build

Free. Stateless. Does NOT execute shell commands.

### Output
- command_gate_id
- risk: high / medium / low
- execution_allowed: bool
- action: deny / require_human_approval_or_sandbox / allow_with_monitoring
- blocked_patterns: list of detected dangerous patterns
- reason: explanation of the decision
- recommended_controls: list of suggested next steps
- agent_action_atom: Atom-compatible reference
- can_feed_into: downstream workflows
