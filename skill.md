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

## Related APIs

- Agent Budget Guard: https://agent-budget-guard.onrender.com
- Agent Memory API: https://agent-memory-api-bix5.onrender.com
- Agent Evolution Engine: https://agent-evolution-engine.onrender.com
