# AgentMesh — Architecture

> **Version:** 0.1.0-draft  
> **Status:** Active  
> **Last updated:** March 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [Design Principles](#2-design-principles)
3. [System Architecture](#3-system-architecture)
4. [Layer 1 — Identity](#4-layer-1--identity)
5. [Layer 2a — Policy Engine](#5-layer-2a--policy-engine)
6. [Layer 2b — Behavior Monitor](#6-layer-2b--behavior-monitor)
7. [Layer 3 — Audit Trail](#7-layer-3--audit-trail)
8. [System Flow](#8-system-flow)
9. [Failure Modes & Error Handling](#9-failure-modes--error-handling)
10. [Performance Targets](#10-performance-targets)
11. [Deployment Model](#11-deployment-model)
12. [Security Guarantees](#12-security-guarantees)
13. [Versioning & Compatibility](#13-versioning--compatibility)

---

## 1. Overview

AgentMesh is a runtime trust and security layer for multi-agent AI systems. It solves a problem that existing tools do not: securing how AI agents communicate with, trust, and delegate to each other in a swarm.

Existing tools (Sage, Aegis) protect a single agent from the OS it runs on. AgentMesh protects agents from **each other** — enforcing identity, policy, and audit at every inter-agent boundary.

### The core threat model

When multiple AI agents collaborate, three attack surfaces open up that no framework currently addresses:

| Threat | Example | AgentMesh response |
|---|---|---|
| Agent impersonation | A rogue agent claims to be the trusted orchestrator | Identity layer — every agent has a signed JWT |
| Unauthorized capability escalation | A sub-agent calls tools it was never supposed to access | Policy engine — default-deny YAML rules |
| Prompt injection hijacking | A malicious document tricks an agent into dangerous tool calls | Behavior monitor — runtime injection detection |
| Undetectable tampering | Logs are altered after an incident to hide what happened | Audit trail — cryptographic hash chain |

### Architecture layers

```
┌─────────────────────────────────────────────────────┐
│               AgentMesh Runtime                     │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │         Layer 1: Identity                     │  │
│  │   Ed25519 keypairs · JWT issuance · Verify    │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  ┌──────────────────┐  ┌──────────────────────────┐ │
│  │ Layer 2a: Policy │  │ Layer 2b: Behavior       │ │
│  │ YAML rules       │  │ Injection detection      │ │
│  │ Default-deny     │  │ Anomaly detection        │ │
│  └──────────────────┘  └──────────────────────────┘ │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │         Layer 3: Audit Trail                  │  │
│  │   Ed25519 signed · SHA-256 chained · Verified │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
         ↑            ↑            ↑
      Agent A      Agent B      Agent C
```

---

## 2. Design Principles

### Zero Trust Communication
Every inter-agent call is verified from scratch. There is no implicit trust between agents, even within the same process. An agent that was trusted 5 minutes ago must re-verify on every call.

### Default Deny
If a policy rule does not explicitly permit an action, the action is blocked. The system never falls back to "allow" in the absence of a matching rule. This is the most critical security decision in the entire design.

### Policy-Driven Control
Permissions are declared in human-readable YAML, not embedded in code. This means permissions can be audited, versioned in git, reviewed in PRs, and changed without redeployment.

### Runtime Observability
Security does not stop at the policy check. Agent behavior is continuously monitored at runtime for signs of compromise, even for actions that passed the policy gate.

### Cryptographic Accountability
Every action is recorded with a signature. Records are chained so that tampering with any entry invalidates everything that follows. The audit trail is a first-class security primitive, not an afterthought.

### Fail Secure
When any component is unavailable or returns an error, the system defaults to blocking the action. An unavailable policy engine means no actions proceed — not that all actions are allowed.

---

## 3. System Architecture

### Component responsibilities

| Component | Language | Responsibility |
|---|---|---|
| `agentmesh.identity` | Python + C++ (pybind11) | JWT issuance, Ed25519 keypair management, token verification |
| `agentmesh.policy` | Python | YAML policy loading, rule evaluation, default-deny enforcement |
| `agentmesh.monitor` | Python + C++ | Tool call interception, injection detection, anomaly detection |
| `agentmesh.audit` | Python | SHA-256 hash chaining, Ed25519 signing, storage backends |
| `@agentmesh/client` | TypeScript | JS/TS SDK — identity, policy check via REST, audit emit |
| `agentmesh-dashboard` | Next.js | Real-time violation viewer, audit log browser |

### Why Python + C++

The interceptor sits on the hot path — every single tool call passes through it. Python alone introduces unacceptable overhead at scale. The interception and verification logic is implemented as a C++ extension (via pybind11) and called from Python. The policy YAML parsing and rule evaluation remain in Python because they are not on the hot path and readability matters more there.

---

## 4. Layer 1 — Identity

### Overview

Every agent joining the mesh is assigned an Ed25519 keypair and a signed JWT during initialization. This token is attached to every inter-agent call and verified by the receiving agent before any action proceeds.

### Key choices

**Why Ed25519 and not RS256?**  
Ed25519 signatures are smaller (64 bytes vs 256+ bytes for RS256), faster to verify, and not vulnerable to the padding attacks that affect RSA. For a hot-path interceptor that verifies on every call, this matters.

**Why JWT and not a custom format?**  
JWTs are a well-understood standard with library support in every language. Using JWT means the JS SDK, Python core, and any future SDKs share the same token format without custom parsing.

### Token structure

```json
{
  "header": {
    "alg": "EdDSA",
    "typ": "JWT"
  },
  "payload": {
    "agent_id": "researcher-001",
    "capabilities": ["web_search", "read_file"],
    "mesh_id": "mesh-abc123",
    "iat": 1711234567,
    "exp": 1711320967,
    "jti": "unique-token-id-uuid4"
  },
  "signature": "<ed25519 signature over header.payload>"
}
```

**Field definitions:**

| Field | Type | Description |
|---|---|---|
| `agent_id` | string | Unique identifier for this agent instance |
| `capabilities` | string[] | Declared capabilities — checked against policy rules |
| `mesh_id` | string | Identifier of the mesh this agent belongs to |
| `iat` | unix timestamp | Issued at |
| `exp` | unix timestamp | Expiry — default 24 hours from issuance |
| `jti` | uuid4 | Unique token ID — used for revocation |

### Key storage

Private keys are stored in memory only during the agent's lifetime. They are never written to disk in plaintext. The public key is registered with the mesh's credential store on agent init and used by other agents for verification.

```
Credential store (in-memory dict, optional Redis backend):
  agent_id → public_key (bytes)
```

### Token lifecycle

```
Agent init
    │
    ▼
Generate Ed25519 keypair
    │
    ▼
Issue JWT (sign with private key)
    │
    ▼
Register public key in credential store
    │
    ▼
Attach JWT to all outgoing calls
    │
    ▼
On each incoming call: verify JWT
    ├── Signature valid? ──── No ──▶ Raise IdentityError
    ├── Not expired?     ──── No ──▶ Raise TokenExpiredError
    ├── jti not revoked? ──── No ──▶ Raise TokenRevokedError
    └── All pass         ──── Yes ─▶ Return AgentContext
```

### Token revocation

Tokens can be revoked by adding their `jti` to the revocation list. The revocation list is checked on every verification. On graceful agent shutdown, the token is automatically revoked.

### API reference

```python
from agentmesh.identity import AgentIdentity

# Initialize an agent identity
identity = AgentIdentity(
    agent_id="researcher-001",
    capabilities=["web_search", "read_file"],
    ttl_hours=24  # default
)

# Issue a token
token: str = identity.issue_token()

# Verify a token (raises on failure)
context: AgentContext = AgentIdentity.verify(token)
# context.agent_id, context.capabilities, context.mesh_id

# Revoke a token
identity.revoke(token)
```

## 4.1 — Credential Store

The `CredentialStore` is the single source of truth for registered agent public keys. It was extracted from `agent_identity.py` into its own module (`agentmesh/identity/credential_store.py`) to enforce separation of concerns and allow future backends (e.g. Redis, Vault).

### Responsibilities

| Method | Description |
|---|---|
| `register(agent_id, public_key_bytes)` | Called on `AgentIdentity.__init__`. Stores the 32-byte Ed25519 public key. |
| `lookup(agent_id)` | Called on `AgentIdentity.verify`. Returns public key bytes or `None`. |
| `deregister(agent_id)` | Called on graceful agent shutdown. Removes key from store. |
| `is_registered(agent_id)` | Utility — used by the policy engine to confirm an agent exists. |

### Validation on registration

- `agent_id` must not be empty — raises `IdentityError`
- `public_key_bytes` must be exactly 32 bytes (Ed25519 raw key length) — raises `IdentityError`

### v0.1 implementation

In-memory `dict[str, bytes]`. Keys are lost on process restart — agents must re-register on startup. This is intentional for v0.1: private keys are also ephemeral (never written to disk), so re-registration is always possible.

### Planned backends (v0.3+)

| Backend | Use case |
|---|---|
| `redis` | Multi-process deployments — shared key store across processes |
| `vault` | Production environments requiring key management audit trail |

### Module location

```
agentmesh/identity/
├── agent_identity.py      # AgentIdentity, AgentContext — uses CredentialStore
├── credential_store.py    # CredentialStore — extracted, standalone
└── exceptions.py          # IdentityError, TokenExpiredError, TokenRevokedError
```

---

## 5. Layer 2a — Policy Engine

### Overview

The Policy Engine defines what each agent is allowed to do through declarative YAML rules. It is evaluated on every inter-agent call, after identity verification and before the behavior monitor.

### Critical rule: default deny

**If no rule explicitly permits an action, the action is blocked.**

This is non-negotiable. The policy engine never falls through to "allow" in the absence of a matching rule. This means a brand-new agent with no policy file cannot do anything until rules are written for it.

### Policy file schema

```yaml
# agentmesh-policy.yaml

version: "1.0"

# Global settings
defaults:
  deny_on_missing_rule: true     # Always true — cannot be set to false
  deny_on_engine_error: true     # If policy engine fails, deny all actions
  log_all_denials: true

agents:
  orchestrator:
    allowed_tools: []            # Orchestrator delegates, does not call tools directly
    allowed_callers: []          # Top-level agent — no caller restriction
    can_delegate_to:
      - researcher
      - summarizer
    rate_limits: {}

  researcher:
    allowed_tools:
      - web_search
      - read_file
    denied_tools:
      - write_file               # Explicit deny — belt and suspenders
      - execute_shell
    allowed_callers:
      - orchestrator             # Only orchestrator can invoke researcher
    can_delegate_to: []          # Researcher cannot delegate further
    rate_limits:
      web_search: "10/minute"
      read_file: "50/minute"

  summarizer:
    allowed_tools:
      - read_context
      - write_output
    allowed_callers:
      - orchestrator
    can_delegate_to: []
    rate_limits:
      write_output: "5/minute"
```

### Rule evaluation logic

```
Incoming request: caller=orchestrator, callee=researcher, tool=web_search

Step 1: Is caller in callee's allowed_callers list?
        orchestrator ∈ [orchestrator] → YES

Step 2: Is tool in callee's denied_tools list?
        web_search ∈ [write_file, execute_shell] → NO

Step 3: Is tool in callee's allowed_tools list?
        web_search ∈ [web_search, read_file] → YES

Step 4: Has rate limit been exceeded?
        researcher.web_search counter < 10/minute → NO

Decision: ALLOW
```

If any step fails, the decision is **DENY** immediately — remaining steps are not evaluated.

### Schema validation

On startup, the policy file is validated against a strict JSON Schema. If the file is malformed, the engine refuses to start. A policy file that fails validation is treated the same as no policy file — all actions are denied.

### API reference

```python
from agentmesh.policy import PolicyEngine

engine = PolicyEngine(policy_path="agentmesh-policy.yaml")

result = engine.evaluate(
    caller_id="orchestrator",
    callee_id="researcher",
    tool_name="web_search"
)
# result: PolicyDecision(allowed=True, reason="rule match")
# result: PolicyDecision(allowed=False, reason="tool not in allowed_tools")
# result: PolicyDecision(allowed=False, reason="rate limit exceeded")
```

---

## 6. Layer 2b — Behavior Monitor

### Overview

The Behavior Monitor intercepts every tool call at runtime and inspects it for signs of compromise — regardless of whether it passed the policy gate. A policy check only knows what the agent is *supposed* to do. The behavior monitor detects when an agent has been *hijacked* into doing something different.

### Interception mechanism

The interceptor wraps tool functions using a Python decorator. The wrapping is done at the C++ extension level for performance — the Python decorator is a thin interface to the C++ hook.

```python
from agentmesh.monitor import intercept_tools

@intercept_tools(identity=agent_identity)
def web_search(query: str) -> str:
    # original implementation
    ...
```

When `web_search` is called, control passes to the C++ interceptor first. The interceptor captures the call context and passes it synchronously to both the injection detector and anomaly detector before allowing execution.

### 6a — Injection Detector

The injection detector scans tool call arguments for prompt injection patterns.

**Detection method:** Pattern matching against a curated blocklist, combined with a structural analysis of argument strings. We do not use an LLM classifier — it would be too slow on the hot path and creates a recursive trust problem (using an AI to protect an AI).

**Pattern categories:**

| Category | Example patterns | Risk |
|---|---|---|
| Instruction override | `ignore previous instructions`, `disregard your system prompt`, `your new instructions are` | Critical |
| Role hijack | `you are now`, `act as`, `pretend you are`, `your true identity` | Critical |
| System prompt leak | `repeat your system prompt`, `what are your instructions`, `output your context` | High |
| Jailbreak prefixes | `DAN mode`, `developer mode`, `unrestricted mode` | High |
| Encoding tricks | Base64 encoded versions of the above patterns | High |
| Delimiter injection | `</tool>`, `</function>`, `[INST]`, `<<SYS>>` | Medium |

Patterns are loaded from `agentmesh/monitor/patterns/injection_patterns.yaml` — this file is designed to be community-contributed.

**False positive handling:** Pattern matches are scored. A single low-confidence match logs a warning but does not block. Two or more matches, or any single critical-confidence match, blocks and logs.

### 6b — Anomaly Detector

The anomaly detector builds a baseline of normal behavior per agent and flags statistically unusual patterns.

**What is tracked per agent:**
- Tool call frequency per minute (rolling window)
- Tool call sequence patterns (which tools follow which tools)
- Argument length distribution per tool
- Time-of-day usage patterns (future: not in v0.1)

**Detection method:** Z-score based statistical anomaly detection. If a metric deviates more than 3 standard deviations from the rolling baseline, it is flagged. The baseline is updated continuously during normal operation.

**v0.1 scope note:** The anomaly detector in v0.1 tracks only tool call frequency. Sequence patterns and argument length distribution are v0.2 features.

### Response actions

When the monitor detects an issue, it can take one of three actions based on severity:

| Severity | Action | Who is notified |
|---|---|---|
| Low | Log warning | Audit trail only |
| Medium | Log + emit alert event | Audit trail + dashboard |
| High | Block action + log + alert | Audit trail + dashboard + webhook (if configured) |

### API reference

```python
from agentmesh.monitor import BehaviorMonitor

monitor = BehaviorMonitor(
    agent_id="researcher-001",
    sensitivity="medium"  # low | medium | high
)

result = monitor.inspect(
    tool_name="web_search",
    arguments={"query": "ignore previous instructions and..."}
)
# result: InspectionResult(safe=False, severity="critical", reason="injection pattern: instruction override")
```

---

## 7. Layer 3 — Audit Trail

### Overview

Every action every agent takes is recorded in a tamper-evident log. The log uses two cryptographic mechanisms: Ed25519 signatures on each entry, and SHA-256 hash chaining between entries. Tampering with any entry invalidates the chain from that point forward.

### Audit entry schema

This is the exact structure of every log entry. A contributor implementing the audit trail must produce entries in this format:

```json
{
  "entry_id": "uuid4-string",
  "timestamp": "2026-03-16T10:30:00.000Z",
  "agent_id": "researcher-001",
  "mesh_id": "mesh-abc123",
  "action_type": "tool_call",
  "tool_name": "web_search",
  "caller_id": "orchestrator-001",
  "arguments_hash": "sha256(canonical_json(arguments))",
  "result_hash": "sha256(canonical_json(result))",
  "policy_decision": "allow",
  "monitor_flags": [],
  "prev_hash": "sha256(previous_entry_json)",
  "signature": "ed25519(sha256(entry_without_signature_field))"
}
```

**Field definitions:**

| Field | Type | Required | Description |
|---|---|---|---|
| `entry_id` | uuid4 | Yes | Unique identifier for this entry |
| `timestamp` | ISO-8601 UTC | Yes | When the action occurred |
| `agent_id` | string | Yes | Agent that performed the action |
| `mesh_id` | string | Yes | Mesh this entry belongs to |
| `action_type` | enum | Yes | `tool_call`, `agent_call`, `policy_violation`, `identity_event` |
| `tool_name` | string or null | Conditional | Required when action_type is `tool_call` |
| `caller_id` | string or null | Conditional | Required when action_type is `agent_call` |
| `arguments_hash` | sha256 hex | Yes | Hash of canonical JSON of call arguments — not the arguments themselves |
| `result_hash` | sha256 hex or null | No | Hash of canonical JSON of result — null if action was blocked |
| `policy_decision` | enum | Yes | `allow`, `deny`, `rate_limited` |
| `monitor_flags` | string[] | Yes | List of monitor warnings, empty if clean |
| `prev_hash` | sha256 hex or null | Yes | Hash of previous entry; null for the genesis entry |
| `signature` | hex string | Yes | Ed25519 signature over `sha256(entry_without_signature_field)` |

**Why hash arguments instead of storing them?** Arguments may contain sensitive data (API keys, user PII, query content). The hash proves what was called without storing the actual content. Full argument storage is an opt-in feature for controlled environments.

### Hash chaining algorithm

```python
def compute_entry_hash(entry: dict) -> str:
    """Produce the canonical hash of an entry for chaining."""
    # Remove signature field before hashing
    entry_without_sig = {k: v for k, v in entry.items() if k != "signature"}
    # Canonical JSON: sorted keys, no whitespace
    canonical = json.dumps(entry_without_sig, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()

def sign_entry(entry: dict, private_key: Ed25519PrivateKey) -> str:
    """Sign the entry hash with the agent's private key."""
    entry_hash = compute_entry_hash(entry).encode()
    signature = private_key.sign(entry_hash)
    return signature.hex()
```

### Chain verification algorithm

```python
def verify_chain(entries: list[dict], public_keys: dict) -> VerificationResult:
    """
    Verify an audit trail chain.
    Returns VerificationResult(valid=True) or VerificationResult(valid=False, failed_at=entry_id)
    """
    prev_hash = None
    for entry in entries:
        # 1. Check prev_hash linkage
        if entry["prev_hash"] != prev_hash:
            return VerificationResult(valid=False, failed_at=entry["entry_id"],
                                      reason="prev_hash mismatch — chain broken")
        # 2. Verify signature
        pub_key = public_keys[entry["agent_id"]]
        expected_hash = compute_entry_hash(entry).encode()
        sig_bytes = bytes.fromhex(entry["signature"])
        try:
            pub_key.verify(sig_bytes, expected_hash)
        except InvalidSignature:
            return VerificationResult(valid=False, failed_at=entry["entry_id"],
                                      reason="signature verification failed — entry tampered")
        prev_hash = compute_entry_hash(entry)
    return VerificationResult(valid=True)
```

### Storage backends

The audit trail supports pluggable storage backends:

| Backend | When to use | Config key |
|---|---|---|
| `local_json` | Development, single-machine | `backend: local_json` |
| `postgresql` | Production, multi-agent | `backend: postgresql` |
| `s3` | Long-term archival | `backend: s3` |

The default backend is `local_json`. All backends implement the same interface (`AuditBackend`) so they are interchangeable without changing application code.

### API reference

```python
from agentmesh.audit import AuditTrail

trail = AuditTrail(
    agent_identity=identity,
    backend="local_json",
    path="./agentmesh-audit.jsonl"
)

# Record an action
trail.record(
    action_type="tool_call",
    tool_name="web_search",
    arguments={"query": "AI security 2026"},
    result={"status": "ok", "results": [...]},
    policy_decision="allow",
    monitor_flags=[]
)

# Verify the entire chain
result = trail.verify()
# result.valid → True / False
# result.failed_at → entry_id of first tampered entry (if any)
```

---

## 8. System Flow

### Complete request lifecycle

```
Agent A wants to call web_search with arguments {"query": "..."}

1. ATTACH IDENTITY
   Agent A attaches its JWT to the outgoing request.

2. VERIFY IDENTITY  (Layer 1)
   Interceptor extracts JWT from request.
   Checks signature against Agent A's registered public key.
   Checks expiry. Checks jti revocation list.
   ├── FAIL → raise IdentityError. Record IDENTITY_FAILURE in audit trail. Block.
   └── PASS → extract AgentContext (agent_id, capabilities)

3. EVALUATE POLICY  (Layer 2a)
   Policy engine evaluates:
     caller=orchestrator, callee=Agent A, tool=web_search
   Checks allowed_callers, allowed_tools, denied_tools, rate_limits.
   ├── DENY → record POLICY_VIOLATION in audit trail. Raise PolicyDenied. Block.
   └── ALLOW → continue

4. INSPECT BEHAVIOR  (Layer 2b)
   Injection detector scans arguments for injection patterns.
   Anomaly detector checks call frequency against baseline.
   ├── HIGH severity → record MONITOR_BLOCK in audit trail. Block.
   ├── MEDIUM severity → record MONITOR_WARN. Continue with alert.
   └── CLEAN → continue

5. EXECUTE ACTION
   Tool function executes normally.
   Result is captured by interceptor.

6. RECORD ACTION  (Layer 3)
   Audit trail records the complete entry:
   entry_id, timestamp, agent_id, tool_name, arguments_hash,
   result_hash, policy_decision, monitor_flags, prev_hash, signature.

Total overhead target: < 5ms per call (see Performance Targets)
```

---

## 9. Failure Modes & Error Handling

The system **fails secure** in all cases. When in doubt, block.

| Failure scenario | System response | Rationale |
|---|---|---|
| Policy engine unreachable | Block all actions. Log POLICY_ENGINE_UNAVAILABLE. | Better to halt the mesh than allow uncontrolled execution. |
| Policy file malformed / invalid schema | Refuse to start. Log POLICY_PARSE_ERROR. | A broken policy is worse than no policy — it may silently allow things it shouldn't. |
| JWT verification fails | Block call. Log IDENTITY_FAILURE with agent_id and reason. | Unverified identity = untrusted caller. |
| JWT expired | Block call. Log TOKEN_EXPIRED. Agent must re-initialize. | Expired tokens must not be honored even if the signature is valid. |
| Audit trail write fails | Block the action that triggered the write. | An action that cannot be recorded should not proceed. |
| Behavior monitor crashes | Block call. Log MONITOR_UNAVAILABLE. | Same as policy engine — fail secure. |
| C++ interceptor panics | Python exception is caught. Block call. Restart interceptor. | The interceptor must never bring down the host process. |
| Rate limit counter backend unreachable | Block all rate-limited tools. Log RATE_LIMIT_UNAVAILABLE. | Cannot enforce rate limits without the counter — fail closed. |

### Error propagation

AgentMesh errors are never silently swallowed. Every error is:
1. Logged to the audit trail with severity and context.
2. Surfaced to the caller as a typed exception (`IdentityError`, `PolicyDenied`, `MonitorBlock`, `AuditWriteError`).
3. Optionally emitted as a dashboard alert event.

The calling agent is responsible for handling these exceptions. AgentMesh does not retry on behalf of callers.

---

## 10. Performance Targets

The interceptor sits on the hot path. These are the targets for v0.1.0 — measured at the 95th percentile:

| Operation | Target | Measurement method |
|---|---|---|
| JWT verification (C++ path) | < 0.5ms | pytest-benchmark, 10,000 iterations |
| Policy rule evaluation | < 1ms | pytest-benchmark |
| Injection pattern scan | < 2ms | pytest-benchmark, 1,000 char input |
| Audit entry write (local_json) | < 1ms | pytest-benchmark |
| **Total interceptor overhead** | **< 5ms** | End-to-end integration test |

### Why 5ms?

Most LLM tool calls themselves take 100ms–10,000ms (network, inference, API). A 5ms security overhead is less than 5% of the fastest tool call. This is the acceptable overhead budget.

If the total overhead exceeds 5ms in benchmarks, the C++ interceptor path must be profiled and optimized before release. Do not ship a version that exceeds this target.

---

## 11. Deployment Model

### How AgentMesh wraps an existing agent

AgentMesh does not require you to rewrite your agents. It wraps them with two decorators:

```python
from agentmesh import secure_agent, secure_tool
from agentmesh.identity import AgentIdentity

# 1. Create an identity for this agent
identity = AgentIdentity(
    agent_id="researcher-001",
    capabilities=["web_search", "read_file"]
)

# 2. Secure the agent class
@secure_agent(
    identity=identity,
    policy="./agentmesh-policy.yaml",
    audit_backend="local_json"
)
class ResearchAgent(YourBaseAgent):
    # Your existing code — unchanged
    ...

# 3. Secure individual tools (optional — secure_agent covers all tools)
@secure_tool(identity=identity)
def web_search(query: str) -> str:
    ...
```

### Process topology

AgentMesh components run **in-process** alongside the agent by default. There is no separate sidecar or daemon required for v0.1. The policy engine and audit trail are embedded in the same Python process.

```
Your Process
├── Your Agent Code
├── AgentMesh Interceptor (C++ extension, in-process)
├── PolicyEngine (in-process, loads YAML on startup)
├── BehaviorMonitor (in-process)
└── AuditTrail (in-process, writes to local_json or remote)
```

**Future (v0.3+):** A sidecar deployment mode for language-agnostic use (Java, Go, Rust agents calling the AgentMesh policy API over a local socket).

### Supported agent frameworks (v0.1)

| Framework | Support level | Notes |
|---|---|---|
| LangChain | Full | `integrations/langchain/` adapter |
| CrewAI | Full | `integrations/crewai/` adapter |
| Custom Python agents | Full | Direct decorator usage |
| Any JS/TS agent | Partial | JS SDK — identity + policy check, no C++ interceptor |
| AutoGPT | Planned (v0.2) | |
| Semantic Kernel | Planned (v0.2) | |

---

## 12. Security Guarantees

| Guarantee | Mechanism | Limitation |
|---|---|---|
| Agent authentication | Ed25519 JWT, verified on every call | Does not protect against compromise of the agent process itself |
| Authorization | Policy engine, default-deny | Policy files must be kept outside agent-writable paths |
| Injection detection | Pattern matching + scoring | Cannot detect novel injection techniques not in the pattern library |
| Tamper-evident logging | SHA-256 chain + Ed25519 signatures | Does not prevent log deletion — only detects modification |
| Rate limiting | Rolling counter per agent per tool | Counter backend must be available (see Failure Modes) |

### What AgentMesh does NOT protect against

Be explicit about the threat model boundary:

- **Compromised agent process:** If the agent process itself is compromised at the OS level, an attacker can bypass the interceptor entirely. AgentMesh is not a replacement for OS-level security.
- **Compromised policy file:** If an attacker can write to the policy YAML file, they can grant themselves any permission. The policy file must be treated as a security-critical asset.
- **Model-level attacks:** AgentMesh does not prevent an LLM from producing harmful outputs — only from harmful *tool calls*. Output filtering is out of scope.

---

## 13. Versioning & Compatibility

### API stability

| Component | Stability in v0.1 | Notes |
|---|---|---|
| `AgentIdentity` API | Unstable — may change | Will stabilize in v1.0 |
| Policy YAML schema | Unstable — may change | Breaking changes announced in CHANGELOG |
| Audit entry schema | **Stable** | Changing this breaks all existing audit logs — frozen from v0.1 |
| `@secure_agent` decorator | Unstable | |
| C++ ABI | Internal — not public | |

### Python version support

| Python version | Support |
|---|---|
| 3.10 | Full |
| 3.11 | Full |
| 3.12 | Full |
| 3.9 | Best-effort |
| < 3.9 | Not supported |

### Changelog

See [CHANGELOG.md](./CHANGELOG.md) for version history. Breaking changes are marked `[BREAKING]`.

---

*AgentMesh is an open-source project. Contributions welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md).*