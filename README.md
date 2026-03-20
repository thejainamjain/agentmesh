# 🛡️ AgentMesh

**Runtime trust and security layer for multi-agent AI systems.**

AgentMesh solves the problem no existing tool addresses: securing how AI agents communicate with, trust, and delegate to each other. Every inter-agent call is verified, every tool call is policy-checked, every action is cryptographically recorded.

[![CI](https://github.com/thejainamjain/agentmesh/actions/workflows/ci.yml/badge.svg)](https://github.com/thejainamjain/agentmesh/actions)
[![Coverage](https://img.shields.io/badge/coverage-88%25-brightgreen)](https://github.com/thejainamjain/agentmesh)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)

---

## Why AgentMesh?

| Tool | What it does | What it misses |
|---|---|---|
| Sage / Aegis | Single-agent OS firewall | Cannot secure agent-to-agent calls |
| LangSmith | Observability / tracing | No enforcement, no identity, no policy |
| OpenTelemetry | General telemetry | Not agent-aware, no security layer |
| **AgentMesh** | **Multi-agent runtime trust** | **This is what we build** |

---

## 5-Minute Quickstart (LangChain)

### 1. Install

```bash
pip install agentmesh
```

### 2. Create a policy file

```yaml
# policy.yaml
version: "1.0"
agents:
  orchestrator:
    allowed_tools: []
    allowed_callers: []
    can_delegate_to: [researcher]
  researcher:
    allowed_tools: [web_search, read_file]
    denied_tools: [execute_shell, write_file]
    allowed_callers: [orchestrator]
    rate_limits:
      web_search: 10/minute
```

### 3. Secure your LangChain agent

```python
from agentmesh.identity import AgentIdentity
from agentmesh.monitor import intercept_tools
from agentmesh.policy import PolicyEngine
from agentmesh.audit import AuditTrail

# Create cryptographic identity
identity = AgentIdentity(
    agent_id="researcher",
    capabilities=["web_search"],
)

# Load policy
engine = PolicyEngine.from_file("policy.yaml")

# Secure your tool — one decorator
@intercept_tools(identity=identity, policy=engine, caller_id="orchestrator")
def web_search(query: str) -> str:
    # Your existing tool implementation — unchanged
    return search_the_web(query)

# Record everything
trail = AuditTrail(identity=identity)

# Use it — AgentMesh checks identity + policy before every call
result = web_search(query="AI security 2026")
trail.record_tool_call(tool_name="web_search", arguments={"query": "AI security 2026"})
```

### 4. Start the API server (for JS SDK + dashboard)

```bash
# Generate a secret key first
python -c "import secrets; print(secrets.token_hex(32))"

# Set it in your environment
export AGENTMESH_SECRET_KEY=<your-generated-key>

# Start the server
python -m agentmesh.api.server --policy policy.yaml --port 8000
```

### 5. Verify it's working

```bash
curl http://localhost:8000/health
# {"status":"ok","version":"0.1.0","policy_loaded":true,"registered_agents":["researcher","orchestrator"]}
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│               AgentMesh Runtime                     │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │  Layer 1: Identity — Ed25519 JWT per agent    │  │
│  └───────────────────────────────────────────────┘  │
│  ┌──────────────────┐  ┌──────────────────────────┐ │
│  │ Layer 2a: Policy │  │ Layer 2b: Behavior       │ │
│  │ YAML · deny-all  │  │ Injection · Anomaly      │ │
│  └──────────────────┘  └──────────────────────────┘ │
│  ┌───────────────────────────────────────────────┐  │
│  │  Layer 3: Audit — Ed25519 signed · SHA-256    │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
         ↑            ↑            ↑
      Agent A      Agent B      Agent C
```

**Four security layers, applied in order on every tool call:**

1. **Identity** — Ed25519 keypairs, JWT tokens, revocation
2. **Policy** — YAML rules, default-deny, rate limiting
3. **Behavior Monitor** — 33 injection patterns, Z-score anomaly detection
4. **Audit Trail** — SHA-256 hash chain, Ed25519 signed, tamper-evident

---

## Security Features

- **Default deny** — no rule = blocked. Always.
- **Prompt injection detection** — 33 patterns across 9 OWASP 2025 attack categories
- **Base64 decode + scan** — catches encoded payloads
- **Typoglycemia resistance** — catches scrambled keyword attacks
- **Immutable audit trail** — tamper with any entry and `verify_chain()` detects it
- **Credential protection** — arguments are never stored, only their SHA-256 hash
- **Rate limiting** — per-agent, per-tool rolling window counters
- **Fail secure** — policy server unreachable = deny. Audit write fails = deny.

---

## What AgentMesh Protects Against

Based on [OWASP LLM Top 10 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/):

| Attack | Protection |
|---|---|
| Agent impersonation | Ed25519 JWT verified on every call |
| Unauthorized tool access | Policy engine default-deny |
| Prompt injection (33 variants) | InjectionDetector pattern library |
| DAN / jailbreak | Role hijack patterns |
| Credential theft | Denied tool patterns + argument hashing |
| Data exfiltration | Exfiltration pattern detection |
| Replay attacks | JWT `jti` revocation list |
| Audit tampering | SHA-256 hash chain + Ed25519 signatures |

---

## Installation

```bash
pip install agentmesh

# Optional: API server dependencies
pip install agentmesh[server]  # FastAPI + uvicorn

# Optional: dashboard
cd dashboard && npm install && npm run dev
```

---

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — deep technical design
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [ROADMAP.md](ROADMAP.md) — what's coming next
- [CHANGELOG.md](CHANGELOG.md) — version history

---

## Contributing

AgentMesh is open source under Apache 2.0. Contributions are welcome.

The easiest way to contribute is to add new injection patterns to
`agentmesh/monitor/patterns/injection_patterns.yaml` — each pattern is a self-contained
PR that makes AgentMesh more secure for everyone.

See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).