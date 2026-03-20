# 🛡️ AgentMesh

**Runtime trust and security layer for multi-agent AI systems.**

AgentMesh solves the problem no existing tool addresses: securing how AI agents communicate with, trust, and delegate to each other. Every inter-agent call is identity-verified, every tool call is policy-checked, every action is cryptographically recorded — and every detection gap is publicly documented.

[![CI](https://github.com/thejainamjain/agentmesh/actions/workflows/ci.yml/badge.svg)](https://github.com/thejainamjain/agentmesh/actions)
[![Coverage](https://img.shields.io/badge/coverage-88%25-brightgreen)](https://github.com/thejainamjain/agentmesh)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

---

## The Problem

When multiple AI agents collaborate — an orchestrator delegating to a researcher, a researcher calling tools, a summarizer writing output — there is currently no standard way to verify:

- **Identity** — Is this message actually from Agent A, or an impersonator?
- **Policy** — Is Agent A allowed to call this specific tool?
- **Safety** — Has this tool call been hijacked by a prompt injection?
- **Audit** — What did Agent A actually do? Can I prove it wasn't tampered with?

AgentMesh wraps any multi-agent system with four security layers that answer all four questions on every single call.

---

## Why AgentMesh?

| Tool | What it does | What it misses |
|---|---|---|
| Sage / Aegis | Single-agent OS firewall | Cannot secure agent-to-agent calls |
| LangSmith | Observability / tracing | No enforcement, no identity, no policy |
| OpenTelemetry | General telemetry | Not agent-aware, no security layer |
| **AgentMesh** | **Multi-agent runtime trust** | **This is what we build** |

OWASP released its [Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) in December 2025. Agent impersonation and privilege escalation are listed as primary threats. No open-source tool addressed them. AgentMesh does.

---

## Live Demo

See 5 real attacks blocked side by side — with and without AgentMesh:

```bash
pip install agentmesh rich
python demo/run_demo.py
```

```
Normal Operation ─────────────────────────────────────────────────────────────
  WITHOUT AgentMesh              │  WITH AgentMesh
  ✅ web_search — allowed        │  ✅ web_search — Identity ✓ Policy ✓ Clean ✓
  ✅ write_summary — allowed     │  ✅ write_summary — Identity ✓ Policy ✓ Audit ✓

⚡ ATTACK: Prompt Injection via Poisoned Web Search (OWASP T3) ───────────────
  ✅ web_search — ALLOWED        │  🛡️  web_search — BLOCKED (1.2ms)
  💀 Injection reached LLM       │  ✅ Caught before LLM sees it

⚡ ATTACK: Privilege Escalation — Researcher calls write_file (OWASP T2) ─────
  ✅ write_file — ALLOWED        │  🛡️  write_file — BLOCKED (0.8ms)
  💀 Attacker planted cron job   │  ✅ denied_tools enforcement
```

Run individual attacks:
```bash
python demo/run_demo.py --attack injection
python demo/run_demo.py --attack escalation
python demo/run_demo.py --attack shell
python demo/run_demo.py --attack exfiltration
python demo/run_demo.py --attack impersonation
```

---

## 5-Minute Quickstart

### 1. Install

```bash
pip install agentmesh
# With LangChain:
pip install agentmesh langchain-core
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
    denied_tools: [execute_shell, write_file, send_email]
    allowed_callers: [orchestrator]
    rate_limits:
      web_search: 10/minute
```

### 3. Secure your tools

**Pure Python:**
```python
from agentmesh import AgentIdentity, PolicyEngine, intercept_tools, AuditTrail

identity = AgentIdentity("researcher", ["web_search"])
engine   = PolicyEngine.from_file("policy.yaml")
trail    = AuditTrail(identity=identity)

@intercept_tools(identity=identity, policy=engine, caller_id="orchestrator")
def web_search(query: str) -> str:
    return my_search_function(query)  # your existing code — unchanged
```

**LangChain:**
```python
from langchain_core.tools import BaseTool
from agentmesh import AgentIdentity, PolicyEngine
from integrations.langchain import secure_langchain_tool

identity = AgentIdentity("researcher", ["web_search"])
engine   = PolicyEngine.from_file("policy.yaml")

@secure_langchain_tool(identity=identity, policy=engine, caller_id="orchestrator")
class WebSearchTool(BaseTool):
    name = "web_search"
    description = "Search the web"
    def _run(self, query: str) -> str:
        return my_search_function(query)  # unchanged
```

### 4. Start the API server

```bash
# Generate a secret key
python -c "import secrets; print(secrets.token_hex(32))"

# Copy env template and fill in your key
cp .env.example .env

# Start the server
export $(cat .env | xargs)
python -m agentmesh.api.server --policy policy.yaml --port 8000

# Verify
curl http://localhost:8000/health
# {"status":"ok","version":"0.1.0","policy_loaded":true,"registered_agents":["researcher","orchestrator"]}
```

### 5. Start the dashboard

```bash
cd dashboard
cp .env.local.example .env.local   # fill in NEXT_PUBLIC_WS_SECRET
npm install && npm run dev
# → http://localhost:3000
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     AgentMesh Runtime                        │
│                                                              │
│  Layer 1 — Identity ─────────────────────────────────────── │
│  Ed25519 keypair per agent · JWT issuance · revocation       │
│                                                              │
│  Layer 2a — Policy          Layer 2b — Behavior Monitor ──── │
│  YAML rules · default-deny   33 injection patterns           │
│  rate limiting · deny_tools  Z-score anomaly detection       │
│                                                              │
│  Layer 3 — Audit ─────────────────────────────────────────── │
│  SHA-256 hash chain · Ed25519 signed · tamper-evident JSONL  │
└──────────────────────────────────────────────────────────────┘
       ↑                   ↑                   ↑
   Agent A             Agent B             Agent C
```

Every tool call passes through all four layers in order. If any layer rejects the call, it is blocked and recorded — the tool function body never executes.

---

## What AgentMesh Catches ✅

| Attack | OWASP | How It's Blocked |
|---|---|---|
| Agent impersonation | T1 | Ed25519 JWT verified — wrong keypair = rejected |
| Unauthorized tool access | T2 | Policy default-deny — not in `allowed_tools` = blocked |
| Privilege escalation | T2 | `denied_tools` list — explicit block before allow check |
| Prompt injection (classic) | T3 | Pattern library — CRITICAL/HIGH = immediate block |
| DAN / jailbreak | T3 | Role hijack patterns |
| Base64 encoded payloads | T3 | Substring decode + rescan |
| Typoglycemia attacks | T3 | Character normalisation before matching |
| Credential theft via keywords | T3 | Credential theft patterns |
| Webhook data exfiltration | T3 | Exfiltration patterns |
| Replay attacks | T1 | JWT `jti` revocation list |
| Rate limit abuse | T2 | Rolling window per agent+tool |
| Audit tampering | — | SHA-256 chain — any modification detected by `verify_chain()` |
| XML/ChatML/delimiter injection | T3 | Delimiter injection patterns |
| Shell injection keywords | CWE-78 | Shell injection patterns |

---

## Known Detection Gaps ❌

AgentMesh documents what it does NOT catch. These are `xfail` tests in [`tests/security/test_known_gaps.py`](tests/security/test_known_gaps.py) — they are visible in CI output and each one maps to a fixable issue.

You can test every gap interactively in the **Attack Lab** tab of the dashboard. When AgentMesh misses an attack, the UI shows `❌ MISSED — attack not detected`, not a false green tick.

| Gap | Bypass Technique | Fix Needed |
|---|---|---|
| GAP-001 | Unicode homoglyphs (`Ιgnore` with Greek Iota) | NFKC normalisation |
| GAP-002 | Leetspeak (`1gn0r3 pr3v10us`) | Leet→ASCII translation |
| GAP-003 | Zero-width characters (`ignore​previous`) | Strip ZWC before matching |
| GAP-004 | Non-English payloads (French, Spanish, German) | Multilingual patterns |
| GAP-005 | Semantic equivalents (`discard your directives`) | Expand pattern library |
| GAP-006 | Payload split across two arguments | Cross-argument concatenation |
| GAP-007 | Subtle role suggestion (`no restrictions from now`) | New patterns |
| GAP-008 | Indirect exfiltration (`include in URL parameter`) | New patterns |
| GAP-009 | Context switch via separators (`---`, `====`) | Header detection patterns |
| GAP-010 | Token doubling (`iiggnnoorre`) | Deduplication normalisation |
| GAP-011 | Newline context injection (`\n\nSYSTEM:`) | Newline header patterns |
| GAP-012 | Payload buried in JSON string value | JSON.parse string args |

**Fixing any gap is a good first PR.** Each row is a self-contained change, most under 20 lines.

---

## Project Status

```
Python tests:   312 passing  |  25 xfail (known gaps)  |  0 failing
Coverage:       88%+  (target: 85%)
Red-team suite: 31/31 payloads blocked  |  0 false positives
Tamper detect:  6/6 scenarios caught
TypeScript SDK: 29 Jest tests passing
CI:             Python 3.11 · 3.12 · 3.13 · Jest · bandit
```

---

## What's Working vs What's Partial vs Not Yet Built

### Fully Working ✅

- Ed25519 identity — keypairs, JWT, revocation, jti tracking
- Policy engine — YAML, default-deny, denied_tools, rate limits, caller verification
- Injection detector — 33 patterns, base64 decode, typoglycemia normalisation
- Anomaly detector — Welford Z-score, rolling window per agent+tool
- Audit trail — SHA-256 chain, Ed25519 signed, tamper detection, JSONL backend
- FastAPI REST server — all 5 routes (see API Reference below)
- WebSocket streaming — real-time audit, shared-secret auth
- TypeScript SDK — `AgentMesh`, `SecureAgent.callTool()`, typed errors, fail-secure
- Next.js dashboard — Monitor tab (live audit feed) + Attack Lab tab
- Attack Lab — user-supplied payloads, real detection result, honest gap display
- LangChain adapter — `@secure_langchain_tool` + `SecureTool`, sync + async
- CI/CD — GitHub Actions on Python 3.11/3.12/3.13 + Jest + bandit

### Partial ⚠️

- **Injection detector** — catches 31/31 known payloads; 12 bypass techniques documented as gaps
- **Anomaly detector** — warms up after 5 samples; first 5 calls per tool are not anomaly-checked
- **LangChain adapter** — `BaseTool` subclass decorator works; `@tool` function decorator not yet supported
- **Audit trail** — `LocalJsonlBackend` production-ready; PostgreSQL + S3 deferred to v0.2

### Not Yet Built ❌

- CrewAI adapter
- AutoGPT adapter
- PostgreSQL audit backend
- S3 audit backend
- Token refresh without restart
- Dashboard policy editor
- Multi-process credential store

---

## API Reference

| Method | Path | Description | Auth Required |
|---|---|---|---|
| `GET` | `/health` | Server status, version, policy info | No |
| `POST` | `/v1/identity/verify` | Verify a JWT token | No |
| `POST` | `/v1/policy/evaluate` | Check if agent can call a tool | No |
| `WS` | `/ws/audit` | Real-time audit stream | `AGENTMESH_SECRET_KEY` in body |
| `POST` | `/v1/attack/run` | Run attack in Attack Lab | `AGENTMESH_ATTACK_LAB=true` |

All policy evaluations default to **deny** if no policy is loaded. The WebSocket endpoint rejects all connections if `AGENTMESH_SECRET_KEY` is not set.

---

## Repository Structure

```
agentmesh/
├── agentmesh/               Python core library
│   ├── identity/            Ed25519 JWT identity layer
│   ├── policy/              YAML policy engine
│   ├── monitor/             Injection + anomaly detection
│   │   └── patterns/        injection_patterns.yaml
│   ├── audit/               SHA-256 chained audit trail
│   └── api/                 FastAPI REST server + WebSocket + Attack Lab
├── integrations/
│   └── langchain/           LangChain BaseTool adapter ✅
├── sdk/                     TypeScript SDK (@agentmesh/client)
├── dashboard/               Next.js real-time dashboard + Attack Lab UI
├── demo/                    Live attack demo (5 scenarios)
├── tests/
│   ├── unit/                312 unit + API tests
│   ├── integration/         LangChain adapter tests
│   └── security/            Red-team suite + 25 known gap (xfail) tests
├── examples/
│   ├── policy_examples/     5 reference policy YAMLs
│   └── langchain_secured/   LangChain quickstart example
└── docs/
    └── GOOD_FIRST_ISSUES.md
```

---

## Security Design Decisions

| Decision | Why |
|---|---|
| Arguments never stored — only SHA-256 hash | Protects PII and API keys from appearing in audit files |
| `deny_on_missing_rule` cannot be `false` | Prevents misconfiguration from opening the default-deny |
| WebSocket auth in message body, not URL | URL params appear in server logs; body does not |
| `AGENTMESH_WS_SECRET` not prefixed `NEXT_PUBLIC_` | Never exposed to browser bundle |
| Policy server unreachable = deny | Fail-secure: unavailability cannot bypass checks |
| Attack Lab disabled by default | The `/v1/attack/run` endpoint only works with `AGENTMESH_ATTACK_LAB=true` |
| Anomaly detector warms up over 5+ samples | Prevents false positives on agent startup |
| `verify_chain()` checks prev_hash + Ed25519 | Two independent tamper signals — breaking one doesn't hide the other |

---

## Environment Variables

**Python server (`.env`):**
```bash
# Required for WebSocket auth
AGENTMESH_SECRET_KEY=<generate: python -c "import secrets; print(secrets.token_hex(32))">

# Optional
AGENTMESH_HOST=127.0.0.1
AGENTMESH_PORT=8000
AGENTMESH_POLICY_PATH=policy.yaml
AGENTMESH_AUDIT_PATH=agentmesh-audit.jsonl

# Enable Attack Lab (disabled by default)
AGENTMESH_ATTACK_LAB=true
```

**Dashboard (`dashboard/.env.local`):**
```bash
NEXT_PUBLIC_API_URL=http://127.0.0.1:8000
NEXT_PUBLIC_WS_URL=ws://127.0.0.1:8000
NEXT_PUBLIC_WS_SECRET=<same as AGENTMESH_SECRET_KEY>
NEXT_PUBLIC_AUDIT_PATH=agentmesh-audit.jsonl
# For demo: NEXT_PUBLIC_AUDIT_PATH=demo/output/audit.jsonl
```

---

## Installation

```bash
# Core only
pip install agentmesh

# With API server
pip install "agentmesh[server]"

# With LangChain integration
pip install "agentmesh[langchain]"

# Dashboard
cd dashboard && npm install && npm run dev
```

---

## Contributing

AgentMesh is Apache 2.0. The easiest contribution is fixing one of the 12 documented detection gaps — each is under 20 lines and has a failing test waiting for it.

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/GOOD_FIRST_ISSUES.md](docs/GOOD_FIRST_ISSUES.md).

---

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — deep technical design
- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup, PR process, code style
- [ROADMAP.md](ROADMAP.md) — what's coming in v0.2 and beyond
- [CHANGELOG.md](CHANGELOG.md) — full version history with every fix
- [docs/GOOD_FIRST_ISSUES.md](docs/GOOD_FIRST_ISSUES.md) — 10 scoped issues for new contributors

---

## License

Apache 2.0 — see [LICENSE](LICENSE).