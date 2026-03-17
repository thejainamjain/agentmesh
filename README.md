# AgentMesh

> Runtime trust & security layer for multi-agent AI systems

[![CI](https://github.com/yourusername/agentmesh/actions/workflows/ci.yml/badge.svg)](https://github.com/thejainamjain/agentmesh/actions)
[![Coverage](https://codecov.io/gh/yourusername/agentmesh/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/agentmesh)
[![PyPI](https://img.shields.io/pypi/v/agentmesh.svg)](https://pypi.org/project/agentmesh/)
[![npm](https://img.shields.io/npm/v/@agentmesh/client.svg)](https://www.npmjs.com/package/@agentmesh/client)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](./LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

---

## The problem

When AI agents collaborate — an orchestrator delegating tasks to sub-agents — there is no standard way to answer three questions:

- **Who is calling?** Is this message actually from the trusted orchestrator, or an impersonator?
- **Is this allowed?** Is this agent permitted to call this tool at all?
- **What happened?** Can I prove exactly what every agent did, in order, without trusting the logs?

Existing tools (Sage, Aegis, LangSmith) protect a single agent from its OS or provide observability after the fact. None of them secure the boundaries *between* agents.

AgentMesh fills that gap.

---

## What AgentMesh does

AgentMesh wraps any multi-agent system with four security layers:

```
┌─────────────────────────────────────────────────────┐
│                  AgentMesh Runtime                  │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │  Identity — Ed25519 JWT on every agent call  │   │
│  └──────────────────────────────────────────────┘   │
│  ┌─────────────────┐  ┌───────────────────────────┐ │
│  │  Policy Engine  │  │    Behavior Monitor       │ │
│  │  YAML · Deny    │  │  Injection · Anomaly      │ │
│  └─────────────────┘  └───────────────────────────┘ │
│  ┌──────────────────────────────────────────────┐   │
│  │  Audit Trail — signed · chained · tamper-    │   │
│  │  evident                                     │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

| Layer | What it does |
|---|---|
| **Identity** | Every agent gets an Ed25519 signed JWT. Verified on every inter-agent call. |
| **Policy engine** | YAML rules define exactly what each agent can do. Default-deny — no rule = blocked. |
| **Behavior monitor** | Scans every tool call for prompt injection. Detects anomalous agent behavior. |
| **Audit trail** | Ed25519 signed + SHA-256 chained log of every action. Tamper-evident. |

---

## Quickstart

**Install:**

```bash
pip install agentmesh
```

**Secure an agent in 3 lines:**

```python
from agentmesh import secure_agent
from agentmesh.identity import AgentIdentity

identity = AgentIdentity(agent_id="researcher", capabilities=["web_search", "read_file"])

@secure_agent(identity=identity, policy="./policy.yaml")
class ResearchAgent(YourBaseAgent):
    # Your existing code — unchanged
    ...
```

**Write a policy file:**

```yaml
# policy.yaml
version: "1.0"

agents:
  researcher:
    allowed_tools: [web_search, read_file]
    denied_tools: [execute_shell, write_file]
    allowed_callers: [orchestrator]
    rate_limits:
      web_search: "10/minute"
```

**That's it.** Every tool call `ResearchAgent` makes is now:
- verified against the caller's identity
- checked against your policy before execution
- scanned for prompt injection attempts
- recorded in a tamper-evident audit trail

**With LangChain:**

```python
from agentmesh.integrations.langchain import secure_langchain_agent

agent = secure_langchain_agent(
    agent=your_langchain_agent,
    agent_id="researcher",
    policy="./policy.yaml"
)
```

**With CrewAI:**

```python
from agentmesh.integrations.crewai import secure_crew

crew = secure_crew(
    crew=your_crew,
    policy="./policy.yaml"
)
```

**JavaScript / TypeScript:**

```bash
npm install @agentmesh/client
```

```typescript
import { AgentMesh } from '@agentmesh/client';

const mesh = new AgentMesh({ policyPath: './policy.yaml' });
const agent = mesh.registerAgent('researcher', ['web_search']);
await agent.callTool('web_search', { query: 'AI security 2026' });
```

---

## Why not existing tools?

| | AgentMesh | Sage / Aegis | LangSmith | OpenTelemetry |
|---|---|---|---|---|
| Agent-to-agent trust | ✅ | ❌ | ❌ | ❌ |
| Default-deny policy | ✅ | ❌ | ❌ | ❌ |
| Prompt injection detection | ✅ | Partial | ❌ | ❌ |
| Tamper-evident audit | ✅ | ❌ | ❌ | ❌ |
| Works with LangChain | ✅ | ✅ | ✅ | ✅ |
| Open source | ✅ | ✅ | ❌ | ✅ |

---

## Threat coverage

AgentMesh is built against a published threat model. v0.1.0 addresses:

| Threat | Severity | Status |
|---|---|---|
| Agent impersonation | 🔴 Critical | Mitigated — Identity layer |
| Unauthorized capability escalation | 🔴 Critical | Mitigated — Policy engine |
| Prompt injection hijacking | 🔴 Critical | Partially mitigated — Behavior monitor |
| Compromised agent behavior | 🟠 High | Partially mitigated — Anomaly detector |
| Audit log tampering | 🟠 High | Mitigated — Audit trail |
| JWT token replay | 🟠 High | Mitigated — jti revocation |
| Malicious MCP server injection | 🔴 Critical | Partially mitigated — v0.2.0 full fix |

Full details: [`docs/security/THREAT_MODEL.md`](./docs/security/THREAT_MODEL.md)

---

## Performance

The AgentMesh interceptor sits on the hot path. Benchmarked at p95:

| Operation | Target | Status |
|---|---|---|
| JWT verification | < 0.5ms | ✅ |
| Policy evaluation | < 1ms | ✅ |
| Injection scan (1,000 chars) | < 2ms | ✅ |
| **Total overhead per call** | **< 5ms** | ✅ |

Most LLM tool calls take 100ms–10,000ms. The security overhead is less than 5% of the fastest tool call.

---

## Project structure

```
agentmesh/           Python core library
  identity/          Layer 1 — JWT issuance and verification
  policy/            Layer 2a — YAML policy engine
  monitor/           Layer 2b — Injection and anomaly detection
    patterns/        Injection pattern YAML (community-contributed)
  audit/             Layer 3 — Tamper-evident audit trail
sdk/                 TypeScript SDK (@agentmesh/client)
dashboard/           Next.js real-time dashboard
integrations/        LangChain, CrewAI adapters
examples/            Working code examples
docs/security/       Threat model, security policy
```

---

## Documentation

- [Architecture](./ARCHITECTURE.md) — system design and implementation spec
- [Threat model](./docs/security/THREAT_MODEL.md) — attacks and mitigations
- [Roadmap](./ROADMAP.md) — what is coming and when
- [Contributing](./CONTRIBUTING.md) — how to contribute
- [Examples](./examples/) — working code for common use cases

---

## Contributing

AgentMesh is built in the open and contributions are welcome. The easiest place to start is adding a new injection detection pattern — no C++ knowledge required, and it directly improves security for everyone using AgentMesh.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup instructions, code standards, and the PR process.

Good first issues are labeled [`good first issue`](https://github.com/yourusername/agentmesh/labels/good%20first%20issue).

---

## Roadmap

- **v0.1.0** — Identity, policy engine, behavior monitor, audit trail, LangChain + CrewAI adapters *(in progress)*
- **v0.2.0** — MCP response scanning, sequence anomaly detection, JWT source binding
- **v0.3.0** — Semantic injection classifier, policy hot reload, OpenTelemetry export
- **v1.0.0** — Stable API, formal security audit, enterprise policy templates

Full roadmap: [ROADMAP.md](./ROADMAP.md)

---

## License

Apache 2.0 — see [LICENSE](./LICENSE).

---

*AgentMesh is pre-release software. The core architecture is stable but APIs may change before v1.0.0. See [ARCHITECTURE.md §13](./ARCHITECTURE.md#13-versioning--compatibility) for the stability guarantees per component.*