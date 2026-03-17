# AgentMesh — Roadmap

This document describes what AgentMesh is building, when, and why. It is a living document — updated after each release.

**Current version:** pre-release (building toward v0.1.0)  
**Last updated:** March 2026

---

## Guiding principle

The roadmap prioritizes **correctness over features**. A security tool that is fast but wrong is worse than useless — it gives false confidence. Every version must be more secure and more correct than the one before it. New features come after existing features are hardened.

---

## Version history

No releases yet. See [v0.1.0](#v010--foundation) below.

---

## v0.1.0 — Foundation

**Target:** End of Week 8 (solo build phase)  
**Status:** In progress

This is the first public release. It establishes the four-layer security architecture and proves the core concept works end-to-end.

### What ships in v0.1.0

**Layer 1 — Identity**
- Ed25519 keypair generation per agent on initialization
- JWT issuance with agent_id, capabilities, mesh_id, iat, exp, jti fields
- Token verification on every inter-agent call
- jti revocation list (in-memory, Redis-backed optional)

**Layer 2a — Policy Engine**
- YAML policy file with full schema: allowed_tools, denied_tools, allowed_callers, rate_limits
- Default-deny enforcement — missing rule = blocked, always
- Rolling rate limit counters per agent per tool
- Schema validation on startup — malformed policy halts the engine

**Layer 2b — Behavior Monitor**
- Prompt injection detector with pattern library (5 categories, 20+ patterns)
- Scoring system: low-confidence = warn, critical or 2+ = block
- Anomaly detector: Z-score baseline tracking per agent (frequency-only in v0.1)
- C++ interceptor wrapping all tool calls with <5ms overhead at p95

**Layer 3 — Audit Trail**
- Ed25519 signed entries + SHA-256 hash chaining
- Full entry schema: entry_id, timestamp, agent_id, action_type, arguments_hash, result_hash, prev_hash, signature
- verify_chain() detects tampered entries with exact position
- Storage backends: local_json (default), postgresql, s3

**SDKs and integrations**
- Python core library published to PyPI as `agentmesh`
- TypeScript SDK published to npm as `@agentmesh/client`
- LangChain adapter in `integrations/langchain/`
- CrewAI adapter in `integrations/crewai/`

**Dashboard**
- Next.js real-time dashboard deployed to Vercel
- Live event feed via WebSocket
- Policy violations view
- Audit log browser with chain verification status
- Per-agent activity charts

**CI/CD**
- GitHub Actions: lint, type check, test, security scan on every PR
- Coverage enforcement: 85%+ overall, 90%+ on security-critical components
- Automated PyPI and npm publish on tag

### What does NOT ship in v0.1.0

These are explicitly deferred. They are not forgotten — they are in v0.2.0 or later.

- MCP server response scanning (critical gap — see threat model T7)
- Sequence anomaly detection (frequency-only in v0.1)
- IP/machine binding for JWT tokens
- AutoGPT, Semantic Kernel, Haystack integrations
- Sidecar deployment mode

---

## v0.2.0 — Hardening

**Target:** 6–8 weeks after v0.1.0  
**Theme:** Close the critical gaps identified in the v0.1.0 threat model

### Planned features

**MCP response scanning** *(highest priority)*  
The v0.1.0 threat model explicitly flags this as a critical gap (T7 residual risk). The behavior monitor currently scans outgoing tool call arguments but does not scan incoming MCP server responses before they reach the agent's LLM context. v0.2.0 adds a response scanner that treats all MCP server output as untrusted input.

**Sequence anomaly detection**  
v0.1.0 anomaly detection tracks tool call frequency only. v0.2.0 adds sequence pattern tracking — detecting when an agent calls tools in an unusual *order*, not just at an unusual *rate*. This catches more subtle compromise patterns.

**JWT source binding**  
Bind tokens to source IP or machine ID to mitigate JWT replay attacks before graceful shutdown (T6 residual risk in v0.1.0).

**Base64 and encoding-trick injection detection**  
v0.1.0 pattern matching does not decode and re-scan base64-encoded or unicode-obfuscated payloads. v0.2.0 adds a decode-and-scan step for arguments that are valid encoded strings.

**New framework integrations**  
AutoGPT adapter, Semantic Kernel adapter — contributed by community or maintainer.

**Sidecar deployment mode (beta)**  
Allow non-Python agents (Go, Java, Rust) to use AgentMesh via a local sidecar that exposes the policy check and audit trail via a local socket. Beta quality in v0.2.0, stable in v0.3.0.

---

## v0.3.0 — Scale

**Target:** 3–4 months after v0.2.0  
**Theme:** Production-readiness for teams running AgentMesh at scale

### Planned features

**Semantic injection classifier**  
v0.1.0 and v0.2.0 injection detection is pattern-based — it cannot catch novel injections with no known signature. v0.3.0 adds an optional LLM-based semantic classifier that runs *off* the hot path (async, non-blocking) to flag semantically malicious arguments that pass the pattern scan. This is opt-in because it adds latency and cost.

**Policy hot reload**  
Currently, policy changes require an agent restart. v0.3.0 allows policy files to be reloaded without downtime via a SIGHUP or API call.

**Remote credential store**  
v0.1.0 uses an in-memory credential store for public key registry. v0.3.0 adds a distributed credential store (Redis, etcd) for multi-process and multi-host deployments.

**Stable sidecar mode**  
The sidecar introduced in beta in v0.2.0 reaches stable quality. Language SDKs (Go, Rust) receive official support.

**OpenTelemetry export**  
Export audit trail events as OpenTelemetry spans so AgentMesh integrates with existing observability stacks (Datadog, Grafana, Jaeger).

---

## v1.0.0 — Stable

**Target:** 6–9 months after v0.1.0  
**Theme:** Stable API, production-proven, enterprise-ready

### What v1.0.0 means

- All public APIs are frozen. Breaking changes require a major version bump.
- The audit entry schema (frozen since v0.1.0) is formally part of the stable spec.
- All four layers have been independently reviewed by at least one external security researcher.
- The policy YAML schema is versioned and backwards-compatible.
- Documentation is complete: API reference, deployment guide, security hardening guide.

### Planned features for v1.0.0

**OWASP Agentic Top 10 coverage report**  
A published document mapping every OWASP Agentic risk to the AgentMesh component that addresses it, with test evidence.

**Formal security audit**  
Commission an independent security audit of the identity, policy, and audit trail components. Publish the findings and remediations.

**Enterprise policy templates**  
Community-contributed and maintainer-verified YAML policy configurations for common production scenarios: financial services, healthcare data handling, customer support automation.

**Multi-mesh federation**  
Allow agents from separate meshes to communicate with each other under controlled cross-mesh trust policies.

---

## Future — Post v1.0.0

These are ideas being tracked but not yet scheduled. They require community interest, real-world usage data, or significant research before being committed to a version.

| Idea | Why it matters | What's needed first |
|---|---|---|
| AgentMesh Cloud | Hosted audit storage + dashboard as a SaaS for teams who don't want to self-host | Stable v1.0 core |
| Hardware security module (HSM) key storage | Store agent private keys in HSM instead of process memory | Real enterprise demand |
| Formal verification of policy engine | Mathematically prove the default-deny invariant cannot be bypassed | Academic collaboration |
| WASM interceptor | Allow AgentMesh to run inside browser-based or edge agent runtimes | Browser agent adoption |
| Cross-language policy evaluation | Evaluate policies in any language without the Python runtime | Sidecar maturity |

---

## How the roadmap works

**Versions are not date-committed.** The dates above are estimates. A feature ships when it is correct and well-tested — not when a deadline arrives.

**The roadmap is open for input.** If you are using AgentMesh and a missing feature is blocking you, open a GitHub issue tagged `roadmap` and explain your use case. Roadmap decisions are driven by real usage, not by what sounds interesting.

**Breaking changes.** Before v1.0.0, APIs may change between minor versions. All breaking changes are marked `[BREAKING]` in `CHANGELOG.md` with a migration guide. After v1.0.0, breaking changes require a major version bump.

**Security fixes bypass the roadmap.** A critical security vulnerability will be fixed and released as a patch version regardless of what version is currently in development. Security always takes priority.

---

## Relationship to the threat model

The roadmap is explicitly ordered by the threat model. Features that close critical or high-severity residual risks in [`docs/security/THREAT_MODEL.md`](./docs/security/THREAT_MODEL.md) are scheduled before features that add new capabilities. This is intentional.

v0.1.0 closes: T1, T2, T3 (partial), T4 (partial), T5, T6  
v0.2.0 closes: T3 (full), T4 (full), T7 (full)  
v0.3.0 closes: remaining residual risks from the v0.1.0 threat model

---

*Want to contribute to a roadmap item? See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to get started.*