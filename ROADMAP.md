# AgentMesh Roadmap

## v0.1.0 — Core Security Layer ✅ (Current)

- Ed25519 identity layer with JWT issuance and revocation
- Tool call interceptor with C++ fast path (pybind11)
- YAML policy engine with default-deny and rate limiting
- Behavior monitor: 33 injection patterns, Z-score anomaly detection
- Immutable audit trail: SHA-256 hash chain + Ed25519 signatures
- FastAPI REST layer for language-agnostic integration
- TypeScript SDK (`@agentmesh/client`)
- Real-time dashboard (Next.js + WebSocket)
- 289 tests, 88%+ coverage

## v0.2.0 — Framework Integrations

- LangChain adapter (`integrations/langchain/`)
- CrewAI adapter (`integrations/crewai/`)
- AutoGPT adapter (`integrations/autogpt/`)
- PostgreSQL audit backend
- Token refresh without restart

## v0.3.0 — Production Hardening

- S3 audit backend
- Multi-process credential store (Redis backend)
- Dashboard: policy editor UI
- Dashboard: agent dependency graph
- OpenTelemetry export

## v1.0.0 — Stable API

- Stable Python API (no breaking changes after this)
- Stable audit entry schema (frozen from v0.1)
- Complete API documentation
- Production deployment guide
- Enterprise policy templates

## Future

- MCP security scanner
- Cloud-hosted audit storage (AgentMesh Cloud)
- Go SDK, Rust SDK
- Enterprise policy templates for regulated industries (HIPAA, SOC2, FedRAMP)