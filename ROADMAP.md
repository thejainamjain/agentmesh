# AgentMesh Roadmap

---

## v0.1.x — Patches (Current)

**v0.1.2** (current)
- ✅ Attack Lab — interactive `/v1/attack/run` endpoint + dashboard UI
- ✅ Honest gap reporting — `❌ MISSED` when AgentMesh fails, not a false green tick
- ✅ Webhook exfil pattern fixed
- ✅ Dashboard configurable audit path — point at any `.jsonl` file

**v0.1.1**
- ✅ `agentmesh/__init__.py` complete public API
- ✅ LangChain adapter self-serialisation bug fixed
- ✅ 25 xfail tests documenting 12 known detection gaps
- ✅ CI C++ build fix, FastAPI deprecation removed

---

## v0.2.0 — Detection Gaps + Framework Integrations

**Detection gap fixes** (from `tests/security/test_known_gaps.py`)
- GAP-001: Unicode NFKC normalisation — `unicodedata.normalize('NFKC', text)`
- GAP-002: Leetspeak / character substitution — leet→ASCII translation table
- GAP-003: Zero-width character stripping — strip `\u200b\u200c\u200d\ufeff\u00ad`
- GAP-004: Multilingual patterns — FR/ES/DE/ZH critical variants
- GAP-006: Cross-argument pattern matching — concatenate all arg values
- GAP-010: Token doubling normalisation — deduplication pass
- GAP-011: Newline context injection patterns — `\n\nSYSTEM:` header detection
- GAP-012: JSON string argument parsing — `json.loads()` attempt on string args

**Framework integrations**
- CrewAI adapter (`integrations/crewai/`)
- AutoGPT adapter (`integrations/autogpt/`)
- Semantic Kernel adapter (`integrations/semantic_kernel/`)

**Audit backends**
- PostgreSQL backend — `AuditBackend` implementation for Postgres
- S3 backend — append-only S3 object storage

**Identity**
- Token refresh without agent restart — `AgentIdentity.refresh_token()`

---

## v0.3.0 — Production Hardening

- Multi-process credential store — Redis backend
- Dashboard: policy editor UI — view/edit `policy.yaml` in the browser
- Dashboard: agent dependency graph — visualise who can call what
- OpenTelemetry export adapter
- Go SDK

---

## v1.0.0 — Stable API

- Frozen public API — no breaking changes after this
- Frozen audit entry schema — v0.1 entries remain valid forever
- Complete API reference documentation
- Production deployment guide (Docker, Kubernetes)
- Enterprise policy templates (HIPAA, SOC2, FedRAMP)

---

## Future

- MCP security scanner — analyse MCP server tool definitions for risks before deployment
- AgentMesh Cloud — hosted audit storage with tamper-evident SLA
- Rust SDK
- Hardware security key support for agent identity (YubiKey, HSM)