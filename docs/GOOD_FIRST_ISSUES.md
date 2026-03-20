# Good First Issues for v0.2.0

Open these on GitHub at launch. Each is self-contained for a new contributor.

1. **Add new injection patterns** — add 3+ patterns + red-team tests
2. **LangChain BaseTool adapter** — `integrations/langchain/adapter.py`
3. **CrewAI tool adapter** — `integrations/crewai/adapter.py`
4. **Policy template: HIPAA healthcare** — `examples/policy_examples/06_hipaa.yaml`
5. **Policy template: financial services** — `examples/policy_examples/07_financial.yaml`
6. **PostgreSQL audit backend** — implement `AuditBackend` for Postgres
7. **Token refresh without restart** — `AgentIdentity.refresh_token()`
8. **Dashboard: policy editor UI** — view/edit policy.yaml in the dashboard
9. **Go SDK** — implement `@agentmesh/client` equivalent in Go
10. **Expand red-team suite to 50+ payloads** — from HackAPrompt + recent research