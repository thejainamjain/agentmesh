# AgentMesh + LangChain

Secure your LangChain tools with one decorator. Zero changes to existing agent code.

## Install

```bash
pip install langchain-core agentmesh
```

## 5-Line Quickstart

```python
from agentmesh.identity import AgentIdentity
from integrations.langchain import secure_langchain_tool

identity = AgentIdentity("researcher", ["web_search"])

@secure_langchain_tool(identity=identity)
class WebSearchTool(BaseTool):
    name = "web_search"
    description = "Search the web"
    def _run(self, query: str) -> str:
        return search(query)
```

That's it. Every call to `_run` now goes through AgentMesh identity verification,
policy enforcement, injection detection, and audit logging.

## Both Patterns

**Decorator — for existing tools:**
```python
@secure_langchain_tool(identity=identity, policy=engine, caller_id="orchestrator")
class WebSearchTool(BaseTool):
    ...
```

**Base class — for new tools:**
```python
from integrations.langchain import SecureTool

class WebSearchTool(SecureTool):
    name = "web_search"
    description = "Search the web"
    mesh_identity = identity
    mesh_policy = engine

    def _run(self, query: str) -> str:
        return search(query)
```

## What Gets Secured

Every `_run()` and `_arun()` call is intercepted:

1. **Identity** — Ed25519 JWT verified
2. **Policy** — YAML rules checked, default-deny
3. **Injection detection** — 33 patterns scanned
4. **Audit** — SHA-256 chained entry written

## Run the Examples

```bash
# Basic decorator example
python examples/langchain_secured/basic_agent.py

# SecureTool base class example
python examples/langchain_secured/secure_tool_class.py
```