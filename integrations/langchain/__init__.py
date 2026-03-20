"""
AgentMesh LangChain Integration

Secures LangChain tools with AgentMesh identity, policy, and audit.
Requires: pip install langchain-core

Usage:

    # Pattern 1 — Decorator (existing tools, zero changes)
    from integrations.langchain import secure_langchain_tool

    @secure_langchain_tool(identity=my_identity, policy=my_engine)
    class WebSearchTool(BaseTool):
        name = "web_search"
        description = "Searches the web"
        def _run(self, query: str) -> str:
            return search(query)

    # Pattern 2 — Base class (new tools)
    from integrations.langchain import SecureTool

    class WebSearchTool(SecureTool):
        name = "web_search"
        description = "Searches the web"
        mesh_identity = my_identity
        def _run(self, query: str) -> str:
            return search(query)
"""

from integrations.langchain.adapter import SecureTool, secure_langchain_tool
from integrations.langchain.exceptions import (
    LangChainAdapterError,
    LangChainNotInstalledError,
    LangChainSecurityError,
)

__all__ = [
    "secure_langchain_tool",
    "SecureTool",
    "LangChainAdapterError",
    "LangChainNotInstalledError",
    "LangChainSecurityError",
]