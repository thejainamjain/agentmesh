from agentmesh.identity.exceptions import AgentMeshError


class LangChainAdapterError(AgentMeshError):
    """Base exception for all LangChain adapter errors."""


class LangChainNotInstalledError(LangChainAdapterError):
    """
    Raised when langchain-core is not installed.

    Install with: pip install langchain-core
    Or with the integration extras: pip install agentmesh[langchain]
    """

    def __init__(self) -> None:
        super().__init__(
            "langchain-core is required for the AgentMesh LangChain adapter. "
            "Install it with: pip install langchain-core\n"
            "Or install AgentMesh with extras: pip install agentmesh[langchain]"
        )


class LangChainSecurityError(LangChainAdapterError):
    """
    Raised when a LangChain tool is used without proper AgentMesh configuration.

    This happens when:
      - A SecureTool subclass is missing mesh_identity
      - A tool is called before identity is set
    """