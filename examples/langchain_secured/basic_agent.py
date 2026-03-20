"""
AgentMesh + LangChain: Secure Agent Example
============================================

This example shows how to secure a LangChain agent with AgentMesh
using the @secure_langchain_tool decorator.

Requirements:
    pip install langchain-core agentmesh

Run:
    python examples/langchain_secured/basic_agent.py
"""

from langchain_core.tools import BaseTool

from agentmesh.identity.agent_identity import AgentIdentity
from agentmesh.policy.engine import PolicyEngine
from agentmesh.audit.trail import AuditTrail
from integrations.langchain import secure_langchain_tool


# ---------------------------------------------------------------------------
# Step 1: Create cryptographic identity for each agent
# ---------------------------------------------------------------------------

orchestrator_identity = AgentIdentity(
    agent_id="orchestrator",
    capabilities=[],
    mesh_id="my-company-mesh",
)

researcher_identity = AgentIdentity(
    agent_id="researcher",
    capabilities=["web_search", "read_file"],
    mesh_id="my-company-mesh",
)

# ---------------------------------------------------------------------------
# Step 2: Load policy
# ---------------------------------------------------------------------------

policy = PolicyEngine.from_dict({
    "version": "1.0",
    "agents": {
        "orchestrator": {
            "allowed_tools": [],
            "allowed_callers": [],
        },
        "researcher": {
            "allowed_tools": ["web_search", "read_file"],
            "denied_tools": ["execute_shell", "write_file"],
            "allowed_callers": ["orchestrator"],
            "rate_limits": {
                "web_search": "10/minute",
            },
        },
    },
})

# ---------------------------------------------------------------------------
# Step 3: Secure your existing LangChain tools — one decorator, zero other changes
# ---------------------------------------------------------------------------

@secure_langchain_tool(
    identity=researcher_identity,
    policy=policy,
    caller_id="orchestrator",
)
class WebSearchTool(BaseTool):
    name: str = "web_search"
    description: str = "Search the web for current information about any topic."

    def _run(self, query: str) -> str:
        # Your real implementation here — AgentMesh checks happen before this runs
        return f"[Simulated] Search results for: {query}"


@secure_langchain_tool(
    identity=researcher_identity,
    policy=policy,
    caller_id="orchestrator",
)
class ReadFileTool(BaseTool):
    name: str = "read_file"
    description: str = "Read the contents of a file."

    def _run(self, path: str) -> str:
        return f"[Simulated] Contents of {path}"


# ---------------------------------------------------------------------------
# Step 4: Set up audit trail
# ---------------------------------------------------------------------------

trail = AuditTrail(
    identity=researcher_identity,
    path="agentmesh-audit.jsonl",
)

# ---------------------------------------------------------------------------
# Step 5: Use the tools — AgentMesh secures every call automatically
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("AgentMesh LangChain Adapter — Basic Example")
    print("=" * 50)

    # Allowed call — will succeed
    try:
        search_tool = WebSearchTool()
        result = search_tool._run("AI security best practices 2026")
        print(f"\n✅ web_search allowed: {result}")
        trail.record_tool_call(
            tool_name="web_search",
            arguments={"query": "AI security best practices 2026"},
            result=result,
        )
    except Exception as e:
        print(f"\n❌ web_search failed: {e}")

    # Attempt a denied tool — will be blocked by policy
    try:
        @secure_langchain_tool(
            identity=researcher_identity,
            policy=policy,
            caller_id="orchestrator",
        )
        class ShellTool(BaseTool):
            name: str = "execute_shell"
            description: str = "Execute shell commands."
            def _run(self, cmd: str) -> str:
                return f"output:{cmd}"

        ShellTool()._run("cat /etc/passwd")
        print("\n❌ execute_shell should have been blocked!")
    except Exception as e:
        print(f"\n✅ execute_shell correctly blocked: {type(e).__name__}")

    # Verify the audit chain
    verification = trail.verify_chain()
    print(f"\n🔒 Audit chain: {verification}")
    print(f"   {trail.entry_count} entries recorded")