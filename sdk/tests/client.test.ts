/**
 * AgentMesh JS SDK Tests
 *
 * All tests mock the REST server using Jest's fetch mock.
 * No live server is required to run these tests.
 *
 * Run with: npm test
 */

import { AgentMesh, SecureAgent } from "../src/client";
import { verifyToken } from "../src/identity";
import {
    AgentMeshError,
    IdentityError,
    PolicyDeniedError,
    ServerConnectionError,
    TimeoutError,
} from "../src/types";

// ---------------------------------------------------------------------------
// Mock fetch globally
// ---------------------------------------------------------------------------

const mockFetch = jest.fn();
global.fetch = mockFetch;

function mockResponse(data: unknown, status = 200): Response {
    return {
        ok: status >= 200 && status < 300,
        status,
        json: async () => data,
    } as Response;
}

beforeEach(() => {
    mockFetch.mockReset();
});

// ---------------------------------------------------------------------------
// verifyToken
// ---------------------------------------------------------------------------

describe("verifyToken", () => {
    const validResponse = {
        valid: true,
        agent_id: "researcher",
        mesh_id: "test-mesh",
        capabilities: ["web_search", "read_file"],
    };

    test("returns AgentContext on valid token", async () => {
        mockFetch.mockResolvedValueOnce(mockResponse(validResponse));
        const ctx = await verifyToken("valid.jwt.token");
        expect(ctx.agentId).toBe("researcher");
        expect(ctx.meshId).toBe("test-mesh");
        expect(ctx.capabilities).toContain("web_search");
    });

    test("throws IdentityError on expired token", async () => {
        mockFetch
            .mockResolvedValueOnce(mockResponse({ valid: false, error: "token_expired" }))
            .mockResolvedValueOnce(mockResponse({ valid: false, error: "token_expired" }));
        await expect(verifyToken("expired.token")).rejects.toThrow(IdentityError);
        await expect(verifyToken("expired.token")).rejects.toThrow("expired");
    });

    test("throws IdentityError on revoked token", async () => {
        mockFetch.mockResolvedValueOnce(
            mockResponse({ valid: false, error: "token_revoked" })
        );
        await expect(verifyToken("revoked.token")).rejects.toThrow(IdentityError);
    });

    test("throws IdentityError on invalid token", async () => {
        mockFetch.mockResolvedValueOnce(
            mockResponse({ valid: false, error: "invalid_token" })
        );
        await expect(verifyToken("bad.token")).rejects.toThrow(IdentityError);
    });

    test("throws ServerConnectionError when server unreachable", async () => {
        mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));
        await expect(verifyToken("token")).rejects.toThrow(ServerConnectionError);
    });

    test("throws TimeoutError when request times out", async () => {
        const abortError = new Error("AbortError");
        abortError.name = "AbortError";
        mockFetch.mockRejectedValueOnce(abortError);
        await expect(verifyToken("token", { timeoutMs: 100 })).rejects.toThrow(
            TimeoutError
        );
    });

    test("throws ServerConnectionError on non-200 response", async () => {
        mockFetch.mockResolvedValueOnce(mockResponse({}, 500));
        await expect(verifyToken("token")).rejects.toThrow(ServerConnectionError);
    });

    test("sends token in request body", async () => {
        mockFetch.mockResolvedValueOnce(mockResponse(validResponse));
        await verifyToken("my.jwt.token");
        const call = mockFetch.mock.calls[0];
        const body = JSON.parse(call[1].body as string);
        expect(body.token).toBe("my.jwt.token");
    });

    test("posts to correct endpoint", async () => {
        mockFetch.mockResolvedValueOnce(mockResponse(validResponse));
        await verifyToken("token", { serverUrl: "http://localhost:9000" });
        expect(mockFetch.mock.calls[0][0]).toBe(
            "http://localhost:9000/v1/identity/verify"
        );
    });
});

// ---------------------------------------------------------------------------
// AgentMesh.health()
// ---------------------------------------------------------------------------

describe("AgentMesh.health()", () => {
    test("returns health info when server is up", async () => {
        mockFetch.mockResolvedValueOnce(
            mockResponse({
                status: "ok",
                version: "0.1.0",
                policy_loaded: true,
                registered_agents: ["researcher", "orchestrator"],
            })
        );
        const mesh = new AgentMesh();
        const health = await mesh.health();
        expect(health.status).toBe("ok");
        expect(health.policyLoaded).toBe(true);
        expect(health.registeredAgents).toContain("researcher");
    });

    test("throws ServerConnectionError when server unreachable", async () => {
        mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));
        const mesh = new AgentMesh();
        await expect(mesh.health()).rejects.toThrow(ServerConnectionError);
    });
});

// ---------------------------------------------------------------------------
// AgentMesh.registerAgent()
// ---------------------------------------------------------------------------

describe("AgentMesh.registerAgent()", () => {
    test("returns a SecureAgent", () => {
        const mesh = new AgentMesh();
        const agent = mesh.registerAgent({
            agentId: "researcher",
            capabilities: ["web_search"],
            token: "test.token",
        });
        expect(agent).toBeInstanceOf(SecureAgent);
        expect(agent.agentId).toBe("researcher");
        expect(agent.capabilities).toContain("web_search");
    });

    test("tracks registered agents", () => {
        const mesh = new AgentMesh();
        mesh.registerAgent({ agentId: "a1", capabilities: [], token: "t1" });
        mesh.registerAgent({ agentId: "a2", capabilities: [], token: "t2" });
        expect(mesh.registeredAgentIds).toContain("a1");
        expect(mesh.registeredAgentIds).toContain("a2");
    });
});

// ---------------------------------------------------------------------------
// SecureAgent.callTool()
// ---------------------------------------------------------------------------

describe("SecureAgent.callTool()", () => {
    const validIdentity = {
        valid: true,
        agent_id: "researcher",
        mesh_id: "test-mesh",
        capabilities: ["web_search"],
    };

    const allowPolicy = {
        decision: "allow",
        reason: "rule match",
        agent_id: "researcher",
        tool_name: "web_search",
    };

    const denyPolicy = {
        decision: "deny",
        reason: "tool not in allowed_tools",
        agent_id: "researcher",
        tool_name: "forbidden_tool",
    };

    const rateLimitPolicy = {
        decision: "rate_limited",
        reason: "Rate limit exceeded: 10 calls/minute",
        agent_id: "researcher",
        tool_name: "web_search",
    };

    function makeAgent(): SecureAgent {
        const mesh = new AgentMesh();
        return mesh.registerAgent({
            agentId: "researcher",
            capabilities: ["web_search"],
            token: "valid.token",
        });
    }

    test("executes tool when identity valid and policy allows", async () => {
        mockFetch
            .mockResolvedValueOnce(mockResponse(validIdentity))  // identity verify
            .mockResolvedValueOnce(mockResponse(allowPolicy));   // policy evaluate

        const agent = makeAgent();
        const result = await agent.callTool(
            "web_search",
            { query: "AI security" },
            async (args) => ({ results: [`result for ${args.query}`] })
        );

        expect(result).toEqual({ results: ["result for AI security"] });
    });

    test("throws PolicyDeniedError when policy denies", async () => {
        mockFetch
            .mockResolvedValueOnce(mockResponse(validIdentity))
            .mockResolvedValueOnce(mockResponse(denyPolicy));

        const agent = makeAgent();
        await expect(
            agent.callTool("forbidden_tool", {}, async () => "nope")
        ).rejects.toThrow(PolicyDeniedError);
    });

    test("PolicyDeniedError has correct decision type on deny", async () => {
        mockFetch
            .mockResolvedValueOnce(mockResponse(validIdentity))
            .mockResolvedValueOnce(mockResponse(denyPolicy));

        const agent = makeAgent();
        try {
            await agent.callTool("forbidden_tool", {}, async () => "nope");
        } catch (err) {
            expect(err).toBeInstanceOf(PolicyDeniedError);
            expect((err as PolicyDeniedError).decision).toBe("deny");
        }
    });

    test("throws PolicyDeniedError on rate limit", async () => {
        mockFetch
            .mockResolvedValueOnce(mockResponse(validIdentity))
            .mockResolvedValueOnce(mockResponse(rateLimitPolicy));

        const agent = makeAgent();
        try {
            await agent.callTool("web_search", { query: "x" }, async () => "nope");
        } catch (err) {
            expect(err).toBeInstanceOf(PolicyDeniedError);
            expect((err as PolicyDeniedError).decision).toBe("rate_limited");
        }
    });

    test("throws IdentityError when token is invalid", async () => {
        mockFetch.mockResolvedValueOnce(
            mockResponse({ valid: false, error: "token_revoked" })
        );

        const agent = makeAgent();
        await expect(
            agent.callTool("web_search", {}, async () => "nope")
        ).rejects.toThrow(IdentityError);
    });

    test("tool function is NOT called when policy denies", async () => {
        mockFetch
            .mockResolvedValueOnce(mockResponse(validIdentity))
            .mockResolvedValueOnce(mockResponse(denyPolicy));

        const toolFn = jest.fn(async () => "result");
        const agent = makeAgent();

        await expect(
            agent.callTool("forbidden_tool", {}, toolFn)
        ).rejects.toThrow(PolicyDeniedError);

        expect(toolFn).not.toHaveBeenCalled();
    });

    test("tool function is NOT called when identity fails", async () => {
        mockFetch.mockResolvedValueOnce(
            mockResponse({ valid: false, error: "token_expired" })
        );

        const toolFn = jest.fn(async () => "result");
        const agent = makeAgent();

        await expect(
            agent.callTool("web_search", {}, toolFn)
        ).rejects.toThrow(IdentityError);

        expect(toolFn).not.toHaveBeenCalled();
    });

    test("fails secure when policy server unreachable", async () => {
        mockFetch
            .mockResolvedValueOnce(mockResponse(validIdentity))
            .mockRejectedValueOnce(new Error("ECONNREFUSED"));

        const agent = makeAgent();
        await expect(
            agent.callTool("web_search", {}, async () => "nope")
        ).rejects.toThrow(PolicyDeniedError);
    });

    test("sends correct agent_id and tool_name to policy endpoint", async () => {
        mockFetch
            .mockResolvedValueOnce(mockResponse(validIdentity))
            .mockResolvedValueOnce(mockResponse(allowPolicy));

        const agent = makeAgent();
        await agent.callTool(
            "web_search",
            { query: "test" },
            async () => "ok"
        );

        const policyCall = mockFetch.mock.calls[1];
        const body = JSON.parse(policyCall[1].body as string);
        expect(body.agent_id).toBe("researcher");
        expect(body.tool_name).toBe("web_search");
    });

    test("passes caller_id to policy endpoint when provided", async () => {
        mockFetch
            .mockResolvedValueOnce(mockResponse(validIdentity))
            .mockResolvedValueOnce(mockResponse(allowPolicy));

        const agent = makeAgent();
        await agent.callTool(
            "web_search",
            {},
            async () => "ok",
            "orchestrator" // callerAgent
        );

        const policyCall = mockFetch.mock.calls[1];
        const body = JSON.parse(policyCall[1].body as string);
        expect(body.caller_id).toBe("orchestrator");
    });

    test("tool exceptions propagate through interceptor", async () => {
        mockFetch
            .mockResolvedValueOnce(mockResponse(validIdentity))
            .mockResolvedValueOnce(mockResponse(allowPolicy));

        const agent = makeAgent();
        await expect(
            agent.callTool("web_search", {}, async () => {
                throw new Error("tool exploded");
            })
        ).rejects.toThrow("tool exploded");
    });
});

// ---------------------------------------------------------------------------
// Error hierarchy
// ---------------------------------------------------------------------------

describe("Error hierarchy", () => {
    test("IdentityError is AgentMeshError", () => {
        const err = new IdentityError("test", "code");
        expect(err).toBeInstanceOf(AgentMeshError);
        expect(err).toBeInstanceOf(Error);
        expect(err.name).toBe("IdentityError");
    });

    test("PolicyDeniedError is AgentMeshError", () => {
        const err = new PolicyDeniedError("test", "reason", "deny");
        expect(err).toBeInstanceOf(AgentMeshError);
        expect(err.decision).toBe("deny");
    });

    test("ServerConnectionError is AgentMeshError", () => {
        const err = new ServerConnectionError("test", "http://localhost");
        expect(err).toBeInstanceOf(AgentMeshError);
        expect(err.serverUrl).toBe("http://localhost");
    });

    test("TimeoutError is AgentMeshError", () => {
        const err = new TimeoutError(5000);
        expect(err).toBeInstanceOf(AgentMeshError);
        expect(err.timeoutMs).toBe(5000);
        expect(err.message).toContain("5000ms");
    });
});