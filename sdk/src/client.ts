/**
 * AgentMesh Client — Main SDK Entry Point
 *
 * Usage:
 *   import { AgentMesh } from '@agentmesh/client';
 *
 *   const mesh = new AgentMesh({ serverUrl: 'http://127.0.0.1:8000' });
 *
 *   const agent = mesh.registerAgent({
 *     agentId: 'researcher',
 *     capabilities: ['web_search'],
 *     token: '<jwt from python AgentIdentity.issue_token()>',
 *   });
 *
 *   // Tool call goes through identity + policy checks automatically
 *   const result = await agent.callTool('web_search', { query: 'AI security' });
 *
 * Security guarantees:
 *   1. Identity verified on every callTool() — zero trust, same as Python interceptor
 *   2. Policy evaluated before every tool execution — default deny
 *   3. Tokens never logged — only agent_id on success
 *   4. Requests timeout after 5s by default — no hanging connections
 *   5. All errors are typed — callers cannot accidentally swallow security failures
 */

import {
    AgentConfig,
    AgentContext,
    AgentMeshConfig,
    HealthResponse,
    PolicyDecision,
    PolicyDeniedError,
    ServerConnectionError,
    TimeoutError,
    ToolArguments,
    ToolResult,
} from "./types.js";
import { verifyToken } from "./identity.js";

const DEFAULT_SERVER_URL = "http://127.0.0.1:8000";
const DEFAULT_TIMEOUT_MS = 5000;

// ---------------------------------------------------------------------------
// SecureAgent — wraps a registered agent and intercepts tool calls
// ---------------------------------------------------------------------------

/**
 * A registered agent that runs all tool calls through AgentMesh security checks.
 *
 * Created by AgentMesh.registerAgent() — do not instantiate directly.
 */
export class SecureAgent {
    private readonly _config: Required<AgentMeshConfig>;

    constructor(
        private readonly _agentConfig: AgentConfig,
        meshConfig: AgentMeshConfig
    ) {
        this._config = {
            serverUrl: meshConfig.serverUrl ?? DEFAULT_SERVER_URL,
            timeoutMs: meshConfig.timeoutMs ?? DEFAULT_TIMEOUT_MS,
            debug: meshConfig.debug ?? false,
        };
    }

    get agentId(): string {
        return this._agentConfig.agentId;
    }

    get capabilities(): string[] {
        return this._agentConfig.capabilities;
    }

    /**
     * Execute a tool call through AgentMesh security checks.
     *
     * Order of operations (mirrors the Python interceptor):
     *   1. Verify identity (JWT check via REST)
     *   2. Evaluate policy (allow/deny/rate_limited via REST)
     *   3. Execute the tool function
     *
     * @param toolName   Name of the tool to call
     * @param args       Tool arguments (JSON-serialisable)
     * @param toolFn     The actual tool implementation to call if checks pass
     * @param callerAgent Optional: ID of the agent invoking this one
     * @returns          Tool result
     * @throws           IdentityError if the token is invalid
     * @throws           PolicyDeniedError if the policy engine denies the call
     */
    async callTool<TArgs extends ToolArguments, TResult extends ToolResult>(
        toolName: string,
        args: TArgs,
        toolFn: (args: TArgs) => Promise<TResult>,
        callerAgent?: string
    ): Promise<TResult> {
        // ── Step 1: Verify identity ────────────────────────────────────────────
        // Re-verify on every call — zero trust. Same behaviour as Python interceptor.
        const _ctx: AgentContext = await verifyToken(this._agentConfig.token, this._config);

        if (this._config.debug) {
            console.debug(
                `[AgentMesh] Identity verified: agent=${_ctx.agentId} tool=${toolName}`
            );
        }

        // ── Step 2: Policy evaluation ──────────────────────────────────────────
        const decision = await this._evaluatePolicy(toolName, callerAgent);

        if (decision.decision !== "allow") {
            if (this._config.debug) {
                console.debug(
                    `[AgentMesh] Policy denied: agent=${this.agentId} tool=${toolName} reason=${decision.reason}`
                );
            }
            throw new PolicyDeniedError(
                `Tool call blocked by policy: ${decision.reason}`,
                decision.reason,
                decision.decision
            );
        }

        if (this._config.debug) {
            console.debug(
                `[AgentMesh] Policy allowed: agent=${this.agentId} tool=${toolName}`
            );
        }

        // ── Step 3: Execute tool ───────────────────────────────────────────────
        return toolFn(args);
    }

    private async _evaluatePolicy(
        toolName: string,
        callerId?: string
    ): Promise<PolicyDecision> {
        const url = `${this._config.serverUrl}/v1/policy/evaluate`;
        const body = JSON.stringify({
            agent_id: this._agentConfig.agentId,
            tool_name: toolName,
            caller_id: callerId ?? null,
        });

        let response: Response;
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this._config.timeoutMs);

            response = await fetch(url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body,
                signal: controller.signal,
            });

            clearTimeout(timeoutId);
        } catch (err) {
            if (err instanceof Error && err.name === "AbortError") {
                throw new TimeoutError(this._config.timeoutMs);
            }
            // Fail secure: if policy server is unreachable, deny the call
            throw new PolicyDeniedError(
                `Cannot reach AgentMesh policy server at ${this._config.serverUrl}. ` +
                `Tool call blocked — fail secure.`,
                "policy_server_unreachable",
                "deny"
            );
        }

        if (!response.ok) {
            throw new PolicyDeniedError(
                `Policy server returned HTTP ${response.status} — failing secure`,
                `http_error_${response.status}`,
                "deny"
            );
        }

        const data = await response.json() as {
            decision: "allow" | "deny" | "rate_limited";
            reason: string;
            agent_id: string;
            tool_name: string;
        };

        return {
            decision: data.decision,
            reason: data.reason,
            agentId: data.agent_id,
            toolName: data.tool_name,
        };
    }
}

// ---------------------------------------------------------------------------
// AgentMesh — the main client class
// ---------------------------------------------------------------------------

/**
 * The AgentMesh client.
 *
 * Create one instance per mesh. Use registerAgent() to create secured agents.
 */
export class AgentMesh {
    private readonly _config: AgentMeshConfig;
    private readonly _agents: Map<string, SecureAgent> = new Map();

    constructor(config: AgentMeshConfig = {}) {
        this._config = {
            serverUrl: config.serverUrl ?? DEFAULT_SERVER_URL,
            timeoutMs: config.timeoutMs ?? DEFAULT_TIMEOUT_MS,
            debug: config.debug ?? false,
        };

        if (this._config.debug) {
            console.debug(
                `[AgentMesh] Client initialised: serverUrl=${this._config.serverUrl}`
            );
        }
    }

    /**
     * Register an agent with the mesh.
     *
     * The agent's JWT token must be issued by the Python AgentIdentity layer.
     * The token is verified on every subsequent tool call.
     *
     * @param agentConfig  Agent configuration including token
     * @returns            A SecureAgent that wraps all tool calls with security checks
     */
    registerAgent(agentConfig: AgentConfig): SecureAgent {
        const agent = new SecureAgent(agentConfig, this._config);
        this._agents.set(agentConfig.agentId, agent);

        if (this._config.debug) {
            console.debug(
                `[AgentMesh] Agent registered: ${agentConfig.agentId} ` +
                `capabilities=${agentConfig.capabilities.join(",")}`
            );
        }

        return agent;
    }

    /**
     * Check if the AgentMesh server is reachable and healthy.
     *
     * @returns HealthResponse with server status
     * @throws  ServerConnectionError if the server is unreachable
     */
    async health(): Promise<HealthResponse> {
        const url = `${this._config.serverUrl}/health`;
        const timeoutMs = this._config.timeoutMs ?? DEFAULT_TIMEOUT_MS;

        let response: Response;
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
            response = await fetch(url, { signal: controller.signal });
            clearTimeout(timeoutId);
        } catch (err) {
            if (err instanceof Error && err.name === "AbortError") {
                throw new TimeoutError(timeoutMs);
            }
            throw new ServerConnectionError(
                `Cannot reach AgentMesh server at ${this._config.serverUrl}`,
                this._config.serverUrl ?? DEFAULT_SERVER_URL
            );
        }

        const data = await response.json() as {
            status: "ok";
            version: string;
            policy_loaded: boolean;
            registered_agents: string[];
        };

        return {
            status: data.status,
            version: data.version,
            policyLoaded: data.policy_loaded,
            registeredAgents: data.registered_agents,
        };
    }

    /** Return all registered agent IDs. */
    get registeredAgentIds(): string[] {
        return Array.from(this._agents.keys());
    }
}