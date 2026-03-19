/**
 * AgentMesh TypeScript SDK — Shared Types
 *
 * All types used across the SDK. No `any` types in the public API.
 * These types mirror the Python dataclasses in the AgentMesh core.
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Configuration for the AgentMesh client. */
export interface AgentMeshConfig {
    /**
     * Base URL of the AgentMesh REST API server.
     * Default: http://127.0.0.1:8000
     */
    serverUrl?: string;

    /**
     * Request timeout in milliseconds.
     * Default: 5000 (5 seconds)
     */
    timeoutMs?: number;

    /**
     * Whether to log debug information.
     * Default: false
     */
    debug?: boolean;
}

/** Configuration for registering an agent. */
export interface AgentConfig {
    /** Unique identifier for this agent. */
    agentId: string;

    /** List of tool names this agent is permitted to call. */
    capabilities: string[];

    /** JWT token issued by the Python AgentIdentity layer. */
    token: string;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/** The verified context of an agent, returned after successful JWT verification. */
export interface AgentContext {
    agentId: string;
    meshId: string;
    capabilities: string[];
}

/** Response from the /v1/identity/verify endpoint. */
export interface VerifyTokenResponse {
    valid: boolean;
    agent_id?: string;
    mesh_id?: string;
    capabilities?: string[];
    error?: string;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/** The three possible policy decisions. */
export type PolicyDecisionType = "allow" | "deny" | "rate_limited";

/** Response from the /v1/policy/evaluate endpoint. */
export interface PolicyDecision {
    decision: PolicyDecisionType;
    reason: string;
    agentId: string;
    toolName: string;
}

// ---------------------------------------------------------------------------
// Tool calls
// ---------------------------------------------------------------------------

/** Arguments passed to a tool call. Any JSON-serialisable value. */
export type ToolArguments = Record<string, unknown>;

/** Result returned by a tool call. Any JSON-serialisable value. */
export type ToolResult = unknown;

/** A tool function that can be intercepted by AgentMesh. */
export type ToolFunction<TArgs extends ToolArguments, TResult extends ToolResult> = (
    args: TArgs
) => Promise<TResult>;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Base error class for all AgentMesh SDK errors. */
export class AgentMeshError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "AgentMeshError";
    }
}

/** Thrown when identity verification fails. */
export class IdentityError extends AgentMeshError {
    constructor(
        message: string,
        public readonly code: string
    ) {
        super(message);
        this.name = "IdentityError";
    }
}

/** Thrown when the policy engine denies a tool call. */
export class PolicyDeniedError extends AgentMeshError {
    constructor(
        message: string,
        public readonly reason: string,
        public readonly decision: PolicyDecisionType
    ) {
        super(message);
        this.name = "PolicyDeniedError";
    }
}

/** Thrown when the AgentMesh server cannot be reached. */
export class ServerConnectionError extends AgentMeshError {
    constructor(message: string, public readonly serverUrl: string) {
        super(message);
        this.name = "ServerConnectionError";
    }
}

/** Thrown when a request to the server times out. */
export class TimeoutError extends AgentMeshError {
    constructor(public readonly timeoutMs: number) {
        super(`Request timed out after ${timeoutMs}ms`);
        this.name = "TimeoutError";
    }
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

/** Response from GET /health */
export interface HealthResponse {
    status: "ok";
    version: string;
    policyLoaded: boolean;
    registeredAgents: string[];
}