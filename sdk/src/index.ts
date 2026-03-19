/**
 * @agentmesh/client — JavaScript/TypeScript SDK
 *
 * Runtime trust and security layer for multi-agent AI systems.
 *
 * @example
 * ```typescript
 * import { AgentMesh } from '@agentmesh/client';
 *
 * const mesh = new AgentMesh({ serverUrl: 'http://127.0.0.1:8000' });
 *
 * const agent = mesh.registerAgent({
 *   agentId: 'researcher',
 *   capabilities: ['web_search'],
 *   token: '<jwt from python AgentIdentity.issue_token()>',
 * });
 *
 * const result = await agent.callTool(
 *   'web_search',
 *   { query: 'AI security 2026' },
 *   async (args) => {
 *     // your actual tool implementation
 *     return await myWebSearchFunction(args.query);
 *   }
 * );
 * ```
 */

export { AgentMesh, SecureAgent } from "./client.js";
export { verifyToken } from "./identity.js";
export {
    AgentMeshError,
    IdentityError,
    PolicyDeniedError,
    ServerConnectionError,
    TimeoutError,
} from "./types.js";
export type {
    AgentConfig,
    AgentContext,
    AgentMeshConfig,
    HealthResponse,
    PolicyDecision,
    PolicyDecisionType,
    ToolArguments,
    ToolFunction,
    ToolResult,
    VerifyTokenResponse,
} from "./types.js";