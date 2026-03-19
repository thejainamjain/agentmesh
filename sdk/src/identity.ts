/**
 * AgentMesh Identity Client
 *
 * Verifies JWT tokens issued by the Python AgentIdentity layer
 * via the AgentMesh REST API.
 *
 * Security notes:
 *   - Tokens are sent over the wire to the local AgentMesh server only.
 *     The server URL defaults to localhost — never send tokens to external URLs.
 *   - Tokens are NEVER logged — only the agent_id on successful verification.
 *   - All three failure modes (expired, revoked, invalid) are typed errors.
 */

import {
    AgentContext,
    AgentMeshConfig,
    IdentityError,
    ServerConnectionError,
    TimeoutError,
    VerifyTokenResponse,
} from "./types.js";

const DEFAULT_SERVER_URL = "http://127.0.0.1:8000";
const DEFAULT_TIMEOUT_MS = 5000;

/**
 * Verify a JWT token with the AgentMesh server.
 *
 * @param token   JWT token string from AgentIdentity.issue_token()
 * @param config  AgentMesh client configuration
 * @returns       AgentContext if valid
 * @throws        IdentityError if the token is invalid, expired, or revoked
 * @throws        ServerConnectionError if the server is unreachable
 * @throws        TimeoutError if the request times out
 */
export async function verifyToken(
    token: string,
    config: AgentMeshConfig = {}
): Promise<AgentContext> {
    const serverUrl = config.serverUrl ?? DEFAULT_SERVER_URL;
    const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;

    const url = `${serverUrl}/v1/identity/verify`;
    const body = JSON.stringify({ token });

    let response: Response;
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        response = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body,
            signal: controller.signal,
        });

        clearTimeout(timeoutId);
    } catch (err) {
        if (err instanceof Error && err.name === "AbortError") {
            throw new TimeoutError(timeoutMs);
        }
        throw new ServerConnectionError(
            `Cannot reach AgentMesh server at ${serverUrl}. ` +
            `Start the server with: python -m agentmesh.api.server`,
            serverUrl
        );
    }

    if (!response.ok) {
        throw new ServerConnectionError(
            `AgentMesh server returned HTTP ${response.status}`,
            serverUrl
        );
    }

    const data = (await response.json()) as VerifyTokenResponse;

    if (!data.valid) {
        const code = data.error ?? "unknown_error";
        const messages: Record<string, string> = {
            token_expired: "Token has expired. Re-initialise the agent to get a new token.",
            token_revoked: "Token has been revoked. The agent has been shut down.",
            invalid_token: "Token is invalid or was not issued by a registered agent.",
            server_error: "AgentMesh server encountered an internal error during verification.",
        };
        throw new IdentityError(messages[code] ?? `Identity verification failed: ${code}`, code);
    }

    console.debug(`[AgentMesh] Identity verified: agent_id=${data.agent_id}`);

    return {
        agentId: data.agent_id!,
        meshId: data.mesh_id!,
        capabilities: data.capabilities ?? [],
    };
}