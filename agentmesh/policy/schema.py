from __future__ import annotations

import jsonschema

from agentmesh.policy.exceptions import PolicyValidationError

# ---------------------------------------------------------------------------
# JSON Schema for the AgentMesh policy YAML format
#
# Every field is strictly typed. `additionalProperties: false` ensures
# unknown fields are rejected — a typo like `allwed_tools` fails loudly
# instead of silently granting no permissions.
# ---------------------------------------------------------------------------

POLICY_SCHEMA: dict = {
    "type": "object",
    "required": ["version", "agents"],
    "additionalProperties": False,
    "properties": {
        "version": {
            "type": "string",
            "description": "Policy schema version. Must be '1.0'.",
            "enum": ["1.0"],
        },
        "defaults": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "deny_on_missing_rule": {
                    "type": "boolean",
                    "description": "Block calls with no matching rule. Always true — cannot be set to false.",
                },
                "deny_on_engine_error": {
                    "type": "boolean",
                    "description": "Block all calls if the policy engine errors. Always true.",
                },
                "log_all_denials": {
                    "type": "boolean",
                    "description": "Write every denial to the audit trail.",
                },
            },
        },
        "agents": {
            "type": "object",
            "description": "Map of agent_id to its policy rules.",
            "minProperties": 1,
            "additionalProperties": {
                "$ref": "#/$defs/agent_policy",
            },
        },
    },
    "$defs": {
        "agent_policy": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "allowed_tools": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                    "description": "Tools this agent is permitted to call. Empty = no tools allowed.",
                },
                "denied_tools": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                    "description": "Explicit deny list — checked before allowed_tools. Belt and suspenders.",
                },
                "allowed_callers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                    "description": "Agent IDs permitted to call this agent. Empty = top-level only (no callers).",
                },
                "can_delegate_to": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                    "description": "Agent IDs this agent is permitted to delegate to.",
                },
                "rate_limits": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "string",
                        "pattern": r"^\d+/(second|minute|hour)$",
                        "description": "Rate limit string, e.g. '10/minute', '100/hour'.",
                    },
                    "description": "Per-tool rate limits for this agent.",
                },
            },
        },
    },
}


def validate_policy(policy_dict: dict) -> None:
    """
    Validate a parsed policy dict against the strict JSON Schema.

    Raises:
        PolicyValidationError: If the policy fails validation, with a
            human-readable message describing exactly what is wrong.

    Security note: validation is performed before the policy is accepted
    by the engine. A policy that fails validation is treated as no policy —
    all calls are denied until a valid policy is loaded.
    """
    try:
        jsonschema.validate(instance=policy_dict, schema=POLICY_SCHEMA)
    except jsonschema.ValidationError as e:
        # Build a clean, actionable error message
        path = " → ".join(str(p) for p in e.absolute_path) if e.absolute_path else "root"
        raise PolicyValidationError(
            f"Policy validation failed at '{path}': {e.message}\n"
            f"Hint: check your policy YAML against the schema in agentmesh/policy/schema.py"
        ) from e
    except jsonschema.SchemaError as e:
        # This would be a bug in our schema — should never happen in production
        raise PolicyValidationError(
            f"Internal schema error (this is a bug, please report it): {e.message}"
        ) from e

    # Extra security check: deny_on_missing_rule and deny_on_engine_error
    # can never be set to False. These are non-negotiable security invariants.
    defaults = policy_dict.get("defaults", {})
    if defaults.get("deny_on_missing_rule") is False:
        raise PolicyValidationError(
            "Security violation: 'deny_on_missing_rule' cannot be set to false. "
            "AgentMesh always denies calls with no matching rule."
        )
    if defaults.get("deny_on_engine_error") is False:
        raise PolicyValidationError(
            "Security violation: 'deny_on_engine_error' cannot be set to false. "
            "AgentMesh always denies calls when the policy engine errors."
        )