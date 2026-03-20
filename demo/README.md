# AgentMesh Live Demo

Shows 5 real multi-agent attacks — side by side, with and without AgentMesh.

## Run in 2 commands

```bash
pip install agentmesh rich
python demo/run_demo.py
```

## What you'll see

```
Normal Operation ──────────────────────────────────────────────
  WITHOUT AgentMesh          |  WITH AgentMesh
  ✅ web_search — allowed    |  ✅ web_search — Identity ✓ Policy ✓ Clean ✓
  ✅ write_summary — allowed |  ✅ write_summary — Identity ✓ Policy ✓ Audit ✓

⚡ ATTACK: Prompt Injection via Poisoned Web Search ────────────
  WITHOUT AgentMesh          |  WITH AgentMesh
  ✅ web_search — allowed    |  🛡️ web_search — BLOCKED (1.2ms)
  💀 Injection reached LLM   |  ✅ Caught before LLM sees it

⚡ ATTACK: Privilege Escalation ────────────────────────────────
  ✅ write_file — allowed    |  🛡️ write_file — BLOCKED (0.8ms)
  💀 Attacker planted cron   |  ✅ denied_tools enforcement
...
```

## Individual attacks

```bash
python demo/run_demo.py --attack injection     # Poisoned web search
python demo/run_demo.py --attack escalation    # Researcher → write_file
python demo/run_demo.py --attack shell         # execute_shell injection
python demo/run_demo.py --attack exfiltration  # send_email data theft
python demo/run_demo.py --attack impersonation # Rogue agent identity
```

## Attacks demonstrated

| Attack | OWASP | Without AgentMesh | With AgentMesh |
|---|---|---|---|
| Prompt injection | T3 | LLM hijacked | Blocked by injection detector |
| Privilege escalation | T2 | write_file executes | Blocked by policy (denied_tools) |
| Shell injection | T2+CWE-78 | Shell executes | Blocked by policy (denied_tools) |
| Data exfiltration | T3 | Email sent | Blocked by policy (denied_tools) |
| Agent impersonation | T1 | Rogue accepted | Ed25519 mismatch rejected |

## Output

After running, check `demo/output/`:
- `audit.jsonl` — tamper-evident audit log (SHA-256 hash-chained)
- `summary.md` — output from the clean pipeline run
