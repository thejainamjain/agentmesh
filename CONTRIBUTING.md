# Contributing to AgentMesh

## Quick Setup

```bash
git clone https://github.com/thejainamjain/agentmesh
cd agentmesh

# Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Build the C++ interceptor
cd agentmesh/monitor/_ext && mkdir build && cd build
cmake .. && cmake --build . && cp interceptor_core*.so ../
cd ../../../..

# Run all tests
pytest tests/ -v --cov=agentmesh
```

---

## The Easiest First Contribution

Add a new injection pattern to `agentmesh/monitor/patterns/injection_patterns.yaml`.

Each pattern needs:
```yaml
- id: your_pattern_id
  pattern: "your\\s+regex\\s+here"
  severity: critical  # critical | high | medium | low
  category: instruction_override  # see existing categories
  description: What this pattern detects and why it matters.
  references: [OWASP-LLM01-2025]
```

Then add a red-team test to `tests/security/test_red_team.py` proving it's caught.

---

## Code Style

**Python:** Black + isort
```bash
black agentmesh/ tests/
isort agentmesh/ tests/
```

**TypeScript:** Prettier
```bash
cd sdk && npx prettier --write src/ tests/
```

---

## Pull Request Process

**Branch naming:**
```
feat/description    — new feature
fix/description     — bug fix
chore/description   — maintenance
security/description — security improvement
```

**Commit format (Conventional Commits):**
```
feat(identity): add token expiry refresh
fix(policy): rate limit window off by one
security(monitor): add new jailbreak pattern
```

**Before opening a PR:**
1. `pytest tests/ --cov=agentmesh` — must reach 85%+
2. `black agentmesh/ tests/` — no style failures
3. Add tests for any new code
4. Update CHANGELOG.md

**Review expectations:** PRs reviewed within 48 hours.

---

## Good First Issues

Look for issues labelled [`good first issue`](https://github.com/thejainamjain/agentmesh/labels/good%20first%20issue).

These are self-contained tasks designed to introduce you to the codebase:
- Add a new injection pattern
- Add a new policy example YAML
- Improve error messages
- Add a new framework integration adapter

---

## What Makes a Great Contribution

The best contributions are things that make AgentMesh more secure for everyone:
- New injection patterns from real-world attacks
- New framework integration adapters (AutoGPT, Semantic Kernel, Haystack)
- Policy templates for regulated industries
- Improved tamper detection

---

## Security Vulnerability Reporting

Do **not** open a public issue for security vulnerabilities.

Email: security@agentmesh.dev (placeholder — set up before launch)

We will respond within 48 hours and coordinate disclosure.