# Contributing to AgentMesh

---

## Quick Setup

```bash
git clone https://github.com/thejainamjain/agentmesh
cd agentmesh

# Python environment
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v --cov=agentmesh

# JS SDK tests
cd sdk && npm install && npm test
```

---

## The Easiest Contribution: Fix a Detection Gap

[`tests/security/test_known_gaps.py`](tests/security/test_known_gaps.py) documents 12 bypass techniques that AgentMesh v0.1.0 does not catch. Each is an `xfail` test with the exact fix described in the `reason` string.

**Example — fixing GAP-003 (zero-width characters):**

In `agentmesh/monitor/injection_detector.py`, in the `_normalise_text` method, add:
```python
import re
# Strip zero-width characters before pattern matching
text = re.sub(r'[\u200b\u200c\u200d\ufeff\u00ad]', '', text)
```

Then in `tests/security/test_known_gaps.py`, change the test from:
```python
@pytest.mark.xfail(reason="GAP-003: ...")
def test_gap_003_zero_width_space(detector):
```
to a normal passing test:
```python
def test_gap_003_zero_width_space(detector):
```

That's a complete PR. Reference `Fixes GAP-003` in your commit message.

---

## Add a New Injection Pattern

The pattern library at `agentmesh/monitor/patterns/injection_patterns.yaml` is community-contributed. Each pattern needs:

```yaml
- id: your_pattern_id
  pattern: "your\\s+regex\\s+here"
  severity: critical     # critical | high | medium | low
  category: instruction_override   # see existing categories
  description: What this detects and why it's dangerous.
  references: [OWASP-LLM01-2025]
```

Then add a red-team test in `tests/security/test_red_team.py`:
```python
def test_your_new_pattern(detector):
    assert_blocked(detector, "your attack payload here", "your_pattern_id")
```

Run `pytest tests/security/test_red_team.py -v` to verify.

---

## Code Style

**Python:** Black + isort
```bash
black agentmesh/ tests/ integrations/
isort agentmesh/ tests/ integrations/
```

**TypeScript:** Prettier
```bash
cd sdk && npx prettier --write src/ tests/
cd dashboard && npx prettier --write src/
```

---

## Pull Request Process

**Branch naming:**
```
feat/description        new feature
fix/description         bug fix
security/description    security improvement (pattern, gap fix)
chore/description       maintenance, deps
docs/description        documentation only
```

**Commit format (Conventional Commits):**
```
feat(monitor): add Unicode NFKC normalisation — fixes GAP-001
fix(langchain): bind self in closure before interceptor serialises args
security(patterns): add French instruction override variants — fixes GAP-004
```

**Before opening a PR:**
1. `pytest tests/ --cov=agentmesh --cov-fail-under=85` — must pass
2. `black agentmesh/ tests/` — no style failures
3. New code has tests
4. If fixing a gap: change the `xfail` test to a normal passing test
5. Update `CHANGELOG.md` under `[Unreleased]`

---

## What Makes a Great Contribution

Best contributions in priority order:

1. **Fix a documented gap** — see `test_known_gaps.py`. Each has exact instructions.
2. **Add a new injection pattern** — real attack payloads from OWASP, CVEs, or research
3. **Framework adapters** — CrewAI, AutoGPT, Semantic Kernel (see `integrations/langchain/` as reference)
4. **Audit backends** — PostgreSQL, S3 implementing the `AuditBackend` interface
5. **Policy templates** — YAML examples for specific industries (HIPAA, fintech, etc.)

