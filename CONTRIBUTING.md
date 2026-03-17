# Contributing to AgentMesh

First off — thank you for considering a contribution. AgentMesh is an open-source security project and the quality of contributions directly affects how well it protects real systems. We take that seriously, and we hope you will too.

This document tells you everything you need to know to go from zero to a merged PR.

---

## Table of Contents

1. [Before you start](#1-before-you-start)
2. [Setting up your dev environment](#2-setting-up-your-dev-environment)
3. [How the codebase is organized](#3-how-the-codebase-is-organized)
4. [Finding something to work on](#4-finding-something-to-work-on)
5. [Making a contribution](#5-making-a-contribution)
6. [Code standards](#6-code-standards)
7. [Testing requirements](#7-testing-requirements)
8. [Commit message format](#8-commit-message-format)
9. [Pull request process](#9-pull-request-process)
10. [Reporting security vulnerabilities](#10-reporting-security-vulnerabilities)
11. [Code of conduct](#11-code-of-conduct)

---

## 1. Before you start

**Read these two documents first.** They are short and will save you a lot of time:

- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — how the system is designed and why
- [`docs/security/THREAT_MODEL.md`](./docs/security/THREAT_MODEL.md) — what attacks AgentMesh protects against

If you are contributing to a security-sensitive component (identity, policy engine, behavior monitor, audit trail), you must read the relevant section of ARCHITECTURE.md before writing any code. Security components have specific invariants — for example, the policy engine must always default-deny, and this must never be made configurable. These invariants are documented and PRs that violate them will not be merged regardless of code quality.

---

## 2. Setting up your dev environment

**Requirements:**
- Python 3.10+
- Node.js 18+
- C++ compiler (GCC 11+ or Clang 14+) — required for the C++ interceptor
- pybind11
- make

**One-command setup:**

```bash
git clone https://github.com/yourusername/agentmesh.git
cd agentmesh
make dev
```

`make dev` does the following:
- Creates a Python virtual environment in `.venv/`
- Installs all Python dependencies including dev dependencies
- Builds the C++ extension
- Installs the JS SDK dependencies
- Runs the test suite once to verify everything works

**Verify your setup:**

```bash
make test       # run full test suite
make lint       # run Black + mypy + ESLint
make benchmark  # run performance benchmarks
```

If `make test` passes and `make lint` shows no errors, you are ready to contribute.

**Common setup issues:**

| Problem | Fix |
|---|---|
| `pybind11 not found` | `pip install pybind11` then `make dev` again |
| `C++ compiler not found` | Install build-essential (Ubuntu) or Xcode CLI tools (macOS) |
| `mypy errors on clean checkout` | Run `make stubs` to generate type stubs for the C++ extension |
| JS tests fail on clean checkout | Run `cd sdk && npm install` manually |

---

## 3. How the codebase is organized

```
agentmesh/          Python core library
  identity/         Layer 1 — JWT issuance and verification
  policy/           Layer 2a — YAML policy engine
  monitor/          Layer 2b — Injection and anomaly detection
    patterns/       Injection pattern YAML files (community-contributed)
  audit/            Layer 3 — Tamper-evident audit trail
  decorators.py     Public API — @secure_agent, @secure_tool

sdk/                TypeScript SDK (@agentmesh/client)
dashboard/          Next.js real-time dashboard
integrations/       Framework adapters (LangChain, CrewAI)
examples/           Working code examples — must always run
tests/
  unit/             Fast, no external deps
  integration/      Requires Docker Compose
  security/         Red-team style injection tests
docs/security/      Threat model and security policy
```

The most common contribution areas for first-time contributors are:

- `agentmesh/monitor/patterns/` — adding injection detection patterns (no C++ required)
- `integrations/` — adding a new framework adapter (Python only)
- `examples/` — adding a new working example
- `dashboard/` — Next.js UI improvements

---

## 4. Finding something to work on

### Good first issues

Issues labeled [`good first issue`](https://github.com/yourusername/agentmesh/labels/good%20first%20issue) are specifically chosen for new contributors. They are:

- Self-contained — you will not need to understand the whole codebase
- Well-specified — the acceptance criteria tell you exactly what done looks like
- Reviewed quickly — we aim to review good first issue PRs within 48 hours

**The best good first issue to start with:** adding a new prompt injection detection pattern to `agentmesh/monitor/patterns/injection_patterns.yaml`. It requires reading the existing patterns, writing a new one in YAML, and adding a test case. No C++ knowledge needed.

### Contribution types we actively want

| Type | Description | Skill required |
|---|---|---|
| Injection patterns | Add new patterns to the detection library | YAML, security knowledge |
| Framework integrations | Add support for AutoGPT, Semantic Kernel, Haystack | Python |
| Policy templates | Community YAML configs for common use cases | YAML |
| Storage backends | New audit trail backends (e.g. MongoDB, DynamoDB) | Python |
| Language SDKs | Go SDK, Rust SDK, Java SDK | Go / Rust / Java |
| Dashboard features | New charts, views, filters | TypeScript, Next.js |
| Documentation | Guides, examples, API docs | Writing |

### Before starting work on a large change

If you want to add a significant new feature — a new detection method, a new layer, a new SDK — please **open an issue first** and describe what you want to build. This saves you from spending days on something that duplicates existing work or conflicts with the roadmap.

For small changes (bug fixes, new injection patterns, documentation), just open a PR directly.

---

## 5. Making a contribution

```bash
# 1. Fork the repo on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/agentmesh.git
cd agentmesh

# 2. Create a branch — name it after the issue number and a short description
git checkout -b 42-add-role-hijack-patterns

# 3. Make your changes

# 4. Run tests and lint before committing
make test
make lint

# 5. Commit with a conventional commit message (see Section 8)
git commit -m "feat(monitor): add role hijack injection patterns"

# 6. Push and open a PR against main
git push origin 42-add-role-hijack-patterns
```

**Branch naming:**
```
{issue-number}-{short-description-with-hyphens}

Examples:
  42-add-role-hijack-patterns
  17-fix-jwt-expiry-check
  88-postgres-audit-backend
```

---

## 6. Code standards

### Python

- Formatter: **Black** — run `black .` before committing. No exceptions.
- Type checker: **mypy** — all new code must be fully typed. `mypy agentmesh/` must pass with no errors.
- Linter: **pylint** — score must stay above 8.5/10.
- Docstrings: all public functions and classes require a one-line docstring minimum.
- No `# type: ignore` comments without an explanation in the same comment.

```python
# Good
def verify(token: str) -> AgentContext:
    """Verify a JWT token and return the agent context."""
    ...

# Bad — no type hints, no docstring
def verify(token):
    ...
```

### TypeScript (SDK and dashboard)

- Formatter: **Prettier** — run `npm run format` before committing.
- Type checker: **TypeScript strict mode** — `tsc --noEmit` must pass.
- No `any` types without a comment explaining why.
- All exported functions must have JSDoc comments.

### C++ (interceptor)

- Follow the Google C++ Style Guide.
- All public functions must have doxygen comments.
- No raw pointers — use smart pointers (`std::unique_ptr`, `std::shared_ptr`).
- No exceptions across the Python/C++ boundary — convert to Python exceptions in the pybind11 binding layer.

### General rules

- No print statements or console.log in production code — use the logger.
- No hardcoded secrets, API keys, or credentials anywhere in the codebase.
- No commented-out code in PRs — delete it or open a separate issue.

---

## 7. Testing requirements

Every PR must maintain or improve coverage. PRs that drop coverage below the target will not be merged.

| Component | Coverage target | Test command |
|---|---|---|
| `agentmesh/identity/` | 90%+ | `pytest tests/unit/test_identity.py -v` |
| `agentmesh/policy/` | 90%+ | `pytest tests/unit/test_policy.py -v` |
| `agentmesh/monitor/` | 85%+ | `pytest tests/unit/test_monitor.py -v` |
| `agentmesh/audit/` | 90%+ | `pytest tests/unit/test_audit.py -v` |
| TypeScript SDK | 80%+ | `cd sdk && npm test` |
| Full suite | 85%+ overall | `make test` |

**For security-sensitive PRs** (anything touching identity, policy, monitor, or audit), you must also add at least one adversarial test case — a test that verifies the system correctly handles a malicious or malformed input.

**Integration tests** run with Docker Compose. They are not required for every PR but are required for PRs that touch the interceptor, policy engine, or audit trail storage backends:

```bash
make test-integration  # requires Docker
```

---

## 8. Commit message format

We use [Conventional Commits](https://www.conventionalcommits.org/). This is required — it drives our automated changelog generation.

```
<type>(<scope>): <short description>

[optional body]

[optional footer: Closes #issue-number]
```

**Types:**

| Type | When to use |
|---|---|
| `feat` | A new feature |
| `fix` | A bug fix |
| `security` | A security fix — use this instead of fix for security issues |
| `perf` | A performance improvement |
| `test` | Adding or fixing tests |
| `docs` | Documentation only |
| `refactor` | Code change that is not a fix or feature |
| `chore` | Build system, CI, dependencies |

**Scopes:** `identity`, `policy`, `monitor`, `audit`, `sdk`, `dashboard`, `integrations`, `ci`, `docs`

**Examples:**

```
feat(monitor): add base64-encoded injection pattern detection

Attackers sometimes encode injection payloads in base64 to bypass
pattern matching. This adds a decode-and-scan step for arguments
that are valid base64 strings.

Closes #54
```

```
security(identity): fix JWT expiry not checked on cached tokens

Cached tokens were not having their expiry re-validated after
the initial verification. An expired token in the cache would
continue to be accepted.

Closes #61
```

```
fix(policy): default-deny when rule file has syntax error

Previously a YAML syntax error caused the engine to fall through
to allow-all behavior. Now raises PolicyParseError and halts.
```

---

## 9. Pull request process

### Before opening a PR

- [ ] `make test` passes with no failures
- [ ] `make lint` passes with no errors
- [ ] Coverage has not dropped below the target for any component you touched
- [ ] `CHANGELOG.md` updated with your change under `[Unreleased]`
- [ ] If you added a new public API, it is documented in the relevant section of `ARCHITECTURE.md`

### PR description

Use this template when opening a PR:

```markdown
## What this PR does
[One paragraph describing the change]

## Why
[Link to the issue this closes, or explain the motivation]

## How to test
[Steps to verify the change manually, beyond the automated tests]

## Security considerations
[Does this change affect any security-sensitive component? If yes, explain the security implications and how they were addressed]

## Checklist
- [ ] Tests added or updated
- [ ] Coverage maintained or improved
- [ ] CHANGELOG.md updated
- [ ] ARCHITECTURE.md updated (if API changed)
```

### Review process

- All PRs require at least one approval before merging.
- PRs touching security-sensitive components (`identity/`, `policy/`, `monitor/`, `audit/`) require maintainer review — not just any contributor.
- We aim to give first feedback within **48 hours** for `good first issue` PRs and **72 hours** for other PRs.
- Address review comments with new commits — do not force-push during review, it makes the diff hard to follow.
- Once approved, the maintainer will squash-merge your PR.

### What causes a PR to be rejected

- Drops test coverage below the target
- Violates the default-deny invariant in the policy engine
- Adds a `# type: ignore` without explanation
- Contains hardcoded credentials or secrets
- Breaks existing tests without a clear justification
- Changes the audit entry schema (frozen from v0.1 — see ARCHITECTURE.md §13)

---

## 10. Reporting security vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

If you find a security vulnerability in AgentMesh, please report it privately via the process described in [`docs/security/SECURITY_POLICY.md`](./docs/security/SECURITY_POLICY.md).

We will acknowledge your report within 48 hours and aim to have a fix published within 14 days for critical issues.

---

## 11. Code of conduct

AgentMesh follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). In short: be respectful, be constructive, assume good faith. Security research and adversarial thinking are welcome — personal attacks are not.

---

*Thank you for contributing to AgentMesh. Every injection pattern you add, every test you write, and every framework adapter you build makes multi-agent AI systems safer for everyone building on them.*