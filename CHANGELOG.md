# Changelog

All notable changes to AgentMesh are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-03-20

### Added
- `AgentIdentity` — Ed25519 keypair generation, JWT issuance, revocation
- `CredentialStore` — in-memory public key registry
- `@intercept_tools` decorator — wraps any tool function with security checks
- C++ pybind11 extension for hot-path interception (< 5ms overhead)
- `PolicyEngine` — YAML policy loader, default-deny evaluator, rate limiting
- `InjectionDetector` — 33 patterns, 9 OWASP 2025 attack categories
- `AnomalyDetector` — Z-score based statistical anomaly detection
- `AuditTrail` — SHA-256 hash chain, Ed25519 signed, tamper-evident
- `LocalJsonlBackend` — append-only JSONL audit storage
- FastAPI REST server (`agentmesh.api.server`)
- WebSocket endpoint for real-time audit streaming
- TypeScript SDK (`@agentmesh/client`)
- Next.js dashboard with real-time WebSocket feed
- 289 Python tests, 88%+ coverage
- 29 Jest tests for the TypeScript SDK

### Security
- Default-deny policy: no matching rule = blocked
- Fail-secure: any component failure = blocked (never allowed)
- Arguments never stored in audit log — only SHA-256 hash
- WebSocket auth via shared secret from environment (never URL)
- Security headers on dashboard (CSP, X-Frame-Options, etc.)