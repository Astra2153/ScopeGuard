# Architecture

## Components

| Component | File or area | Responsibility |
| --- | --- | --- |
| API | `backend/app/main.py` and routers | HTTP endpoints, security headers |
| Auth and sessions | `auth.py`, `sessions.py`, `mfa.py`, `security.py` | Argon2id, lockout, TOTP MFA, server-side sessions, CSRF |
| Access control | `access.py` | Role checks and the central ownership check |
| Rate limiting | `ratelimit.py` | Per-IP sliding window, 429 with Retry-After |
| Crypto | `crypto.py` | AES-256-GCM, keyed HMAC, Ed25519, subkey derivation |
| Audit | `audit.py` | Hash-chained append-only log with verification |
| Targets | `targets.py` | Registration and token-file ownership verification |
| SSRF guard | `ssrf.py` | URL parsing, address policy, pinned connection, request limits |
| Scan engine | `checks.py`, `scans.py` | Safe configuration checks, findings, retest logic |
| Authorization engine | `matrix.py`, `authz.py` | Two-identity object-level comparison with a control request |
| Reports | `reportgen.py`, `reports.py` | Escaped Markdown snapshots, Ed25519 signatures |
| Database | `models.py`, `migrations/` | SQLAlchemy models and Alembic migrations |

## Trust boundaries

1. Browser to API: the client is untrusted. Every request is authenticated, authorized and CSRF-checked.
2. API to database: only parameterized queries. The audit table refuses UPDATE, DELETE and TRUNCATE through triggers.
3. API to target: every outbound request goes through the SSRF guard. Target responses are untrusted data.
4. Target text to findings and reports: sanitised or escaped before it is stored or rendered.

## A scan request, step by step

1. The user is authenticated and CSRF-checked, and a role and ownership check runs.
2. The target must have been verified in the last 30 days. Otherwise the request fails with 409 and nothing is sent.
3. The URL is parsed again, the host is resolved once, and every address is checked against the blocked ranges.
4. The connection goes to the validated IP with the original Host header and SNI. Redirects are off, and size and time limits apply.
5. The checks produce findings with fixed text. They are stored with a fingerprint, so a re-scan does not duplicate them.
6. Audit events record IDs and counts only.

## Data model

users, sessions, backup_codes, engagements, targets, findings, reports, audit_log.

## Not built yet

React frontend, background worker queue, LLM drafter, Redis-backed rate limiting.
