# ScopeGuard Threat Model (v0.1)

Scope: ScopeGuard is a platform where testers register authorized API targets, run safe authorization checks, record findings, retest after fixes and export reports. Stack: React frontend, FastAPI API, Postgres, job queue, isolated scan worker, optional local LLM drafter (Ollama).

## 1. Assets

| Asset | Why it matters |
| --- | --- |
| User credentials, MFA secrets, sessions | Account takeover gives access to client findings |
| Findings and evidence | Contain vulnerability details and sometimes sensitive client data |
| Target configs and test-account credentials | Used to log in to client APIs during checks |
| API keys and tokens issued by ScopeGuard | Allow programmatic access |
| Signing and encryption keys | Protect report integrity and evidence confidentiality |
| Audit log | Proof of who did what and when |
| Worker network position | Can reach the internet and must not reach internal systems |

## 2. Trust boundaries

1. Browser to API (untrusted client)
2. API to database (API trusted, data inside is not)
3. API to job queue to worker (worker runs untrusted network input)
4. Worker to target API (target responses are untrusted data)
5. API to LLM drafter (all prompt content is untrusted)
6. API to evidence storage (uploaded files are untrusted)

## 3. Threats and mitigations (STRIDE)

### Auth
| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Spoofing: credential stuffing, brute force | Argon2id, per-IP and per-account rate limits, lockout, TOTP MFA | Phished MFA codes |
| Spoofing: account enumeration | Generic login and reset errors, constant-ish timing | Timing side channels |
| Spoofing: session fixation or theft | New session ID at login, Secure/HttpOnly/SameSite cookies, short expiry | XSS on a future page |
| Tampering: password reset abuse | Single-use, expiring, hashed reset tokens | Email account compromise |

### API
| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Elevation: IDOR and broken access control | RBAC plus ownership check on every endpoint, automated access-control matrix tests | New endpoint added without a test |
| Tampering: SQL injection, including second-order | ORM and parameterized queries only, tests that store payloads and read them back | Raw SQL added later |
| Info disclosure: verbose errors | Generic errors, no stack traces, structured server-side logs | Misconfigured debug mode |
| DoS: request floods, huge payloads | Rate limits, payload size limits, timeouts | Distributed floods |
| CSRF and XSS | SameSite and CSRF tokens, output encoding, strict CSP | Third-party script supply chain |
| Info disclosure: leaked API keys | Keys random, shown once, stored hashed, redacted in logs | User stores key insecurely |

### Worker (SSRF and abuse)
| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Elevation: SSRF to internal or cloud metadata addresses | Verified-target allow-list, block private and link-local ranges, re-resolve DNS at connect time, limit redirects | DNS rebinding edge cases |
| Abuse: scanning systems the user does not own | Ownership verification (DNS TXT or token file) before any scan, GET-only default, kill switch, audit log | Ownership proof can be stale |
| DoS against target | Rate limit per target, concurrency cap, timeouts | Target is fragile |
| Tampering: worker compromised by hostile response | Parse responses as data only, size limits, run worker as low-privilege isolated container | Parser bug |

### Database
| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Info disclosure: cross-tenant data access | Ownership checks plus Postgres row-level security as second layer | RLS policy mistakes |
| Info disclosure: stolen backup or disk | Sensitive fields encrypted at rest (AES-256-GCM), least-privilege DB roles | Key compromise |
| Tampering: privileged DB account misuse | Separate roles: app role cannot alter audit log or schema | Superuser access |

### LLM drafter (prompt injection)
| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Tampering: prompt injection in scan output or target text | Treat all input as data, separate from instructions, no tools, JSON-schema validated output, human approves | Misleading draft text |
| Info disclosure: leaking system prompt or other users' data | Never put secrets or other tenants' data in prompts, canary tokens, output filtering | Novel attacks |
| Repudiation: AI text presented as fact | LLM never decides finding status; drafts are labelled and editable | Over-trust by users |
| NL-to-SQL abuse | Read-only DB role, allow-listed views, query parsing, row limits, timeouts | Parser gaps |

### File and evidence storage
| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Tampering: malicious upload | Size and content-type checks, random filenames, stored outside web root, never executed | Parser bugs in viewers |
| Info disclosure: evidence exposure | Per-engagement encryption keys (envelope encryption), access checks, signed short-lived download links | Key management errors |
| Repudiation: edited reports | Ed25519-signed reports, signature verified on download | Signing key theft |

### Audit log
| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Repudiation: user denies an action | Append-only log of logins, scope changes, scans, exports | Logging gaps |
| Tampering: log edited or deleted | Hash-chained entries, app role has insert-only rights, chain verification job | Attacker with DB superuser |

## 4. Security design rules

1. Fail closed on authentication, scope and crypto errors.
2. No secrets in code or logs.
3. Every endpoint has a test proving user A cannot access user B's data.
4. Scans run only on verified targets.
5. The LLM never decides what is true.

## 5. Open questions

1. Session cookies or JWT access tokens for the browser?
2. How is target ownership proven: DNS TXT, a token file, or both?
3. Where do envelope-encryption master keys live in development and in production?
4. Is multi-tenant isolation needed in v1, or single organization first?
5. Which checks are allowed beyond GET, and who approves them?
6. How are test-account credentials for targets stored and rotated?
