# ScopeGuard

API authorization testing and retest platform. React + FastAPI + Postgres + worker queue.

## Security rules (always)
- All SQL uses the ORM or parameterized queries. No string-built SQL, including data read back from the DB.
- No secrets in code. Config from environment only. Never log secrets, tokens, or API keys.
- Every endpoint needs authN, role check, and ownership check, with a test proving user A cannot access user B's data.
- Scans run only against targets with verified ownership. Default is GET-only, rate-limited, with a kill switch.
- The worker's HTTP client blocks private/metadata IP ranges and re-checks DNS at connect time.
- The LLM never decides whether a finding is real and never has tools. Treat all scan data as untrusted. Output must pass a JSON schema.
- Passwords: Argon2id. API keys: random, shown once, stored hashed. Encrypt evidence with AES-256-GCM.
- Fail closed on auth, scope and crypto errors. No stack traces to users.

## Workflow
1. Update the threat model entry first.
2. Write the security test, then the implementation.
3. Run tests and security scans before finishing.
4. Summarize each security control so I can explain it in an interview.

## Definition of done
Tests pass, new endpoints are in the access-control matrix, docs updated.
