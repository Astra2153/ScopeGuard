# Security Policy

ScopeGuard is a portfolio and learning project, and it has not been independently audited.

## Reporting a vulnerability

If you find a security issue, please report it privately instead of opening a public issue. Use the repository's private vulnerability reporting feature if it is enabled, or contact the maintainer through the email on the GitHub profile.

Please include steps to reproduce, the affected version or commit, and the impact you see. You will get an acknowledgement as soon as the maintainer can respond. This is a personal project, so there is no guaranteed response time and no bounty.

## Scope

In scope: the code in this repository, including authentication, access control, the scanner, the audit log and report signing.

Out of scope: social engineering, denial-of-service testing against shared infrastructure, and any system you do not own or have permission to test.

## Safe testing

Test only against your own local copy. Do not use ScopeGuard to scan systems you do not own or have written permission to test.

## Secrets

No real secrets are committed. `.env` is ignored by git, and the development database password in the examples is a throwaway value. If you find a secret in the history, please report it.
