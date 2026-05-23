# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub's vulnerability reporting:
https://github.com/holeyfield33-art/aletheia-sentinel/security/advisories/new

We will acknowledge confirmed reports within 14 days.

## Scope

Aletheia Sentinel is research software submitted to the SANS FIND EVIL! AI hackathon
(June 2026). It is not intended for production deployment against live evidence without
additional hardening. Issues that depend on production-grade controls (enterprise IAM,
zero-trust networking, FIPS-validated cryptography) are out of scope for the hackathon
submission timeline.

In-scope concerns include:

- Audit chain tamper detection bypasses
- Tool surface escape (executing operations outside the typed wrappers)
- Receipt forgery or signature stripping
- Spectral gate evasion (causing STRESSED reasoning to register HEALTHY)
- Prompt-injection that escalates beyond the architectural constraints

## Acknowledgments

Responsible reporters will be credited in release notes unless anonymity is preferred.
