# Feature Landscape: CI/CD API Security Scanning

**Domain:** CI/CD-integrated API security scanning (GitHub Actions delivery)
**Researched:** 2026-04-04

## What Already Exists in Secoraa (Do Not Rebuild)

The scanner core is feature-complete for the hard parts:

- OpenAPI and Postman spec parsing
- 11 per-endpoint OWASP test categories (Auth, BOLA, SQLi, NoSQLi, CMDi, SSRF, SSTI, XXE, Mass Assignment, BFLA, Info Disclosure)
- 5 global checks (Headers, CORS, Rate limiting, Admin path discovery, Version discovery)
- JWT analysis, OOB blind vulnerability detection
- CVSS scoring per finding, severity classification
- OWASP API Top 10 2023 coverage mapping
- Structured report dict output

The CI/CD milestone is entirely about **delivery surface and integration plumbing**, not scanner capability.

---

## Table Stakes

| Feature | Why Expected | Complexity |
|---------|--------------|------------|
| GitHub Action accepting spec file path | Non-negotiable entry point | Low |
| `target-url` input (base URL to scan) | Scanner needs a live target | Low |
| SARIF 2.1.0 output | GitHub Security tab, code scanning alerts, PR annotations all depend on it | Medium |
| Exit code = 1 on HIGH/CRITICAL findings | Required for PR merge blocking via branch protection | Low |
| Configurable severity threshold | Teams differ — startups allow HIGH, enterprises block on MEDIUM | Low |
| PR comment with findings summary | Primary dev UX — findings in-context | Medium |
| Auth configuration input | Virtually every real API requires auth | Low |
| Docker image packaging | GitHub Actions `uses: docker://` syntax requires published image | Medium |
| API key input for optional callback | CI/CD standard for platform auth | Low |
| Minimal working example in README | Developers skip tools with poor docs | Low |

## Differentiators

| Feature | Value Proposition | Complexity |
|---------|-------------------|------------|
| Blind OOB vulnerability detection in CI | Most CI scanners don't run OOB infrastructure | Medium |
| OWASP coverage map in PR comment | Shows which categories tested vs. findings | Low |
| Dual-token privilege escalation testing | Rare in CI tools — BOLA/BFLA with two user tokens | Medium |
| Platform scan history for CI scans | Centralized history across repos — opt-in callback | Low |
| Scan source tagging (manual vs ci-cd) | Distinguish CI scans from manual runs | Low |
| Branch/commit metadata in findings | Traceability back to exact code scanned | Low |
| Postman collection support | Many teams don't have OpenAPI specs | Low |
| CVSS score per finding in PR comment | More signal than severity labels alone | Low |

## Anti-Features (Do Not Build)

| Anti-Feature | Why Avoid |
|--------------|-----------|
| GitLab CI / Bitbucket support | Fragmentation before GitHub Actions is stable |
| Custom scan rule authoring | Large surface area, few users use it |
| Real-time scan streaming to platform | Creates hard uptime dependency |
| Scan result diff / baseline comparison | Requires platform dependency during scan |
| Slack/Teams/PagerDuty notifications | Belongs in platform, not the Action |
| Browser/UI scan configuration wizard | CI audience works in YAML |
| Per-endpoint test selection/exclusion | Complex config surface; defer |
| OAuth/OIDC for platform auth | Impossible from CI runner |

## Feature Dependencies

```
Docker image published
  └── GitHub Action can run

Scanner entrypoint accepts file inputs
  └── Action `with:` inputs map to entrypoint args
  └── SARIF output file path configurable

SARIF formatter
  └── GitHub Security tab integration
  └── PR annotations

PR comment poster
  └── Requires: GITHUB_TOKEN + scan result dict

Exit code gate
  └── Requires: severity_counts + threshold input

Optional platform callback
  └── Requires: secoraa-api-key (skip if absent)
  └── Must NOT block exit code gate
```

## MVP Recommendation

**Must ship (unusable without):**
1. Docker image with scanner entrypoint
2. SARIF 2.1.0 output
3. PR comment with findings table
4. Exit code on configurable severity threshold
5. Core inputs: target-url, openapi-file/postman-file, auth-token, fail-on-severity
6. Minimal working workflow.yml example

**Ship but not blocking:**
7. Optional platform callback
8. API key management in Settings
9. CI scan history view

## Competitive Matrix

| Feature | StackHawk | 42Crunch | Escape | ZAP Action | **Secoraa** |
|---------|-----------|----------|--------|------------|-------------|
| GitHub Action | Yes | Yes | Yes | Yes | **Yes** |
| SARIF output | Yes | Yes | Yes | Yes | **Yes** |
| PR comment | Yes | Yes | Yes | No | **Yes** |
| Dynamic DAST | Yes | No | Yes | Yes | **Yes** |
| OOB blind detection | No | No | Limited | Limited | **Yes** |
| Two-token BOLA | No | No | Yes | No | **Yes** |
| Self-contained | No | No | No | Yes | **Yes** |
| CVSS scores shown | No | Yes | Yes | No | **Yes** |
| Postman support | Yes | No | Yes | No | **Yes** |

**Key takeaway:** Self-contained + OOB blind detection + two-token BOLA + CVSS scores + Postman support is meaningfully differentiated. No single competitor has all five.
