# vuln-app (INTENTIONALLY VULNERABLE)

> **Warning:** this is deliberately insecure demo code for the SealedBounty hackathon demo.
> Do not deploy it, expose it to a network, or copy patterns from it.

A tiny Express + Postgres API used as the bounty target. The judge sees `src/server.ts`
verbatim as the code excerpt.

- Demo repo URL: `https://github.com/sealedbounty/vuln-app`
- Demo commit id (fixed, fake): `demo-commit-0001`

## Planted bugs (the "answer key")

| # | Endpoint | Bug | CWE | Expected verdict |
|---|----------|-----|-----|------------------|
| 1 | `GET /users?id=` | SQL injection: `id` is concatenated into the SQL string | CWE-89 | valid, critical/high |
| 2 | `GET /invoices/:id` | IDOR: any logged-in user can read any invoice (no `owner_id` check) | CWE-639 | valid, high/medium |

Everything else (`/health`, `GET /invoices`, `requireUser`) is intentionally fine, so a
report claiming e.g. RCE via `/health` is bogus. The comments in the source deliberately do not
point at the bugs, so the judge has to find them in the code.

Exploit reports for the demo live in `../exploits/`.
