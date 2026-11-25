# Security policy

Report vulnerabilities privately (GitHub "Report a vulnerability") rather than in a public issue.

Hardening checklist for hosting publicly: set a strong `SECRET_KEY`, `COOKIE_SECURE=true` behind
HTTPS, keep `ALLOW_PRIVATE_TARGETS=false`, consider `ALLOW_REGISTRATION=false`, and add an egress
firewall (the SSRF guard re-resolves DNS after validation, so rebinding is not fully excluded).
