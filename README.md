# >_ CyberLabs

**A free, self-hostable penetration-testing & threat-intelligence dashboard — 28 security tools in one browser tab.**

Reconnaissance, cryptography/integrity, threat intelligence and utilities behind a hacker-terminal UI
(matrix rain, boot sequence, scanlines). Built with **FastAPI · Jinja2 · SQLite · bcrypt + JWT · slowapi**.
No paid tier, no installs for users.

> ## ⚠️ Authorised use only
> Scanning or probing systems you don't own or lack written permission to test is illegal in most
> countries (India IT Act 2000 §43/66, US CFAA, UK Computer Misuse Act…). Use your own servers, a lab,
> or `scanme.nmap.org`. Every tool is **read-only reconnaissance** — nothing here exploits anything.

## Features
- **28 tools** in 4 domains (table below), auto-generated forms from a tool registry
- **Accounts**: bcrypt-hashed passwords, JWT sessions in HttpOnly SameSite cookies, timing-safe login
- **SSRF guards**: loopback, RFC 1918, link-local/cloud-metadata, CGNAT, multicast & reserved ranges
  are refused; redirects are re-validated hop by hop; response bodies are size-capped
- **Rate limiting** (slowapi) on auth and tool routes; strict input validation on every tool
- **Audit log + SecureCheck Report Builder**: every run is saved per user; export selected runs as
  JSON, CSV (formula-injection-safe) or a printable HTML report (Print → Save as PDF)
- **Self-hardened**: strict CSP (no inline JS/CSS), results rendered with `textContent` (no XSS from hostile targets)
- Secrets never stored: passwords, JWTs and API keys are excluded from logs; generated passwords aren't persisted

## Tools
| Domain | Tools |
|---|---|
| **Reconnaissance & Footprinting** | Port Scanner · WHOIS · DNS Lookup · Subdomain Enumeration (crt.sh, passive) · Reverse DNS · HTTP Security Headers · robots.txt/security.txt · Technology Fingerprint · SSL/TLS Checker |
| **Crypto & Integrity** | Hash Generator · File Integrity Check · Base64 · Hex · URL encode/decode · Password Strength · Password Generator · Hash Identifier |
| **Threat Intelligence** | VirusTotal · IP Geolocation/ASN · DNSBL blocklists · SPF/DKIM/DMARC audit · URL Risk Analyzer |
| **Utilities** | JWT Decoder · CIDR Calculator · Redirect Chain Tracer · Timestamp Converter · IP Classifier · IOC Defang/Refang |

## Quick start
```bash
git clone https://github.com/<you>/CyberLabs.git && cd CyberLabs
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env     # set SECRET_KEY (python -c "import secrets;print(secrets.token_urlsafe(48))")
set -a; source .env; set +a
uvicorn app.main:app --reload
```
Open <http://localhost:8000>, create an account (the first account becomes admin).

### Docker
```bash
cp .env.example .env    # set SECRET_KEY
docker compose up --build
```

### Tests
```bash
pip install -r requirements-dev.txt && pytest -q      # 74 tests, fully offline
```

## Configuration (`.env`)
| Variable | Default | Meaning |
|---|---|---|
| `SECRET_KEY` | random per start | JWT signing key — **set in production** |
| `DATABASE_PATH` | `cyberlabs.db` | SQLite file |
| `COOKIE_SECURE` | `false` | `true` when served over HTTPS |
| `ALLOW_PRIVATE_TARGETS` | `false` | Home-lab switch to allow scanning your own LAN |
| `ALLOW_REGISTRATION` | `true` | Close sign-ups after creating your accounts |
| `RATE_LIMIT_TOOLS` / `RATE_LIMIT_AUTH` | `30/minute` / `10/minute` | slowapi limits |
| `VT_API_KEY` | – | Optional server-wide VirusTotal key |

## API
Interactive docs at `/docs`. Core endpoints: `POST /api/auth/{register,login,logout}`, `GET /api/auth/me`,
`GET /api/tools`, `POST /api/tools/{id}` (`{"params": {...}}`), `GET /api/history`,
`POST /api/reports/export` (`{"ids":[…], "format":"json|csv|html"}`). Use the cookie or `Authorization: Bearer <token>`.

```bash
TOKEN=$(curl -s localhost:8000/api/auth/login -H 'content-type: application/json' \
  -d '{"username":"me","password":"…"}' | jq -r .access_token)
curl -s localhost:8000/api/tools/dns_lookup -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"params":{"domain":"example.com"}}'
```

## Project layout
```
app/
  main.py            app factory, security-header middleware
  config.py          environment settings
  db.py              SQLite schema (users, scan_logs)
  core/              security.py (bcrypt/JWT) · security_guards.py (SSRF) · limiter.py · errors.py
  routers/           pages · auth · tools · reports
  tools/             registry.py + recon / crypto / threat_intel / utilities
  templates/         Jinja2 pages (+ printable report.html)
  static/            css + js (terminal UI, no frameworks)
tests/               pytest suite
docs/ARCHITECTURE.md design notes and "how to add a tool"
```

## Known limitations
- The SSRF guard validates DNS, then `requests` resolves again: DNS rebinding is mitigated, not eliminated.
  Run behind an egress firewall for hostile environments.
- Port scanner is IPv4 TCP-connect only, max 1024 ports per request.
- Network-dependent tools (WHOIS, crt.sh, VirusTotal, ipwho.is, DNS) depend on those third parties;
  the automated tests cover only offline logic and the guard paths.
- Not implemented on purpose: exploitation, injection fuzzing, brute-forcing, hash cracking, web shell.

## Team
Final-year project, group K4RGC0112 — Uvais RS (repository owner), Mohammad Thafheem K, Sonu Subhash,
Muhammed Ansar, Isha Thamana. See `git log` for who authored what.

## License
MIT — see [LICENSE](LICENSE).
