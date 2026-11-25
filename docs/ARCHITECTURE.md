# Architecture

```
Browser (Jinja2 pages + vanilla JS, terminal UI)
   │  JSON over HTTPS, HttpOnly JWT cookie
   ▼
FastAPI app ── SecurityHeaders middleware (CSP, XFO, nosniff…)
   ├─ routers/pages.py     server-rendered pages (/, /login, /dashboard, /reports)
   ├─ routers/auth.py      register / login / logout / me      (bcrypt + JWT, rate-limited)
   ├─ routers/tools.py     GET /api/tools · POST /api/tools/{id} · /api/history
   └─ routers/reports.py   POST /api/reports/export  (json | csv | html)
        │
        ▼
tools/registry.py  ── 28 tools = decorated functions (recon, crypto, threat_intel, utilities)
        │
        ├─ core/security_guards.py   SSRF guard + safe_request (per-hop validation, size cap)
        ├─ core/security.py          bcrypt, JWT, current_user dependency
        ├─ core/limiter.py           slowapi
        └─ db.py                     SQLite: users, scan_logs (audit trail)
```

## Request flow for a tool run
1. `POST /api/tools/{id}` with `{"params": {...}}`; cookie or `Authorization: Bearer` required.
2. slowapi enforces `RATE_LIMIT_TOOLS` per client IP.
3. The tool function validates input; anything network-facing calls the SSRF guard first.
4. `TargetBlocked` → HTTP 403, `ToolError` → 400, anything else → 500 with a generic message.
5. Every outcome (`ok` / `error` / `blocked`) is written to `scan_logs`. Fields flagged `sensitive`
   are never logged; tools with `store_result=False` (password generator, JWT decoder) store no output.

## Adding a tool
```python
from app.tools.registry import F, tool

@tool("my_tool", "My Tool", "utils", "One-line description shown in the UI.",
      [F("value", "Value", placeholder="...")])
def my_tool(p: dict) -> dict:
    return {"echo": p["value"]}
```
Field types: `text textarea number select password checkbox file`.
Import the module in `registry.load_all()` if you add a new file.

## Tool catalogue (28)
| Domain | Tools |
|---|---|
| Recon & footprinting (9) | port_scan, whois, dns_lookup, subdomain_enum, reverse_dns, http_headers, site_files, tech_fingerprint, ssl_check |
| Crypto & integrity (8) | hash_generate, file_hash, base64_codec, hex_codec, url_codec, password_strength, password_generator, hash_identify |
| Threat intelligence (5) | virustotal, ip_geolocation, dnsbl_check, email_auth, url_analyzer |
| Utilities (6) | jwt_decode, cidr_calc, redirect_chain, timestamp_convert, ip_classify, defang_ioc |

## Deliberately out of scope
Exploitation, SQLi/XSS payload injection, directory brute-forcing, password/hash cracking and an
arbitrary-command web terminal. They are unsafe on a shared public host and legally risky for
a free platform; use dedicated tools on your own lab for those.
