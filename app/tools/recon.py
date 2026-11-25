"""Reconnaissance & footprinting (9 tools). Read-only; no exploitation."""

from __future__ import annotations

import concurrent.futures
import re
import socket
import ssl
from datetime import datetime, timezone

import dns.resolver
import requests
import whois as whois_lib
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from app.core.errors import ToolError
from app.core.security_guards import (
    USER_AGENT, clean_domain, clean_host, normalise_url, require_public_ip,
    resolve_and_validate, safe_request, validate_url,
)
from app.tools.registry import F, tool

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}
MAX_SCAN_PORTS = 1024


# ------------------------------------------------------------------ 1 port scan
def _probe(ip: str, port: int, timeout: float):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return None
            banner = ""
            try:  # passive banner grab only: we listen, we never send payloads
                s.settimeout(0.4)
                banner = s.recv(120).decode(errors="ignore").strip()
            except Exception:
                pass
            return {"port": port, "service": COMMON_PORTS.get(port, "unknown"),
                    "banner": banner[:120]}
    except Exception:
        return None


@tool("port_scan", "Port Scanner", "recon",
      "TCP connect scan of common ports or a custom range (max 1024 ports per run).",
      [F("host", "Host / IP", placeholder="scanme.nmap.org"),
       F("mode", "Mode", "select", options=["common", "range"], default="common"),
       F("start_port", "Start port", "number", default=1, required=False),
       F("end_port", "End port", "number", default=1024, required=False),
       F("authorized", "I own this target or have written permission to scan it",
         "checkbox")],
      network=True, active=True)
def port_scan(p: dict) -> dict:
    if not p.get("authorized"):
        raise ToolError("Confirm you are authorised to scan this target.")
    host = clean_host(p.get("host", ""))
    ips = [i for i in resolve_and_validate(host) if ":" not in i]
    if not ips:
        raise ToolError("Only IPv4 targets are supported by the scanner.")
    ip = ips[0]
    if p.get("mode", "common") == "common":
        ports = sorted(COMMON_PORTS)
    else:
        try:
            lo, hi = int(p.get("start_port") or 1), int(p.get("end_port") or 1024)
        except (TypeError, ValueError):
            raise ToolError("Ports must be integers")
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535) or hi < lo:
            raise ToolError("Ports must be 1-65535 and end >= start")
        if hi - lo + 1 > MAX_SCAN_PORTS:
            raise ToolError(f"Range too large - max {MAX_SCAN_PORTS} ports per scan.")
        ports = list(range(lo, hi + 1))
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as pool:
        for r in pool.map(lambda x: _probe(ip, x, 0.7), ports):
            if r:
                found.append(r)
    return {"host": host, "resolved_ip": ip, "ports_scanned": len(ports),
            "open_count": len(found), "open_ports": sorted(found, key=lambda r: r["port"])}


# -------------------------------------------------------------------- 2 whois
def _fmt(v):
    if isinstance(v, (list, tuple, set)):
        return sorted({_fmt(x) for x in v if x}, key=str) if v else []
    if isinstance(v, datetime):
        return v.isoformat()
    return v


@tool("whois", "WHOIS Lookup", "recon",
      "Registrar, registration dates, name servers and contacts for a domain.",
      [F("domain", "Domain", placeholder="example.com")], network=True)
def whois_lookup(p: dict) -> dict:
    domain = clean_domain(p.get("domain", ""))
    try:
        w = whois_lib.whois(domain)
    except Exception as e:
        raise ToolError(f"WHOIS lookup failed: {e}")
    if not w or not (w.get("domain_name") or w.get("registrar")):
        raise ToolError("No WHOIS record found for this domain.")
    out = {k: _fmt(w.get(k)) for k in (
        "registrar", "creation_date", "expiration_date", "updated_date",
        "name_servers", "status", "emails", "org", "country")}
    exp = w.get("expiration_date")
    exp = exp[0] if isinstance(exp, list) and exp else exp
    if isinstance(exp, datetime):
        exp = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
        out["days_until_expiry"] = (exp - datetime.now(timezone.utc)).days
    return {"domain": domain, **out}


# ----------------------------------------------------------------- 3 dns lookup
_RTYPES = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV", "PTR", "DS", "DNSKEY"}


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = r.lifetime = 4
    return r


@tool("dns_lookup", "DNS Lookup", "recon",
      "Query A, AAAA, MX, NS, TXT, CNAME, SOA and other record types.",
      [F("domain", "Domain", placeholder="example.com"),
       F("types", "Record types (comma separated)", default="A,AAAA,MX,NS,TXT,CNAME,SOA",
         required=False)], network=True)
def dns_lookup(p: dict) -> dict:
    domain = clean_domain(p.get("domain", ""))
    types = [t.strip().upper() for t in (p.get("types") or "").split(",") if t.strip()] \
        or ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    bad = [t for t in types if t not in _RTYPES]
    if bad:
        raise ToolError(f"Unsupported record type(s): {', '.join(bad)}")
    res, records = _resolver(), {}
    for t in types:
        try:
            records[t] = [a.to_text() for a in res.resolve(domain, t)]
        except dns.resolver.NoAnswer:
            records[t] = []
        except dns.resolver.NXDOMAIN:
            raise ToolError(f"Domain does not exist: {domain}")
        except Exception as e:
            records[t] = [f"error: {type(e).__name__}"]
    return {"domain": domain, "records": records}


# ------------------------------------------------------------ 4 subdomain enum
@tool("subdomain_enum", "Subdomain Enumeration", "recon",
      "Passive discovery from Certificate Transparency logs (crt.sh). Nothing is sent to the target.",
      [F("domain", "Domain", placeholder="example.com")], network=True)
def subdomain_enum(p: dict) -> dict:
    domain = clean_domain(p.get("domain", ""))
    try:
        r = requests.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                         timeout=20, headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
        rows = r.json()
    except Exception as e:
        raise ToolError(f"crt.sh lookup failed: {type(e).__name__}")
    subs = set()
    for row in rows:
        for name in str(row.get("name_value", "")).split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*") and name.endswith(domain):
                subs.add(name)
    return {"domain": domain, "count": len(subs), "subdomains": sorted(subs)[:1000],
            "truncated": len(subs) > 1000}


# ------------------------------------------------------------------ 5 reverse dns
@tool("reverse_dns", "Reverse DNS (PTR)", "recon",
      "Find the host name published for a public IP address.",
      [F("ip", "IP address", placeholder="8.8.8.8")], network=True)
def reverse_dns(p: dict) -> dict:
    ip = require_public_ip(p.get("ip", ""))
    try:
        name, aliases, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror):
        return {"ip": ip, "hostname": None, "aliases": [], "note": "No PTR record."}
    return {"ip": ip, "hostname": name, "aliases": aliases}


# ------------------------------------------------------------ 6 http security headers
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("high", "Forces HTTPS; stops downgrade / SSL-strip attacks."),
    "Content-Security-Policy": ("high", "Mitigates XSS and data-injection."),
    "X-Content-Type-Options": ("medium", "Stops MIME sniffing (value should be 'nosniff')."),
    "X-Frame-Options": ("medium", "Prevents clickjacking (or use CSP frame-ancestors)."),
    "Referrer-Policy": ("low", "Limits referrer data leaked to other sites."),
    "Permissions-Policy": ("low", "Restricts browser features such as camera / geolocation."),
}
_SEV = {"critical": 5, "high": 3, "medium": 2, "low": 1, "info": 0}


def _grade(score: int) -> str:
    return "A" if score == 0 else "B" if score <= 3 else "C" if score <= 6 else "D" if score <= 9 else "F"


@tool("http_headers", "HTTP Security Headers", "recon",
      "Audit security headers, cookie flags and banner disclosure of a web page.",
      [F("url", "URL", placeholder="https://example.com")], network=True, active=True)
def http_headers(p: dict) -> dict:
    r = safe_request(p.get("url", ""))
    h = {k.lower(): v for k, v in r.headers.items()}
    findings = []
    if not r.url.startswith("https://"):
        findings.append({"severity": "high", "issue": "Page not served over HTTPS",
                         "detail": "Traffic can be read or modified in transit."})
    for name, (sev, why) in SECURITY_HEADERS.items():
        if name.lower() not in h:
            if name == "Strict-Transport-Security" and not r.url.startswith("https://"):
                continue
            findings.append({"severity": sev, "issue": f"Missing {name}", "detail": why})
    if h.get("x-content-type-options", "nosniff").lower() != "nosniff":
        findings.append({"severity": "low", "issue": "X-Content-Type-Options is not 'nosniff'",
                         "detail": h["x-content-type-options"]})
    for hdr in ("server", "x-powered-by", "x-aspnet-version"):
        if hdr in h and re.search(r"\d", h[hdr]):
            findings.append({"severity": "low", "issue": f"{hdr} discloses a version",
                             "detail": f"{hdr}: {h[hdr]}"})
    for c in r.set_cookies:
        low, name = c.lower(), c.split("=", 1)[0].strip()
        flags = [f for f, ok in (("Secure", "secure" in low),
                                 ("HttpOnly", "httponly" in low),
                                 ("SameSite", "samesite" in low)) if not ok]
        if flags:
            findings.append({"severity": "medium", "issue": f"Cookie '{name}' missing {', '.join(flags)}",
                             "detail": "Weak cookie flags enable theft via XSS, sniffing or CSRF."})
    score = sum(_SEV[f["severity"]] for f in findings)
    return {"url": p.get("url"), "final_url": r.url, "status_code": r.status,
            "grade": _grade(score), "risk_score": score, "findings": findings,
            "redirects": len(r.chain) - 1}


# ------------------------------------------------------------ 7 robots/security.txt
@tool("site_files", "robots.txt / security.txt", "recon",
      "Check for robots.txt, sitemap.xml and /.well-known/security.txt, and list disallowed paths.",
      [F("url", "Site URL", placeholder="https://example.com")], network=True, active=True)
def site_files(p: dict) -> dict:
    base = normalise_url(p.get("url", ""))
    from urllib.parse import urlsplit
    sp = urlsplit(base)
    root = f"{sp.scheme}://{sp.netloc}"
    validate_url(root)
    out = {}
    for label, path in (("robots_txt", "/robots.txt"), ("sitemap_xml", "/sitemap.xml"),
                        ("security_txt", "/.well-known/security.txt")):
        try:
            r = safe_request(root + path, max_bytes=200_000)
            ok = r.status == 200 and b"<html" not in r.body[:300].lower()
            out[label] = {"found": ok, "status": r.status, "url": r.url}
            if ok and label == "robots_txt":
                out[label]["disallowed"] = [l.split(":", 1)[1].strip() for l in r.text.splitlines()
                                            if l.lower().startswith("disallow:") and l.split(":", 1)[1].strip()][:100]
            if ok and label == "security_txt":
                out[label]["contact"] = [l.split(":", 1)[1].strip() for l in r.text.splitlines()
                                         if l.lower().startswith("contact:")]
        except ToolError as e:
            out[label] = {"found": False, "error": str(e)}
    out["site"] = root
    return out


# ------------------------------------------------------------ 8 tech fingerprint
_TECH_SIGNS = [
    ("WordPress", r"wp-content|wp-includes"), ("Drupal", r"Drupal\.settings|/sites/default/files"),
    ("Joomla", r"/media/jui/|Joomla!"), ("Shopify", r"cdn\.shopify\.com"),
    ("React", r"data-reactroot|react(?:\.min)?\.js"), ("Vue.js", r"vue(?:\.min)?\.js|data-v-"),
    ("Angular", r"ng-version|angular(?:\.min)?\.js"), ("jQuery", r"jquery[-.\d]*(?:\.min)?\.js"),
    ("Bootstrap", r"bootstrap(?:\.min)?\.(?:css|js)"), ("Google Analytics", r"google-analytics\.com|gtag/js"),
    ("Cloudflare", r"cdnjs\.cloudflare\.com"), ("Next.js", r"/_next/"),
]


@tool("tech_fingerprint", "Technology Fingerprint", "recon",
      "Passively identify server, framework and CMS from headers and page source.",
      [F("url", "URL", placeholder="https://example.com")], network=True, active=True)
def tech_fingerprint(p: dict) -> dict:
    r = safe_request(p.get("url", ""))
    h = {k.lower(): v for k, v in r.headers.items()}
    html = r.text
    tech = sorted({n for n, rx in _TECH_SIGNS if re.search(rx, html, re.I)})
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I)
    cdn = [n for n, k in (("Cloudflare", "cf-ray"), ("Fastly", "x-served-by"),
                          ("Akamai", "x-akamai-transformed"), ("CloudFront", "x-amz-cf-id"),
                          ("Vercel", "x-vercel-id")) if k in h]
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return {"url": r.url, "status_code": r.status, "server": h.get("server"),
            "powered_by": h.get("x-powered-by"), "generator": gen.group(1) if gen else None,
            "cdn_or_waf": cdn, "detected": tech,
            "title": re.sub(r"\s+", " ", title.group(1)).strip()[:150] if title else None,
            "content_type": h.get("content-type")}


# ------------------------------------------------------------------ 9 TLS check
def _der_cert(host: str, ip: str, port: int, verify: bool):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=6) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            return s.getpeercert(binary_form=True), s.version(), s.cipher()


@tool("ssl_check", "SSL / TLS Checker", "recon",
      "Certificate validity, issuer, SANs, expiry, TLS version and cipher.",
      [F("host", "Host", placeholder="example.com"),
       F("port", "Port", "number", default=443, required=False)], network=True, active=True)
def ssl_check(p: dict) -> dict:
    host = clean_host(p.get("host", ""))
    try:
        port = int(p.get("port") or 443)
    except (TypeError, ValueError):
        raise ToolError("Port must be an integer")
    if not 1 <= port <= 65535:
        raise ToolError("Port must be 1-65535")
    ip = resolve_and_validate(host)[0]
    verify_error = None
    try:
        der, version, cipher = _der_cert(host, ip, port, True)
    except ssl.SSLCertVerificationError as e:
        verify_error = e.verify_message or str(e)
        try:
            der, version, cipher = _der_cert(host, ip, port, False)
        except Exception as e2:
            raise ToolError(f"TLS handshake failed: {e2}")
    except Exception as e:
        raise ToolError(f"TLS handshake failed: {e}")
    cert = x509.load_der_x509_certificate(der)
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    days = (na - datetime.now(timezone.utc)).days
    try:
        sans = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    def cn(name):
        a = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        b = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return (a or b)[0].value if (a or b) else None

    issues = []
    if verify_error:
        issues.append(f"Certificate failed verification: {verify_error}")
    if days < 0:
        issues.append("Certificate has expired")
    elif days <= 30:
        issues.append(f"Certificate expires in {days} days")
    if version in ("TLSv1", "TLSv1.1"):
        issues.append(f"Outdated protocol {version}")
    return {"host": host, "port": port, "ip": ip, "tls_version": version,
            "cipher_suite": cipher[0] if cipher else None, "trusted": verify_error is None,
            "subject_cn": cn(cert.subject), "issuer": cn(cert.issuer),
            "valid_from": nb.isoformat(), "valid_until": na.isoformat(),
            "days_until_expiry": days, "san": sans[:50],
            "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
            "key_size": getattr(cert.public_key(), "key_size", None),
            "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
            "issues": issues}
