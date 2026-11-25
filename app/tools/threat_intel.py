"""Threat intelligence (5 tools)."""

from __future__ import annotations

import base64
import ipaddress
import re
from urllib.parse import unquote, urlsplit

import dns.resolver
import requests

from app.config import settings
from app.core.errors import ToolError
from app.core.security_guards import USER_AGENT, clean_domain, normalise_url, require_public_ip
from app.tools.registry import F, tool

VT_BASE = "https://www.virustotal.com/api/v3"


# ---------------------------------------------------------------- 18 VirusTotal
@tool("virustotal", "VirusTotal Lookup", "intel",
      "Reputation of a file hash, URL, domain or IP from 70+ engines. Needs a free VirusTotal API key "
      "(or set VT_API_KEY on the server). Your key is never stored.",
      [F("api_key", "API key (blank = server key)", "password", required=False, sensitive=True),
       F("query_type", "Type", "select", options=["hash", "domain", "ip", "url"], default="hash"),
       F("query", "Indicator", placeholder="hash / domain / IP / URL")],
      network=True)
def virustotal(p: dict) -> dict:
    key = (p.get("api_key") or settings.vt_api_key).strip()
    if not key:
        raise ToolError("Provide a VirusTotal API key (free at virustotal.com).")
    qt, q = p.get("query_type"), (p.get("query") or "").strip()
    if not q:
        raise ToolError("Indicator is required")
    if qt == "hash":
        if not re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", q):
            raise ToolError("Hash must be MD5, SHA-1 or SHA-256 (hex)")
        ep = f"/files/{q.lower()}"
    elif qt == "domain":
        ep = f"/domains/{clean_domain(q)}"
    elif qt == "ip":
        ep = f"/ip_addresses/{ipaddress.ip_address(q) if _is_ip(q) else _bad_ip()}"
    elif qt == "url":
        ep = "/urls/" + base64.urlsafe_b64encode(normalise_url(q).encode()).decode().strip("=")
    else:
        raise ToolError("Type must be hash, domain, ip or url")
    try:
        r = requests.get(VT_BASE + ep, headers={"x-apikey": key, "User-Agent": USER_AGENT}, timeout=12)
    except requests.RequestException as e:
        raise ToolError(f"VirusTotal request failed: {type(e).__name__}")
    if r.status_code in (401, 403):
        raise ToolError("VirusTotal rejected the API key")
    if r.status_code == 429:
        raise ToolError("VirusTotal rate limit hit (free keys: 4 requests/minute)")
    if r.status_code == 404:
        return {"found": False, "message": "VirusTotal has no report for this indicator yet."}
    if not r.ok:
        raise ToolError(f"VirusTotal error {r.status_code}")
    data = r.json().get("data", {})
    a = data.get("attributes", {})
    st = a.get("last_analysis_stats", {})
    mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
    return {"found": True, "type": data.get("type"), "id": data.get("id"),
            "verdict": "malicious" if mal >= 3 else "suspicious" if mal or sus else "clean / unknown",
            "malicious": mal, "suspicious": sus, "harmless": st.get("harmless", 0),
            "undetected": st.get("undetected", 0), "total_engines": sum(st.values()) if st else 0,
            "reputation": a.get("reputation"), "tags": a.get("tags", [])[:15],
            "link": f"https://www.virustotal.com/gui/search/{q}"}


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _bad_ip():
    raise ToolError("Not a valid IP address")


# -------------------------------------------------------------- 19 IP geolocation
@tool("ip_geolocation", "IP Geolocation & ASN", "intel",
      "Country, city, ISP and ASN for a public IP (via ipwho.is).",
      [F("ip", "IP address", placeholder="8.8.8.8")], network=True)
def ip_geolocation(p: dict) -> dict:
    ip = require_public_ip(p.get("ip", ""))
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=10, headers={"User-Agent": USER_AGENT})
        d = r.json()
    except Exception as e:
        raise ToolError(f"Geolocation service unreachable: {type(e).__name__}")
    if not d.get("success"):
        raise ToolError(d.get("message", "Lookup failed"))
    conn = d.get("connection", {})
    return {"ip": ip, "country": d.get("country"), "region": d.get("region"), "city": d.get("city"),
            "latitude": d.get("latitude"), "longitude": d.get("longitude"),
            "timezone": (d.get("timezone") or {}).get("id"), "asn": conn.get("asn"),
            "organisation": conn.get("org"), "isp": conn.get("isp"), "domain": conn.get("domain")}


# ------------------------------------------------------------------ 20 DNSBL
DNSBLS = {
    "zen.spamhaus.org": "Spamhaus ZEN",
    "bl.spamcop.net": "SpamCop",
    "b.barracudacentral.org": "Barracuda",
    "dnsbl-1.uceprotect.net": "UCEPROTECT L1",
    "psbl.surriel.com": "Passive Spam Block List",
}


@tool("dnsbl_check", "Blocklist (DNSBL) Check", "intel",
      "Is this IPv4 address listed on well-known spam / abuse blocklists?",
      [F("ip", "IPv4 address", placeholder="1.2.3.4")], network=True)
def dnsbl_check(p: dict) -> dict:
    ip = require_public_ip(p.get("ip", ""))
    if ":" in ip:
        raise ToolError("DNSBL check supports IPv4 only")
    rev = ".".join(reversed(ip.split(".")))
    res = dns.resolver.Resolver()
    res.timeout = res.lifetime = 3
    results, listed = [], 0
    for zone, name in DNSBLS.items():
        try:
            ans = [a.to_text() for a in res.resolve(f"{rev}.{zone}", "A")]
            if any(a.startswith("127.255.255.") for a in ans):   # Spamhaus: public resolver refused
                results.append({"list": name, "status": "unknown", "detail": "query refused (public resolver)"})
            else:
                listed += 1
                results.append({"list": name, "status": "listed", "detail": ", ".join(ans)})
        except dns.resolver.NXDOMAIN:
            results.append({"list": name, "status": "clean", "detail": ""})
        except Exception as e:
            results.append({"list": name, "status": "unknown", "detail": type(e).__name__})
    return {"ip": ip, "listed_on": listed, "checked": len(results), "results": results}


# ------------------------------------------------- 21 SPF / DKIM / DMARC audit
_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"]


def _txt(res, name):
    try:
        return ["".join(s.decode() for s in r.strings) for r in res.resolve(name, "TXT")]
    except Exception:
        return []


@tool("email_auth", "Email Auth (SPF/DKIM/DMARC)", "intel",
      "Audit a domain's anti-spoofing records and flag weak policies.",
      [F("domain", "Domain", placeholder="example.com")], network=True)
def email_auth(p: dict) -> dict:
    d = clean_domain(p.get("domain", ""))
    res = dns.resolver.Resolver()
    res.timeout = res.lifetime = 3
    issues = []

    spf = next((t for t in _txt(res, d) if t.lower().startswith("v=spf1")), None)
    if not spf:
        issues.append({"severity": "high", "issue": "No SPF record"})
    elif spf.rstrip().endswith("+all") or spf.rstrip().endswith(" all"):
        issues.append({"severity": "high", "issue": "SPF allows any sender (+all)"})
    elif spf.rstrip().endswith("?all"):
        issues.append({"severity": "medium", "issue": "SPF is neutral (?all) - no enforcement"})
    elif spf.rstrip().endswith("~all"):
        issues.append({"severity": "low", "issue": "SPF soft-fail (~all); consider -all"})

    dmarc = next((t for t in _txt(res, f"_dmarc.{d}") if t.lower().startswith("v=dmarc1")), None)
    policy = None
    if not dmarc:
        issues.append({"severity": "high", "issue": "No DMARC record"})
    else:
        m = re.search(r"\bp=(\w+)", dmarc, re.I)
        policy = m.group(1).lower() if m else None
        if policy == "none":
            issues.append({"severity": "medium", "issue": "DMARC policy is p=none (monitor only)"})
        if "rua=" not in dmarc.lower():
            issues.append({"severity": "low", "issue": "DMARC has no aggregate report address (rua)"})

    dkim = [s for s in _DKIM_SELECTORS
            if any("p=" in t for t in _txt(res, f"{s}._domainkey.{d}"))]
    return {"domain": d, "spf": spf, "dmarc": dmarc, "dmarc_policy": policy,
            "dkim_selectors_found": dkim,
            "dkim_note": "Only common selectors are probed; DKIM may exist under others.",
            "issues": issues}


# --------------------------------------------------- 22 URL phishing heuristics
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
_BAD_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "country", "work", "support"}
_LURES = ("login", "signin", "verify", "secure", "account", "update", "confirm", "banking",
          "password", "wallet", "invoice", "suspend", "unlock")


@tool("url_analyzer", "URL Risk Analyzer", "intel",
      "Offline phishing heuristics for a suspicious link. The URL is analysed as text and never visited.",
      [F("url", "URL", placeholder="http://paypa1-secure-login.example.top/verify")])
def url_analyzer(p: dict) -> dict:
    raw = (p.get("url") or "").strip()
    if not raw or len(raw) > 2048:
        raise ToolError("Provide a URL (max 2048 characters)")
    url = raw if "://" in raw else "http://" + raw
    try:
        sp = urlsplit(url)
        host = (sp.hostname or "").lower()
        port = sp.port
    except ValueError:
        raise ToolError("Malformed URL")
    if not host:
        raise ToolError("URL has no host")
    flags, pts = [], 0

    def add(points, msg):
        nonlocal pts
        pts += points
        flags.append(msg)

    if _is_ip(host):
        add(25, "Host is a raw IP address")
    if sp.scheme == "http":
        add(10, "Not using HTTPS")
    if "@" in sp.netloc:
        add(25, "Contains '@' - real host may differ from what is displayed")
    if host.startswith("xn--") or ".xn--" in host:
        add(20, "Punycode host - possible look-alike (homograph) domain")
    if host in _SHORTENERS:
        add(15, "URL shortener hides the true destination")
    labels = host.split(".")
    if len(labels) > 4:
        add(15, f"Many subdomain levels ({len(labels)})")
    if labels[-1] in _BAD_TLDS:
        add(15, f"TLD .{labels[-1]} is heavily abused")
    if host.count("-") >= 3:
        add(10, "Many hyphens in host name")
    if re.search(r"[a-z][01][a-z]", labels[-2] if len(labels) > 1 else ""):
        add(10, "Digit/letter swaps (e.g. paypa1) suggest brand impersonation")
    lures = [w for w in _LURES if w in (host + unquote(sp.path)).lower()]
    if lures:
        add(min(20, 7 * len(lures)), "Credential-lure keywords: " + ", ".join(lures))
    if port and port not in (80, 443):
        add(10, f"Unusual port {port}")
    if len(url) > 120:
        add(5, "Very long URL")
    if "%" in sp.path and len(re.findall(r"%[0-9a-f]{2}", sp.path, re.I)) > 5:
        add(10, "Heavily percent-encoded path")
    pts = min(pts, 100)
    return {"host": host, "scheme": sp.scheme, "risk_score": pts,
            "verdict": "High risk" if pts >= 50 else "Suspicious" if pts >= 25 else "Low risk",
            "flags": flags,
            "defanged": url.replace("http", "hxxp", 1).replace(".", "[.]"),
            "disclaimer": "Heuristics only - confirm with VirusTotal or a reputation service."}
