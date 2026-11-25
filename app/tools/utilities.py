"""Utilities (6 tools)."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
from datetime import datetime, timezone

from app.core.errors import ToolError
from app.core.security_guards import blocked_reason, safe_request
from app.tools.registry import F, tool


# -------------------------------------------------------------------- 23 JWT
def _b64json(part: str):
    try:
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (binascii.Error, ValueError, json.JSONDecodeError):
        raise ToolError("Token segment is not valid Base64URL JSON")


@tool("jwt_decode", "JWT Decoder", "utils",
      "Decode a JSON Web Token's header and claims, and flag risky settings. The signature is NOT verified.",
      [F("token", "JWT", "textarea", sensitive=True)], store_result=False)
def jwt_decode(p: dict) -> dict:
    parts = (p.get("token") or "").strip().split(".")
    if len(parts) != 3:
        raise ToolError("A JWT has three dot-separated parts")
    header, claims = _b64json(parts[0]), _b64json(parts[1])
    warn, now = [], datetime.now(timezone.utc).timestamp()
    if str(header.get("alg", "")).lower() == "none" or not parts[2]:
        warn.append("Unsigned token (alg=none) - must never be accepted")
    if str(header.get("alg", "")).upper().startswith("HS"):
        warn.append("Symmetric HMAC algorithm - the signing secret could be brute-forced if weak")
    exp, nbf = claims.get("exp"), claims.get("nbf")
    status = {}
    if isinstance(exp, (int, float)):
        status["expires"] = datetime.fromtimestamp(exp, timezone.utc).isoformat()
        status["expired"] = exp < now
    else:
        warn.append("No 'exp' claim - token never expires")
    if isinstance(nbf, (int, float)):
        status["not_before_in_future"] = nbf > now
    return {"header": header, "claims": claims, "time_status": status, "warnings": warn,
            "signature_verified": False}


# -------------------------------------------------------------------- 24 CIDR
@tool("cidr_calc", "CIDR / Subnet Calculator", "utils",
      "Network, broadcast, mask and host range for an IPv4 or IPv6 block.",
      [F("cidr", "CIDR", placeholder="192.168.10.0/24")])
def cidr_calc(p: dict) -> dict:
    try:
        n = ipaddress.ip_network((p.get("cidr") or "").strip(), strict=False)
    except ValueError:
        raise ToolError("Not a valid CIDR block, e.g. 10.0.0.0/8")
    hosts = n.num_addresses - (2 if n.version == 4 and n.prefixlen < 31 else 0)
    out = {"network": str(n.network_address), "prefix_length": n.prefixlen, "version": n.version,
           "total_addresses": n.num_addresses, "usable_hosts": max(hosts, 0),
           "first_address": str(n.network_address), "last_address": str(n.broadcast_address)}
    if n.version == 4:
        out.update(netmask=str(n.netmask), wildcard=str(n.hostmask), broadcast=str(n.broadcast_address))
        if n.prefixlen < 31 and n.num_addresses > 2:
            out["first_usable"] = str(n.network_address + 1)
            out["last_usable"] = str(n.broadcast_address - 1)
    return out


# -------------------------------------------------------- 25 redirect chain
@tool("redirect_chain", "Redirect Chain Tracer", "utils",
      "Follow a link hop by hop (up to 10) to reveal where a short or tracking URL really goes.",
      [F("url", "URL", placeholder="https://bit.ly/...")], network=True, active=True)
def redirect_chain(p: dict) -> dict:
    r = safe_request(p.get("url", ""), max_redirects=10)
    return {"hops": len(r.chain) - 1, "final_url": r.url, "final_status": r.status, "chain": r.chain}


# ------------------------------------------------------- 26 timestamp convert
@tool("timestamp_convert", "Timestamp Converter", "utils",
      "Convert between Unix epoch (s / ms) and ISO-8601 - handy when reading logs.",
      [F("value", "Epoch or ISO date", placeholder="1767225600  or  2026-01-01T00:00:00Z")])
def timestamp_convert(p: dict) -> dict:
    v = (p.get("value") or "").strip()
    if not v:
        raise ToolError("Enter a value")
    if re.fullmatch(r"-?\d+(\.\d+)?", v):
        x = float(v)
        if abs(x) > 1e14:
            x /= 1e6   # microseconds
        elif abs(x) > 1e11:
            x /= 1e3   # milliseconds
        try:
            dt = datetime.fromtimestamp(x, timezone.utc)
        except (OverflowError, OSError, ValueError):
            raise ToolError("Timestamp out of range")
    else:
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ToolError("Unrecognised date. Use ISO-8601, e.g. 2026-01-01T00:00:00Z")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    return {"iso_utc": dt.astimezone(timezone.utc).isoformat(), "epoch_seconds": int(dt.timestamp()),
            "epoch_milliseconds": int(dt.timestamp() * 1000), "weekday": dt.strftime("%A")}


# ------------------------------------------------------------ 27 IP classifier
@tool("ip_classify", "IP Address Classifier", "utils",
      "Offline: version, scope (public / private / loopback...), reverse pointer and numeric forms.",
      [F("ip", "IP address", placeholder="10.0.0.5")])
def ip_classify(p: dict) -> dict:
    s = (p.get("ip") or "").strip()
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        raise ToolError("Not a valid IP address")
    return {"ip": str(a), "version": a.version, "is_global": a.is_global, "is_private": a.is_private,
            "is_loopback": a.is_loopback, "is_link_local": a.is_link_local,
            "is_multicast": a.is_multicast, "is_reserved": a.is_reserved,
            "scannable_by_this_platform": blocked_reason(str(a), False) is None,
            "reverse_pointer": a.reverse_pointer, "integer": int(a), "hex": hex(int(a))}


# ------------------------------------------------------------- 28 IOC defanger
@tool("defang_ioc", "IOC Defang / Refang", "utils",
      "Make URLs, domains and IPs safe to paste into reports and tickets (hxxp, [.]) - or reverse it.",
      [F("text", "Indicators (one per line)", "textarea"),
       F("mode", "Mode", "select", options=["defang", "refang"], default="defang")])
def defang_ioc(p: dict) -> dict:
    t = p.get("text") or ""
    if not t.strip() or len(t) > 50_000:
        raise ToolError("Provide up to 50,000 characters of text")
    if p.get("mode") == "refang":
        out = re.sub(r"hxxp", "http", t, flags=re.I)
        out = out.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[@]", "@").replace("[at]", "@")
    else:
        out = re.sub(r"http", "hxxp", t, flags=re.I)
        out = re.sub(r"(?<=\w)\.(?=\w)", "[.]", out).replace("@", "[@]")
    return {"output": out, "lines": len(out.splitlines())}
