"""SSRF guards and safe outbound HTTP.

Every tool that touches a user-supplied host or URL goes through this module.

What is enforced
  * Hostnames are syntax-checked (no schemes, paths, credentials, whitespace).
  * Every IP a hostname resolves to must be globally routable. Loopback, RFC 1918,
    link-local (incl. cloud metadata 169.254.169.254), CGNAT, multicast, reserved
    and unspecified addresses are refused. IPv4-mapped IPv6 is unwrapped first.
  * HTTP fetches follow redirects manually and re-validate every hop.
  * Response bodies are capped so a target cannot exhaust memory.

Known limitation
  Validation resolves the name, then `requests` resolves it again to connect, so a
  hostile DNS server could in theory answer differently the second time
  (DNS rebinding). For a stricter deployment run behind an egress firewall.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlsplit

import requests

from app.config import settings
from app.core.errors import TargetBlocked, ToolError

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
_REDIRECT_CODES = {301, 302, 303, 307, 308}
MAX_BODY_BYTES = 1_000_000
USER_AGENT = "CyberLabs-Recon/1.0 (+authorized security testing)"


# --------------------------------------------------------------------------- IPs
def blocked_reason(ip: str, allow_private: Optional[bool] = None) -> Optional[str]:
    """Return why `ip` must not be contacted, or None if it is acceptable."""
    if allow_private is None:
        allow_private = settings.allow_private_targets
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "not a valid IP address"
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped

    if addr.is_unspecified:
        return "unspecified address"
    if addr.is_multicast:
        return "multicast address"
    if addr.is_reserved:
        return "reserved address"
    if allow_private:
        return None
    if addr.is_loopback:
        return "loopback address"
    if addr.is_link_local:
        return "link-local address (cloud metadata range)"
    if addr.is_private:
        return "private (RFC 1918 / ULA) address"
    if not addr.is_global:
        return "non-global address (e.g. CGNAT / documentation range)"
    return None


def is_blocked_ip(ip: str, allow_private: Optional[bool] = None) -> bool:
    return blocked_reason(ip, allow_private) is not None


def require_public_ip(ip: str) -> str:
    """Validate a literal IP supplied by the user and return it normalised."""
    ip = (ip or "").strip()
    try:
        norm = str(ipaddress.ip_address(ip))
    except ValueError:
        raise ToolError(f"'{ip}' is not a valid IP address")
    reason = blocked_reason(norm)
    if reason:
        raise TargetBlocked(f"Blocked target {norm}: {reason}.")
    return norm


# ------------------------------------------------------------------------- hosts
def clean_host(host: str) -> str:
    """Syntax-check a bare hostname or IP literal and return it lower-cased."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        raise ToolError("A host or domain is required")
    if any(c in host for c in "/\\@?#: \t\r\n") and not _is_ip_literal(host):
        raise ToolError("Enter a bare host name (no scheme, path, port or credentials)")
    if _is_ip_literal(host):
        return host
    if not _HOST_RE.match(host):
        raise ToolError(f"'{host}' is not a valid host name")
    return host


def clean_domain(domain: str) -> str:
    """Like clean_host but must be a DNS name (not an IP) with at least one dot."""
    host = clean_host(domain)
    if _is_ip_literal(host):
        raise ToolError("Enter a domain name, not an IP address")
    if "." not in host:
        raise ToolError("Enter a fully qualified domain name, e.g. example.com")
    return host


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def resolve_and_validate(host: str) -> List[str]:
    """Resolve `host` and ensure *all* addresses are allowed. Returns the IPs."""
    host = clean_host(host).strip("[]")
    if _is_ip_literal(host):
        ips = [host]
    else:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            raise ToolError(f"Could not resolve host: {host}")
        ips = sorted({i[4][0] for i in infos})
    for ip in ips:
        reason = blocked_reason(ip)
        if reason:
            raise TargetBlocked(f"Blocked target {host} -> {ip}: {reason}.")
    return ips


# -------------------------------------------------------------------------- URLs
def normalise_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ToolError("A URL is required")
    if "://" not in url:
        url = "https://" + url
    return url


def validate_url(url: str) -> str:
    """Validate scheme, credentials and destination of a URL. Returns the URL."""
    url = normalise_url(url)
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise TargetBlocked("Only http:// and https:// URLs are allowed.")
    if parts.username or parts.password:
        raise TargetBlocked("URLs containing credentials are not allowed.")
    if not parts.hostname:
        raise ToolError("URL has no host")
    try:
        parts.port  # raises ValueError if out of range
    except ValueError:
        raise ToolError("URL has an invalid port")
    resolve_and_validate(parts.hostname)
    return url


@dataclass
class SafeResponse:
    url: str
    status: int
    headers: Dict[str, str]
    set_cookies: List[str]
    body: bytes
    chain: List[dict] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def safe_request(url: str, method: str = "GET", max_redirects: int = 5,
                 timeout: float = 8.0, max_bytes: int = MAX_BODY_BYTES,
                 follow: bool = True) -> SafeResponse:
    """HTTP request with per-hop SSRF validation and a response size cap."""
    current = validate_url(url)
    chain: List[dict] = []
    for _ in range(max_redirects + 1):
        validate_url(current)
        try:
            resp = requests.request(
                method, current, timeout=timeout, allow_redirects=False, stream=True,
                headers={"User-Agent": USER_AGENT},
            )
        except requests.exceptions.SSLError as e:
            raise ToolError(f"TLS error talking to {current}: {_short(e)}")
        except requests.exceptions.RequestException as e:
            raise ToolError(f"Could not reach {current}: {_short(e)}")
        try:
            body = resp.raw.read(max_bytes, decode_content=True) if method != "HEAD" else b""
            try:
                cookies = list(resp.raw.headers.getlist("Set-Cookie"))
            except Exception:
                cookies = [resp.headers["Set-Cookie"]] if "Set-Cookie" in resp.headers else []
            location = resp.headers.get("Location")
            chain.append({"url": current, "status": resp.status_code, "location": location})
            if follow and resp.status_code in _REDIRECT_CODES and location:
                current = urljoin(current, location)
                continue
            return SafeResponse(current, resp.status_code, dict(resp.headers),
                                cookies, body, chain)
        finally:
            resp.close()
    raise ToolError(f"Too many redirects (>{max_redirects})")


def _short(exc: Exception) -> str:
    msg = str(exc)
    return msg if len(msg) < 200 else msg[:197] + "..."
