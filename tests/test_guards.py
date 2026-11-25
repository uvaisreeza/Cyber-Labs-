import pytest

from app.core.errors import TargetBlocked, ToolError
from app.core.security_guards import (
    blocked_reason, clean_domain, clean_host, require_public_ip, resolve_and_validate, validate_url,
)


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254", "100.64.0.1",
    "0.0.0.0", "224.0.0.1", "240.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
])
def test_blocked_ips(ip):
    assert blocked_reason(ip, allow_private=False)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_ips_allowed(ip):
    assert blocked_reason(ip, allow_private=False) is None


def test_allow_private_switch_still_blocks_garbage():
    assert blocked_reason("192.168.1.1", allow_private=True) is None
    assert blocked_reason("127.0.0.1", allow_private=True) is None
    assert blocked_reason("0.0.0.0", allow_private=True)
    assert blocked_reason("224.0.0.1", allow_private=True)


def test_require_public_ip():
    assert require_public_ip(" 8.8.8.8 ") == "8.8.8.8"
    with pytest.raises(TargetBlocked):
        require_public_ip("127.0.0.1")
    with pytest.raises(ToolError):
        require_public_ip("not-an-ip")


def test_localhost_resolves_but_is_blocked():
    with pytest.raises(TargetBlocked):
        resolve_and_validate("localhost")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[::1]:8080/",
    "http://10.0.0.1", "http://localhost:5000", "ftp://example.com", "file:///etc/passwd",
    "gopher://8.8.8.8", "http://user:pw@8.8.8.8/", "http://0x7f000001/", "http://2130706433/",
])
def test_ssrf_urls_rejected(url):
    with pytest.raises(ToolError):
        validate_url(url)


def test_public_ip_url_ok():
    assert validate_url("http://8.8.8.8/x") == "http://8.8.8.8/x"


@pytest.mark.parametrize("bad", ["", "a b.com", "http://x.com", "x.com/path", "x.com:80", "u@x.com", "-a.com"])
def test_bad_hosts(bad):
    with pytest.raises(ToolError):
        clean_host(bad)


def test_clean_domain():
    assert clean_domain("Example.COM.") == "example.com"
    with pytest.raises(ToolError):
        clean_domain("8.8.8.8")
    with pytest.raises(ToolError):
        clean_domain("localhost")
