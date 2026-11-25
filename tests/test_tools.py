import base64
import json

from app.core.limiter import limiter
from app.tools.registry import REGISTRY, load_all
from tests.conftest import make_user, run


def test_catalogue_has_28_tools_in_4_categories(authed):
    d = authed.get("/api/tools").json()
    assert len(d["tools"]) == 28 == len(REGISTRY)
    assert {t["category"] for t in d["tools"]} == {"recon", "crypto", "intel", "utils"}
    assert len({t["id"] for t in d["tools"]}) == 28
    assert "handler" not in d["tools"][0]


def test_every_tool_has_valid_field_metadata():
    load_all()
    for t in REGISTRY.values():
        assert t.description and t.name
        for f in t.fields:
            assert f["type"] in {"text", "textarea", "number", "select", "password", "checkbox", "file"}
            if f["type"] == "select":
                assert f["options"]


def test_unauthenticated_cannot_run(client):
    assert run(client, "hash_generate", text="x").status_code == 401


def test_unknown_tool(authed):
    assert run(authed, "nope").status_code == 404


def test_hash_generate(authed):
    h = run(authed, "hash_generate", text="hello").json()["result"]["hashes"]
    assert h["md5"] == "5d41402abc4b2a76b9719d911017c592"
    assert h["sha256"].startswith("2cf24dba5fb0a30e26e83b2ac5b9e29e")


def test_file_hash_and_verification(authed):
    b64 = base64.b64encode(b"hello").decode()
    sha = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    r = run(authed, "file_hash", file={"name": "a.txt", "content_b64": b64}, expected=sha.upper()).json()["result"]
    assert r["verification"] == {"match": True, "algorithm": "sha256"}
    r = run(authed, "file_hash", file={"name": "a.txt", "content_b64": b64}, expected="00" * 32).json()["result"]
    assert r["verification"]["match"] is False
    assert run(authed, "file_hash", file={"name": "x", "content_b64": "!!!"}).status_code == 400


def test_codecs(authed):
    assert run(authed, "base64_codec", text="hi there", mode="encode").json()["result"]["output"] == "aGkgdGhlcmU="
    assert run(authed, "base64_codec", text="aGkgdGhlcmU", mode="decode").json()["result"]["output"] == "hi there"
    assert run(authed, "base64_codec", text="@@@", mode="decode").status_code == 400
    assert run(authed, "hex_codec", text="AB", mode="encode").json()["result"]["output"] == "4142"
    assert run(authed, "hex_codec", text="0x41 42", mode="decode").json()["result"]["output"] == "AB"
    assert run(authed, "url_codec", text="a b&c", mode="encode").json()["result"]["output"] == "a%20b%26c"


def test_password_strength_and_not_logged(authed):
    weak = run(authed, "password_strength", password="password").json()["result"]
    strong = run(authed, "password_strength", password="Tr0ub4dor&3-horse-staple!").json()["result"]
    assert weak["score"] < 25 and strong["score"] >= 85
    hist = json.dumps(authed.get("/api/history").json())
    assert "Tr0ub4dor" not in hist and "password\"" not in hist.replace("password_strength", "")
    full = json.dumps([authed.get(f"/api/history/{i['id']}").json() for i in authed.get("/api/history").json()["items"]])
    assert "Tr0ub4dor" not in full


def test_password_generator(authed):
    r = run(authed, "password_generator", length=24, count=3, symbols=True, ambiguous=True).json()
    pws = r["result"]["passwords"]
    assert len(pws) == 3 and all(len(p) == 24 for p in pws) and len(set(pws)) == 3
    assert not any(c in "0Ol1I" for p in pws for c in p)
    # generated secrets must not be persisted
    hid = r["log_id"]
    assert authed.get(f"/api/history/{hid}").json()["result"] is None
    assert run(authed, "password_generator", length=3, count=1).status_code == 400


def test_hash_identify(authed):
    r = run(authed, "hash_identify", hash="5f4dcc3b5aa765d61d8327deb882cf99").json()["result"]
    assert r["candidates"][0] == "MD5" and "MD5" in r["weak_for_passwords"]
    b = run(authed, "hash_identify", hash="$2b$12$" + "a" * 53).json()["result"]
    assert b["candidates"] == ["bcrypt"]


def test_jwt_decode_flags_alg_none(authed):
    def seg(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    tok = f"{seg({'alg': 'none'})}.{seg({'sub': '1'})}."
    r = run(authed, "jwt_decode", token=tok).json()["result"]
    assert any("alg=none" in w for w in r["warnings"]) and r["signature_verified"] is False
    assert run(authed, "jwt_decode", token="a.b").status_code == 400


def test_cidr_ip_time_defang(authed):
    c = run(authed, "cidr_calc", cidr="192.168.10.77/24").json()["result"]
    assert c["network"] == "192.168.10.0" and c["usable_hosts"] == 254 and c["broadcast"] == "192.168.10.255"
    assert run(authed, "cidr_calc", cidr="bogus").status_code == 400
    i = run(authed, "ip_classify", ip="10.0.0.5").json()["result"]
    assert i["is_private"] and i["scannable_by_this_platform"] is False
    t = run(authed, "timestamp_convert", value="1767225600").json()["result"]
    assert t["iso_utc"].startswith("2026-01-01T00:00:00")
    assert run(authed, "timestamp_convert", value="1767225600000").json()["result"]["epoch_seconds"] == 1767225600
    d = run(authed, "defang_ioc", text="http://evil.com/a\nbob@evil.com", mode="defang").json()["result"]["output"]
    assert d == "hxxp://evil[.]com/a\nbob[@]evil[.]com"
    back = run(authed, "defang_ioc", text=d, mode="refang").json()["result"]["output"]
    assert back == "http://evil.com/a\nbob@evil.com"


def test_url_analyzer_offline(authed):
    bad = run(authed, "url_analyzer", url="http://paypa1-secure-login.verify-account.example.top/signin").json()["result"]
    good = run(authed, "url_analyzer", url="https://www.python.org/").json()["result"]
    assert bad["risk_score"] > 40 and good["risk_score"] == 0
    assert bad["defanged"].startswith("hxxp://") and "[.]" in bad["defanged"]


# ---------------------------------------------------------------- SSRF end-to-end
def test_ssrf_blocked_with_403_and_audited(authed):
    for tool, params in [
        ("http_headers", {"url": "http://169.254.169.254/latest/meta-data/"}),
        ("tech_fingerprint", {"url": "http://127.0.0.1:8000"}),
        ("redirect_chain", {"url": "http://10.0.0.1/"}),
        ("site_files", {"url": "http://localhost"}),
        ("ssl_check", {"host": "192.168.1.1"}),
        ("port_scan", {"host": "127.0.0.1", "mode": "common", "authorized": True}),
        ("reverse_dns", {"ip": "10.0.0.1"}),
        ("ip_geolocation", {"ip": "127.0.0.1"}),
        ("dnsbl_check", {"ip": "192.168.0.1"}),
    ]:
        r = run(authed, tool, **params)
        assert r.status_code == 403, (tool, r.text)
    items = authed.get("/api/history").json()["items"]
    assert items and all(i["status"] == "blocked" for i in items)


def test_port_scan_requires_authorisation(authed):
    r = run(authed, "port_scan", host="8.8.8.8", mode="common")
    assert r.status_code == 400 and "authorised" in r.json()["detail"]


def test_port_scan_range_cap(authed):
    r = run(authed, "port_scan", host="8.8.8.8", mode="range", start_port=1, end_port=5000, authorized=True)
    assert r.status_code == 400 and "max 1024" in r.json()["detail"]


def test_vt_needs_key_and_validates(authed):
    assert run(authed, "virustotal", query_type="hash", query="abc").status_code == 400
    assert run(authed, "virustotal", api_key="k", query_type="hash", query="abc").status_code == 400
    assert run(authed, "virustotal", api_key="k", query_type="ip", query="nope").status_code == 400


def test_history_is_private_per_user(client):
    make_user(client, "alice")
    log_id = run(client, "hash_generate", text="secret-a").json()["log_id"]
    client.post("/api/auth/logout")
    make_user(client, "bobby", "bobs-long-password")
    assert client.get("/api/history").json()["items"] == []
    assert client.get(f"/api/history/{log_id}").status_code == 404
    assert client.delete(f"/api/history/{log_id}").status_code == 404


def test_rate_limit_enforced(authed):
    limiter.enabled = True
    limiter.reset()
    try:
        codes = [run(authed, "hash_generate", text="x").status_code for _ in range(35)]
    finally:
        limiter.enabled = False
        limiter.reset()
    assert codes.count(200) == 30 and codes[-1] == 429
