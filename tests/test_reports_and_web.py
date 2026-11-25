import csv
import io
import json
import re
from pathlib import Path

from tests.conftest import run


def _ids(c):
    return [i["id"] for i in c.get("/api/history").json()["items"]]


def test_export_json_csv_html(authed):
    run(authed, "hash_generate", text="a")
    run(authed, "cidr_calc", cidr="10.0.0.0/30")
    run(authed, "http_headers", url="http://127.0.0.1")          # blocked entry
    ids = _ids(authed)
    j = authed.post("/api/reports/export", json={"ids": ids, "format": "json", "title": "T"})
    assert j.status_code == 200 and "attachment" in j.headers["content-disposition"]
    body = j.json()
    assert body["title"] == "T" and len(body["scans"]) == 3 and body["generated_by"] == "alice"

    c = authed.post("/api/reports/export", json={"ids": ids, "format": "csv"})
    rows = list(csv.reader(io.StringIO(c.text)))
    assert rows[0][:3] == ["scan_id", "tool", "target"] and len(rows) > 5

    h = authed.post("/api/reports/export", json={"ids": ids, "format": "html", "title": "<b>X</b>"})
    assert "&lt;b&gt;X&lt;/b&gt;" in h.text and "<b>X</b>" not in h.text      # autoescaped


def test_csv_formula_injection_neutralised(authed):
    run(authed, "defang_ioc", text="=cmd|' /C calc'!A0")
    ids = _ids(authed)
    out = authed.post("/api/reports/export", json={"ids": ids, "format": "csv"}).text
    for row in csv.reader(io.StringIO(out)):
        assert not any(cell[:1] in "=+@" for cell in row if cell), row


def test_export_only_own_scans_and_validation(client):
    from tests.conftest import make_user
    make_user(client, "alice")
    run(client, "hash_generate", text="a")
    ids = _ids(client)
    client.post("/api/auth/logout")
    make_user(client, "bobby", "bobs-long-password")
    assert client.post("/api/reports/export", json={"ids": ids, "format": "json"}).status_code == 404
    assert client.post("/api/reports/export", json={"ids": [], "format": "json"}).status_code == 422
    assert client.post("/api/reports/export", json={"ids": [1], "format": "exe"}).status_code == 422


def test_security_headers_present(client):
    r = client.get("/")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/healthz").json()["tools"] == 28


def test_templates_have_no_inline_script_or_style(authed):
    for path in ("/", "/login", "/register", "/dashboard", "/reports"):
        html = authed.get(path, follow_redirects=True).text
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), path
        assert " style=" not in html and "onclick=" not in html, path


def test_frontend_never_uses_innerhtml():
    js = Path(__file__).resolve().parents[1] / "app" / "static" / "js"
    for f in js.glob("*.js"):
        assert "innerHTML" not in f.read_text(), f.name


def test_static_files_served(client):
    for p in ("css/style.css", "js/common.js", "js/dashboard.js", "js/auth.js", "js/reports.js"):
        assert client.get(f"/static/{p}").status_code == 200
