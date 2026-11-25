import jwt
from app.core.security import hash_password, verify_password, decode_token, create_token
from tests.conftest import make_user


def test_password_hash_roundtrip_and_long_passwords():
    h = hash_password("hunter2hunter2")
    assert h.startswith("$2") and verify_password("hunter2hunter2", h)
    assert not verify_password("wrong", h)
    long = "x" * 200
    assert verify_password(long, hash_password(long))
    assert not verify_password(long[:-1] + "y", hash_password(long))


def test_register_login_me(client):
    r = make_user(client)
    assert r.json()["is_admin"] is True           # first user
    c = r.headers["set-cookie"].lower()
    assert "httponly" in c and "samesite=lax" in c
    assert client.get("/api/auth/me").json()["username"] == "alice"
    client.post("/api/auth/logout")
    assert client.get("/api/auth/me").status_code == 401
    ok = client.post("/api/auth/login", json={"username": "ALICE", "password": "correct-horse-battery"})
    assert ok.status_code == 200 and ok.json()["access_token"]


def test_second_user_not_admin_and_duplicate(client):
    make_user(client)
    assert client.post("/api/auth/register", json={"username": "bob", "password": "another-long-pass"}).json()["is_admin"] is False
    d = client.post("/api/auth/register", json={"username": "Alice", "password": "another-long-pass"})
    assert d.status_code == 409


def test_register_validation(client):
    assert client.post("/api/auth/register", json={"username": "ab", "password": "long-enough-pw"}).status_code == 422
    assert client.post("/api/auth/register", json={"username": "bad name!", "password": "long-enough-pw"}).status_code == 400
    assert client.post("/api/auth/register", json={"username": "okname", "password": "short"}).status_code == 400


def test_login_failures_are_generic(client):
    make_user(client)
    a = client.post("/api/auth/login", json={"username": "alice", "password": "nope-nope-nope"})
    b = client.post("/api/auth/login", json={"username": "ghost", "password": "nope-nope-nope"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_bearer_token_works_and_tampered_rejected(client):
    make_user(client)
    tok = client.post("/api/auth/login", json={"username": "alice", "password": "correct-horse-battery"}).json()["access_token"]
    client.cookies.clear()
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}x"}).status_code == 401


def test_expired_and_none_alg_tokens_rejected(client):
    make_user(client)
    assert decode_token(create_token(1, "alice"))
    expired = jwt.encode({"sub": "1", "exp": 1}, "test-secret-key-test-secret-key-test-secret", algorithm="HS256")
    assert decode_token(expired) is None
    none_alg = jwt.encode({"sub": "1", "exp": 9999999999}, None, algorithm="none")
    assert decode_token(none_alg) is None


def test_pages_redirect_when_logged_out(client):
    for path in ("/dashboard", "/reports"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/").status_code == 200
    assert client.get("/login").status_code == 200
    assert client.get("/api/tools").status_code == 401
