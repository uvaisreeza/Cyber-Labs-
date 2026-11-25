"""Registration, login, logout (bcrypt + JWT in an HttpOnly cookie)."""

import re
import sqlite3

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.config import settings
from app.core.limiter import limiter
from app.core.security import (
    COOKIE_NAME, CurrentUser, create_token, hash_password, verify_dummy, verify_password,
)
from app.db import get_db

router = APIRouter(prefix="/api/auth", tags=["auth"])
_USERNAME = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=256)


def _set_cookie(resp: Response, token: str) -> None:
    resp.set_cookie(COOKIE_NAME, token, max_age=settings.token_minutes * 60, httponly=True,
                    samesite="lax", secure=settings.cookie_secure, path="/")


@router.post("/register", status_code=201)
@limiter.limit(settings.rate_limit_auth)
def register(request: Request, response: Response, body: Credentials):
    if not settings.allow_registration:
        raise HTTPException(403, "Registration is disabled on this server")
    if not _USERNAME.match(body.username):
        raise HTTPException(400, "Username: 3-32 characters, letters, digits, . _ - only")
    if len(body.password) < 10:
        raise HTTPException(400, "Password must be at least 10 characters")
    try:
        with get_db() as db:
            first = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
            cur = db.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?,?,?)",
                (body.username, hash_password(body.password), int(first)))
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "That username is taken")
    _set_cookie(response, create_token(uid, body.username))
    return {"id": uid, "username": body.username, "is_admin": first}


@router.post("/login")
@limiter.limit(settings.rate_limit_auth)
def login(request: Request, response: Response, body: Credentials):
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE username = ?", (body.username,)).fetchone()
    if not row:
        verify_dummy(body.password)
        raise HTTPException(401, "Invalid username or password")
    if not verify_password(body.password, row["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    _set_cookie(response, create_token(row["id"], row["username"]))
    return {"id": row["id"], "username": row["username"], "is_admin": bool(row["is_admin"]),
            "access_token": create_token(row["id"], row["username"]), "token_type": "bearer"}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me")
def me(user: dict = CurrentUser):
    return {"id": user["id"], "username": user["username"], "is_admin": bool(user["is_admin"])}
