"""Password hashing (bcrypt) and session tokens (JWT)."""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request

from app.config import settings
from app.db import get_db

JWT_ALG = "HS256"
COOKIE_NAME = "access_token"


def _prehash(password: str) -> bytes:
    # bcrypt silently truncates / rejects input over 72 bytes. SHA-256 + base64
    # gives a fixed 44-byte input so long passphrases are fully used.
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_prehash(password), hashed.encode())
    except ValueError:
        return False


# A real hash to compare against when the user does not exist, so login timing
# does not reveal which usernames are registered.
_DUMMY_HASH = hash_password("dummy-password-for-timing")


def verify_dummy(password: str) -> None:
    verify_password(password, _DUMMY_HASH)


def create_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "usr": username,
        "iat": now,
        "exp": now + timedelta(minutes=settings.token_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALG)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[JWT_ALG],
                          options={"require": ["exp", "sub"]})
    except jwt.PyJWTError:
        return None


def _token_from_request(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.cookies.get(COOKIE_NAME)


def user_from_request(request: Request) -> Optional[dict]:
    token = _token_from_request(request)
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    with get_db() as db:
        row = db.execute("SELECT id, username, is_admin FROM users WHERE id = ?",
                         (int(payload["sub"]),)).fetchone()
    return dict(row) if row else None


def current_user(request: Request) -> dict:
    user = user_from_request(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    return user


CurrentUser = Depends(current_user)
