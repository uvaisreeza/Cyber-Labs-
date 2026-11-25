"""Crypto & integrity (8 tools). Pure offline computation - nothing leaves the server."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import math
import re
import secrets
import string
from urllib.parse import quote, unquote

from app.core.errors import ToolError
from app.tools.registry import F, tool

MAX_TEXT = 100_000
MAX_FILE_BYTES = 5 * 1024 * 1024


def _text(p: dict, key: str = "text") -> str:
    t = p.get(key)
    if t is None or t == "":
        raise ToolError("Input text is required")
    if len(t) > MAX_TEXT:
        raise ToolError(f"Input too large (max {MAX_TEXT:,} characters)")
    return t


# ------------------------------------------------------------- 10 hash generator
@tool("hash_generate", "Hash Generator", "crypto",
      "MD5, SHA-1, SHA-2, SHA-3 and BLAKE2 digests of any text. (MD5/SHA-1 are broken for security use.)",
      [F("text", "Text", "textarea")])
def hash_generate(p: dict) -> dict:
    data = _text(p).encode()
    algos = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"]
    return {"input_bytes": len(data), "hashes": {a: hashlib.new(a, data).hexdigest() for a in algos}}


# ------------------------------------------------------------- 11 file integrity
@tool("file_hash", "File Integrity Check", "crypto",
      "Hash a file (up to 5 MB, hashed in memory, not stored) and compare it with a published checksum.",
      [F("file", "File", "file"),
       F("expected", "Expected checksum (optional)", required=False,
         placeholder="paste the vendor's SHA-256")],
      store_result=True)
def file_hash(p: dict) -> dict:
    f = p.get("file")
    if not isinstance(f, dict) or "content_b64" not in f:
        raise ToolError("Choose a file")
    try:
        data = base64.b64decode(f["content_b64"], validate=True)
    except (binascii.Error, ValueError):
        raise ToolError("File upload was corrupted")
    if len(data) > MAX_FILE_BYTES:
        raise ToolError("File too large (max 5 MB)")
    hashes = {a: hashlib.new(a, data).hexdigest() for a in ("md5", "sha1", "sha256", "sha512")}
    out = {"filename": str(f.get("name", ""))[:120], "size_bytes": len(data), "hashes": hashes}
    exp = (p.get("expected") or "").strip().lower()
    if exp:
        match = next((a for a, v in hashes.items() if hmac.compare_digest(v, exp)), None)
        out["verification"] = ({"match": True, "algorithm": match} if match
                               else {"match": False, "note": "No digest matched - file may be corrupt or tampered."})
    return out


# ---------------------------------------------------------------- 12-14 encoders
@tool("base64_codec", "Base64 Encode / Decode", "crypto", "Standard or URL-safe Base64.",
      [F("text", "Input", "textarea"),
       F("mode", "Mode", "select", options=["encode", "decode"], default="encode"),
       F("variant", "Alphabet", "select", options=["standard", "urlsafe"], default="standard")])
def base64_codec(p: dict) -> dict:
    t, urlsafe = _text(p), p.get("variant") == "urlsafe"
    if p.get("mode") == "decode":
        s = re.sub(r"\s+", "", t)
        if not re.fullmatch(r"[A-Za-z0-9_-]*={0,2}" if urlsafe else r"[A-Za-z0-9+/]*={0,2}", s):
            raise ToolError("Not valid Base64")
        try:
            raw = (base64.urlsafe_b64decode if urlsafe else base64.b64decode)(s + "=" * (-len(s) % 4))
        except (binascii.Error, ValueError):
            raise ToolError("Not valid Base64")
        try:
            return {"output": raw.decode("utf-8"), "bytes": len(raw)}
        except UnicodeDecodeError:
            return {"output": raw.hex(), "bytes": len(raw), "note": "Binary data - shown as hex"}
    raw = t.encode()
    return {"output": (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(raw).decode(), "bytes": len(raw)}


@tool("hex_codec", "Hex Encode / Decode", "crypto", "Convert text to and from hexadecimal.",
      [F("text", "Input", "textarea"),
       F("mode", "Mode", "select", options=["encode", "decode"], default="encode")])
def hex_codec(p: dict) -> dict:
    t = _text(p)
    if p.get("mode") == "decode":
        cleaned = re.sub(r"(0x|\\x|\s|:)", "", t)
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError:
            raise ToolError("Not valid hexadecimal")
        return {"output": raw.decode("utf-8", errors="replace"), "bytes": len(raw)}
    return {"output": t.encode().hex(), "bytes": len(t.encode())}


@tool("url_codec", "URL Encode / Decode", "crypto", "Percent-encode or decode URL components.",
      [F("text", "Input", "textarea"),
       F("mode", "Mode", "select", options=["encode", "decode"], default="encode")])
def url_codec(p: dict) -> dict:
    t = _text(p)
    return {"output": unquote(t) if p.get("mode") == "decode" else quote(t, safe="")}


# ------------------------------------------------------------ 15 password strength
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
    "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein",
    "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "superman", "1qaz2wsx", "welcome", "admin", "password1",
    "iloveyou", "trustno1", "passw0rd", "p@ssw0rd", "qwerty123", "admin123", "login",
}
_SEQ = re.compile(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|wert|asdf|zxcv)", re.I)


def human_time(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    for name, s in (("years", 31_536_000), ("days", 86_400), ("hours", 3600), ("minutes", 60), ("seconds", 1)):
        if seconds >= s:
            v = seconds / s
            return f"{v:.2e} {name}" if v > 1e6 else f"{v:,.1f} {name}"
    return "instantly"


@tool("password_strength", "Password Strength", "crypto",
      "Entropy, pattern checks and offline crack-time estimate. The password is never stored or logged.",
      [F("password", "Password", "password", sensitive=True)])
def password_strength(p: dict) -> dict:
    pw = p.get("password") or ""
    if not pw:
        raise ToolError("Password cannot be empty")
    classes = {"lower": bool(re.search(r"[a-z]", pw)), "upper": bool(re.search(r"[A-Z]", pw)),
               "digit": bool(re.search(r"\d", pw)), "symbol": bool(re.search(r"[^a-zA-Z0-9]", pw))}
    pool = sum(n for k, n in (("lower", 26), ("upper", 26), ("digit", 10), ("symbol", 33)) if classes[k]) or 1
    entropy = round(len(pw) * math.log2(pool), 1)
    score, issues = 100, []
    if pw.lower() in COMMON_PASSWORDS:
        score -= 60; issues.append("Appears in lists of commonly breached passwords")
    if re.search(r"(.)\1{2,}", pw):
        score -= 10; issues.append("Repeated character runs (aaa, 111)")
    if _SEQ.search(pw):
        score -= 15; issues.append("Sequential or keyboard pattern")
    if len(pw) < 8:
        score -= 30; issues.append("Shorter than 8 characters")
    elif len(pw) < 12:
        score -= 10; issues.append("Under the recommended 12 characters")
    variety = sum(classes.values())
    if variety < 3:
        score -= (3 - variety) * 10; issues.append("Low character variety")
    score = max(0, min(100, score))
    verdict = ("Very Strong" if score >= 85 else "Strong" if score >= 65 else "Moderate" if score >= 45
               else "Weak" if score >= 25 else "Very Weak")
    return {"length": len(pw), "entropy_bits": entropy, "score": score, "verdict": verdict,
            "estimated_crack_time": human_time(2 ** entropy / 1e10),
            "assumes": "10 billion guesses/second against a fast unsalted hash",
            "character_classes": classes, "issues": issues}


# ------------------------------------------------------------ 16 password generator
@tool("password_generator", "Password Generator", "crypto",
      "Cryptographically secure random passwords (Python `secrets`). Results are not stored.",
      [F("length", "Length", "number", default=20),
       F("count", "How many", "number", default=5),
       F("symbols", "Include symbols", "checkbox", default=True, required=False),
       F("ambiguous", "Avoid look-alike characters (0 O l 1 I)", "checkbox", default=True, required=False)],
      store_result=False)
def password_generator(p: dict) -> dict:
    try:
        n, count = int(p.get("length") or 20), int(p.get("count") or 5)
    except (TypeError, ValueError):
        raise ToolError("Length and count must be numbers")
    if not 8 <= n <= 128 or not 1 <= count <= 20:
        raise ToolError("Length must be 8-128 and count 1-20")
    sets = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if p.get("symbols"):
        sets.append("!@#$%^&*()-_=+[]{};:,.?")
    if p.get("ambiguous"):
        sets = ["".join(c for c in s if c not in "0Ol1I") for s in sets]
    alphabet = "".join(sets)
    out = []
    for _ in range(count):
        chars = [secrets.choice(s) for s in sets]  # guarantee one of each class
        chars += [secrets.choice(alphabet) for _ in range(n - len(chars))]
        secrets.SystemRandom().shuffle(chars)
        out.append("".join(chars))
    return {"passwords": out, "entropy_bits": round(n * math.log2(len(alphabet)), 1)}


# ------------------------------------------------------------- 17 hash identifier
_HASH_RULES = [
    (r"^\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}$", ["bcrypt"]),
    (r"^\$argon2(id|i|d)\$", ["Argon2"]),
    (r"^\$6\$", ["SHA-512 crypt (Linux shadow)"]),
    (r"^\$5\$", ["SHA-256 crypt (Linux shadow)"]),
    (r"^\$1\$", ["MD5 crypt (legacy)"]),
    (r"^\$P\$|^\$H\$", ["phpass (WordPress / phpBB)"]),
    (r"^pbkdf2_sha256\$", ["Django PBKDF2-SHA256"]),
    (r"^\*[A-F0-9]{40}$", ["MySQL 4.1+ (SHA-1 of SHA-1)"]),
    (r"^[a-f0-9]{128}$", ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"]),
    (r"^[a-f0-9]{96}$", ["SHA-384", "SHA3-384"]),
    (r"^[a-f0-9]{64}$", ["SHA-256", "SHA3-256", "BLAKE2s", "RIPEMD-256"]),
    (r"^[a-f0-9]{56}$", ["SHA-224", "SHA3-224"]),
    (r"^[a-f0-9]{40}$", ["SHA-1", "RIPEMD-160"]),
    (r"^[a-f0-9]{32}$", ["MD5", "NTLM", "MD4"]),
    (r"^[a-f0-9]{16}$", ["MySQL < 4.1", "Half MD5"]),
    (r"^[a-f0-9]{8}$", ["CRC32 / Adler32"]),
]
_WEAK = {"MD5", "SHA-1", "MD4", "NTLM", "MD5 crypt (legacy)", "CRC32 / Adler32", "MySQL < 4.1"}


@tool("hash_identify", "Hash Identifier", "crypto",
      "Guess the algorithm of a hash from its format. Identification only - no cracking.",
      [F("hash", "Hash", placeholder="5f4dcc3b5aa765d61d8327deb882cf99")])
def hash_identify(p: dict) -> dict:
    h = (p.get("hash") or "").strip()
    if not h or len(h) > 600:
        raise ToolError("Provide a hash (max 600 chars)")
    cand = next((c for rx, c in _HASH_RULES if re.match(rx, h if h.startswith(("$", "*", "pbkdf2")) else h.lower())), [])
    return {"hash": h[:120], "length": len(h), "candidates": cand,
            "weak_for_passwords": [c for c in cand if c in _WEAK],
            "note": "Same-length digests are indistinguishable; the first candidate is the most common."
            if cand else "No known format matches."}
