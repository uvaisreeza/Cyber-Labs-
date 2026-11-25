"""Tool catalogue, tool execution and the per-user scan history / audit log."""

import json
import time
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.config import settings
from app.core.errors import TargetBlocked, ToolError
from app.core.limiter import limiter
from app.core.security import CurrentUser
from app.db import get_db
from app.tools.registry import CATEGORIES, REGISTRY, Tool

router = APIRouter(prefix="/api", tags=["tools"])
MAX_RESULT_BYTES = 200_000


class RunRequest(BaseModel):
    params: Dict[str, Any] = {}


def _target_of(tool: Tool, params: dict) -> str:
    """Human-readable target for the audit log - never a secret."""
    for f in tool.fields:
        if f.get("sensitive") or f["type"] in ("file", "checkbox", "select", "password"):
            continue
        v = params.get(f["name"])
        if isinstance(v, str) and v.strip():
            return v.strip()[:200]
    return ""


def _log(user_id: int, tool: Tool, target: str, status: str, ms: int,
         result: dict = None, error: str = None) -> int:
    blob = None
    if result is not None and tool.store_result:
        blob = json.dumps(result, default=str)
        if len(blob) > MAX_RESULT_BYTES:
            blob = json.dumps({"truncated": True, "note": "Result too large to store"})
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO scan_logs (user_id, tool_id, tool_name, category, target, status,"
            " duration_ms, result_json, error) VALUES (?,?,?,?,?,?,?,?,?)",
            (user_id, tool.id, tool.name, tool.category, target, status, ms, blob, error))
        return cur.lastrowid


@router.get("/tools")
def list_tools(user: dict = CurrentUser):
    return {"categories": [{"id": c, "name": n} for c, n in CATEGORIES],
            "tools": [t.public() for t in REGISTRY.values()]}


@router.post("/tools/{tool_id}")
@limiter.limit(settings.rate_limit_tools)
def run_tool(request: Request, tool_id: str, body: RunRequest, user: dict = CurrentUser):
    tool = REGISTRY.get(tool_id)
    if not tool:
        raise HTTPException(404, "Unknown tool")
    target = _target_of(tool, body.params)
    start = time.perf_counter()
    try:
        result = tool.handler(body.params)
    except TargetBlocked as e:
        ms = int((time.perf_counter() - start) * 1000)
        _log(user["id"], tool, target, "blocked", ms, error=str(e))
        raise HTTPException(403, str(e))
    except ToolError as e:
        ms = int((time.perf_counter() - start) * 1000)
        _log(user["id"], tool, target, "error", ms, error=str(e))
        raise HTTPException(400, str(e))
    except Exception:
        ms = int((time.perf_counter() - start) * 1000)
        _log(user["id"], tool, target, "error", ms, error="internal error")
        raise HTTPException(500, "The tool failed unexpectedly")
    ms = int((time.perf_counter() - start) * 1000)
    log_id = _log(user["id"], tool, target, "ok", ms, result=result)
    return {"tool": tool.id, "duration_ms": ms, "log_id": log_id, "result": result}


# ------------------------------------------------------------------- history
def _row(r, with_result=False) -> dict:
    d = {k: r[k] for k in ("id", "tool_id", "tool_name", "category", "target", "status",
                           "duration_ms", "error", "created_at")}
    if with_result:
        d["result"] = json.loads(r["result_json"]) if r["result_json"] else None
    return d


@router.get("/history")
def history(limit: int = 100, user: dict = CurrentUser):
    limit = max(1, min(limit, 500))
    with get_db() as db:
        rows = db.execute("SELECT * FROM scan_logs WHERE user_id = ? ORDER BY id DESC LIMIT ?",
                          (user["id"], limit)).fetchall()
    return {"items": [_row(r) for r in rows]}


@router.get("/history/{log_id}")
def history_item(log_id: int, user: dict = CurrentUser):
    with get_db() as db:
        r = db.execute("SELECT * FROM scan_logs WHERE id = ? AND user_id = ?",
                       (log_id, user["id"])).fetchone()
    if not r:
        raise HTTPException(404, "Not found")
    return _row(r, with_result=True)


@router.delete("/history/{log_id}")
def delete_history(log_id: int, user: dict = CurrentUser):
    with get_db() as db:
        cur = db.execute("DELETE FROM scan_logs WHERE id = ? AND user_id = ?", (log_id, user["id"]))
    if not cur.rowcount:
        raise HTTPException(404, "Not found")
    return {"deleted": log_id}
