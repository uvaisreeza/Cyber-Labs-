"""SecureCheck Report Builder: export saved scan results as JSON, CSV or printable HTML."""

import csv
import io
import json
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app.config import settings
from app.core.limiter import limiter
from app.core.security import CurrentUser
from app.db import get_db
from app.paths import TEMPLATES_DIR

router = APIRouter(prefix="/api/reports", tags=["reports"])
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


class ExportRequest(BaseModel):
    ids: List[int] = Field(min_length=1, max_length=200)
    format: str = Field(pattern="^(json|csv|html)$")
    title: str = Field("SecureCheck Report", max_length=120)


def _flatten(v, prefix=""):
    """Flatten nested results into (path, value) rows for CSV."""
    if isinstance(v, dict):
        for k, x in v.items():
            yield from _flatten(x, f"{prefix}{k}.")
    elif isinstance(v, list):
        if v and all(not isinstance(x, (dict, list)) for x in v):
            yield prefix.rstrip("."), ", ".join(map(str, v))
        else:
            for i, x in enumerate(v):
                yield from _flatten(x, f"{prefix}{i}.")
    else:
        yield prefix.rstrip("."), v


def _csv_safe(v) -> str:
    """Neutralise spreadsheet formula injection (=, +, -, @ at start of a cell)."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@router.post("/export")
@limiter.limit(settings.rate_limit_tools)
def export(request: Request, body: ExportRequest, user: dict = CurrentUser):
    marks = ",".join("?" * len(body.ids))
    with get_db() as db:
        rows = db.execute(
            f"SELECT * FROM scan_logs WHERE user_id = ? AND id IN ({marks}) ORDER BY id",
            (user["id"], *body.ids)).fetchall()
    if not rows:
        raise HTTPException(404, "No matching scans")
    items = [{**{k: r[k] for k in ("id", "tool_name", "category", "target", "status",
                                   "duration_ms", "error", "created_at")},
              "result": json.loads(r["result_json"]) if r["result_json"] else None} for r in rows]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")

    if body.format == "json":
        payload = json.dumps({"title": body.title, "generated_at": generated,
                              "generated_by": user["username"], "scans": items}, indent=2)
        return Response(payload, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="securecheck-{stamp}.json"'})

    if body.format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["scan_id", "tool", "target", "status", "time", "field", "value"])
        for it in items:
            base = [it["id"], it["tool_name"], it["target"], it["status"], it["created_at"]]
            rows_ = list(_flatten(it["result"])) if it["result"] else [("error", it["error"] or "")]
            for k, v in rows_:
                w.writerow([_csv_safe(c) for c in base] + [_csv_safe(k), _csv_safe(v)])
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="securecheck-{stamp}.csv"'})

    html = templates.get_template("report.html").render(
        title=body.title, generated=generated, user=user["username"], items=items,
        flat={it["id"]: list(_flatten(it["result"])) if it["result"] else [] for it in items})
    return Response(html, media_type="text/html",
                    headers={"Content-Disposition": f'attachment; filename="securecheck-{stamp}.html"'})
