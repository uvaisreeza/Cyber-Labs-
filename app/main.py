"""CyberLabs - free penetration-testing & threat-intelligence dashboard (FastAPI)."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.limiter import limiter
from app.db import init_db
from app.paths import STATIC_DIR
from app.routers import auth, pages, reports, tools
from app.tools.registry import REGISTRY, load_all

logging.basicConfig(level=logging.INFO)

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


class SecurityHeaders(BaseHTTPMiddleware):
    """The platform audits other sites' headers, so it ships a strict set itself."""

    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("Content-Security-Policy", CSP)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if request.url.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    load_all()
    logging.getLogger("cyberlabs").info("Loaded %d tools", len(REGISTRY))
    yield


app = FastAPI(title="CyberLabs", version="1.0.0", lifespan=lifespan,
              description="Free penetration-testing & threat-intelligence dashboard")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SecurityHeaders)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
app.include_router(pages.router)
app.include_router(auth.router)
app.include_router(tools.router)
app.include_router(reports.router)


@app.get("/healthz", include_in_schema=False)
def healthz():
    return JSONResponse({"status": "ok", "tools": len(REGISTRY)})
