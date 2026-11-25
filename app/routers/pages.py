"""Server-rendered Jinja2 pages."""

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.core.security import user_from_request
from app.paths import TEMPLATES_DIR
from app.tools.registry import CATEGORIES, REGISTRY

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _page(request: Request, name: str, user=None, **ctx):
    return templates.TemplateResponse(request, name, {"user": user, **ctx})


@router.get("/")
def index(request: Request):
    user = user_from_request(request)
    if user:
        return RedirectResponse("/dashboard", status_code=303)
    return _page(request, "landing.html", tool_count=len(REGISTRY), categories=CATEGORIES)


@router.get("/login")
def login_page(request: Request):
    if user_from_request(request):
        return RedirectResponse("/dashboard", status_code=303)
    return _page(request, "login.html", mode="login")


@router.get("/register")
def register_page(request: Request):
    if user_from_request(request):
        return RedirectResponse("/dashboard", status_code=303)
    return _page(request, "login.html", mode="register", open=settings.allow_registration)


@router.get("/dashboard")
def dashboard(request: Request):
    user = user_from_request(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return _page(request, "dashboard.html", user=user, tool_count=len(REGISTRY))


@router.get("/reports")
def reports(request: Request):
    user = user_from_request(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return _page(request, "reports.html", user=user)
