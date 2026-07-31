from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from fastapi import Cookie, Depends, FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .admin_config import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    get_full_config,
    update_config,
)
from .auth import AUTH_COOKIE_NAME, create_access_token, decode_access_token, hash_password, verify_password
from .config import (
    ADMIN_COOKIE_NAME,
    ADMIN_TOKEN_EXPIRE_SECONDS,
    APP_VERSION,
    COOKIE_SECURE,
    LOG_FILE,
    LOG_LEVEL,
    RATE_LIMIT_ADMIN_MAX,
    RATE_LIMIT_ADMIN_WINDOW,
    RATE_LIMIT_AUTH_MAX,
    RATE_LIMIT_AUTH_WINDOW,
)
from .database import (
    create_user,
    fetch_api_keys,
    fetch_history,
    get_user_by_username,
    initialize_database,
    save_analysis,
    save_api_key,
)
from .exceptions import (
    AppError,
    AuthenticationError,
    AuthorizationError,
    RateLimitExceeded,
)
from .logging_config import setup_logging
from .rate_limit import RateLimiter
from .schemas import (
    AnalysisResponse,
    AnalyzeRequest,
    ApiKeysStatus,
    ApiKeysUpdate,
    ApiResponse,
    AuthResponse,
    HistoryItem,
    LoginRequest,
    ResponseMetadata,
    UserCreate,
)
from .services.analyzer import AnalyzerService

setup_logging(log_file=LOG_FILE, level=LOG_LEVEL)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="URL Trust Analyzer",
    version=APP_VERSION,
    lifespan=lifespan,
    # Never expose internal error details in production
    openapi_url="/openapi.json",
)

analyzer_service = AnalyzerService()
_auth_limiter = RateLimiter(max_requests=RATE_LIMIT_AUTH_MAX, window_seconds=RATE_LIMIT_AUTH_WINDOW)
_admin_limiter = RateLimiter(max_requests=RATE_LIMIT_ADMIN_MAX, window_seconds=RATE_LIMIT_ADMIN_WINDOW)


# ── Global exception handlers ─────────────────────────────────────────────────

@app.exception_handler(AppError)
async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=ApiResponse.error(exc.message, exc.details).model_dump(),
    )


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content=ApiResponse.error(exc.message).model_dump(),
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = [f"{' -> '.join(str(l) for l in e['loc'])}: {e['msg']}" for e in exc.errors()]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ApiResponse.error("Validation error.", errors).model_dump(),
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ApiResponse.error("An unexpected error occurred. Please try again later.").model_dump(),
    )


# ── Auth helpers ──────────────────────────────────────────────────────────────

def get_current_user(auth_token: str | None = Cookie(default=None)) -> dict[str, Any]:
    if not auth_token:
        raise AuthenticationError("Authentication required.")
    payload = decode_access_token(auth_token)
    if not payload or "sub" not in payload:
        raise AuthenticationError("Invalid or expired authentication token.")
    user = get_user_by_username(payload["sub"])
    if not user:
        raise AuthenticationError("User not found.")
    return user


def require_admin(request: Request) -> bool:
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    if not token:
        raise AuthorizationError("Admin authentication required.")
    payload = decode_access_token(token)
    if not payload or not payload.get("is_admin"):
        raise AuthorizationError("Invalid or expired admin token.")
    return True


def _make_auth_cookie_response(username: str) -> JSONResponse:
    access_token = create_access_token(username)
    response = JSONResponse(
        ApiResponse.ok(AuthResponse(username=username).model_dump()).model_dump()
    )
    response.set_cookie(
        AUTH_COOKIE_NAME, access_token,
        httponly=True, samesite="strict", secure=COOKIE_SECURE,
        max_age=30 * 60, path="/",
    )
    return response


# ── Request bodies ────────────────────────────────────────────────────────────

@dataclass
class AdminLoginRequest:
    username: str
    password: str


@dataclass
class AdminConfigUpdate:
    dimension_weights: dict[str, int] | None = None
    providers: dict[str, dict] | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return ApiResponse.ok({"status": "ok", "version": APP_VERSION}, "Service operational.")


@app.post("/auth/register")
def register(user: UserCreate, _: None = Depends(_auth_limiter)):
    if get_user_by_username(user.username):
        from .exceptions import ValidationError
        raise ValidationError("Username already exists.")
    create_user(user.username, hash_password(user.password))
    return _make_auth_cookie_response(user.username)


@app.post("/auth/login")
def login(user: LoginRequest, _: None = Depends(_auth_limiter)):
    if ADMIN_USERNAME and ADMIN_PASSWORD and user.username == ADMIN_USERNAME and user.password == ADMIN_PASSWORD:
        admin_token = create_access_token(user.username, extra_claims={"is_admin": True})
        response = JSONResponse(
            ApiResponse.ok(
                AuthResponse(username=user.username, is_admin=True).model_dump()
            ).model_dump()
        )
        response.set_cookie(AUTH_COOKIE_NAME, create_access_token(user.username), httponly=True, samesite="strict", secure=COOKIE_SECURE, max_age=30 * 60, path="/")
        response.set_cookie(ADMIN_COOKIE_NAME, admin_token, httponly=True, samesite="strict", secure=COOKIE_SECURE, max_age=ADMIN_TOKEN_EXPIRE_SECONDS, path="/")
        return response

    stored_user = get_user_by_username(user.username)
    if not stored_user or not verify_password(user.password, stored_user["password_hash"]):
        raise AuthenticationError("Incorrect username or password.")
    return _make_auth_cookie_response(user.username)


@app.post("/auth/logout")
def logout():
    response = JSONResponse(ApiResponse.ok(None, "Logged out.").model_dump())
    response.delete_cookie(AUTH_COOKIE_NAME, path="/")
    return response


@app.get("/auth/me")
def me(current_user: dict[str, Any] = Depends(get_current_user)):
    is_admin = current_user["username"] == ADMIN_USERNAME
    return ApiResponse.ok(AuthResponse(username=current_user["username"], is_admin=is_admin).model_dump())


@app.post("/analyze")
async def analyze(request: AnalyzeRequest, current_user: dict[str, Any] = Depends(get_current_user)):
    api_keys = fetch_api_keys(current_user["username"])
    result = await analyzer_service.analyze(request, api_keys=api_keys or None)

    save_analysis(
        result.response.model_dump(),
        current_user["username"],
        processing_time_ms=result.processing_time_ms,
        providers_count=result.providers_count,
        algo_version=result.algo_version,
        from_cache=result.from_cache,
    )

    return ApiResponse.ok(
        result.response,
        processing_time_ms=result.processing_time_ms,
        provider_count=result.providers_count,
        cached=result.from_cache,
    )


@app.get("/auth/api-keys")
def get_api_keys(current_user: dict[str, Any] = Depends(get_current_user)):
    keys = fetch_api_keys(current_user["username"])
    return ApiResponse.ok(ApiKeysStatus(
        has_urlscan=bool(keys.get("URLSCAN")),
        has_google_safebrowsing=bool(keys.get("GOOGLE_SAFEBROWSING")),
        has_virustotal=bool(keys.get("VIRUSTOTAL")),
        has_abuseipdb=bool(keys.get("ABUSEIPDB")),
    ))


@app.put("/auth/api-keys")
def update_api_keys(update: ApiKeysUpdate, current_user: dict[str, Any] = Depends(get_current_user)):
    save_api_key(current_user["username"], "URLSCAN", update.urlscan)
    save_api_key(current_user["username"], "GOOGLE_SAFEBROWSING", update.google_safebrowsing)
    save_api_key(current_user["username"], "VIRUSTOTAL", update.virustotal)
    save_api_key(current_user["username"], "ABUSEIPDB", update.abuseipdb)
    keys = fetch_api_keys(current_user["username"])
    return ApiResponse.ok(ApiKeysStatus(
        has_urlscan=bool(keys.get("URLSCAN")),
        has_google_safebrowsing=bool(keys.get("GOOGLE_SAFEBROWSING")),
        has_virustotal=bool(keys.get("VIRUSTOTAL")),
        has_abuseipdb=bool(keys.get("ABUSEIPDB")),
    ))


@app.get("/history")
def history(current_user: dict[str, Any] = Depends(get_current_user)):
    items = fetch_history(username=current_user["username"])
    return ApiResponse.ok(items, provider_count=None)


@app.post("/admin/login")
def admin_login(body: AdminLoginRequest, _: None = Depends(_admin_limiter)):
    if body.username != ADMIN_USERNAME or body.password != ADMIN_PASSWORD:
        raise AuthenticationError("Incorrect admin credentials.")
    admin_token = create_access_token(body.username, extra_claims={"is_admin": True})
    response = JSONResponse(ApiResponse.ok({"admin": True}).model_dump())
    response.set_cookie(ADMIN_COOKIE_NAME, admin_token, httponly=True, samesite="strict", secure=COOKIE_SECURE, max_age=ADMIN_TOKEN_EXPIRE_SECONDS, path="/")
    return response


@app.post("/admin/logout")
def admin_logout():
    response = JSONResponse(ApiResponse.ok(None, "Admin logged out.").model_dump())
    response.delete_cookie(ADMIN_COOKIE_NAME, path="/")
    return response


@app.get("/admin/config")
def admin_get_config(_=Depends(require_admin)):
    return ApiResponse.ok(get_full_config())


@app.put("/admin/config")
def admin_update_config(body: AdminConfigUpdate, _=Depends(require_admin)):
    try:
        return ApiResponse.ok(update_config(
            dimension_weights=body.dimension_weights,
            providers=body.providers,
        ))
    except ValueError as exc:
        from .exceptions import ValidationError
        raise ValidationError(str(exc)) from exc


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)