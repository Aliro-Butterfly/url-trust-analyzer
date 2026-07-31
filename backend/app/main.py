import hashlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, status

_LOG_FILE = Path(__file__).resolve().parent.parent.parent / "backend_api.log"
logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)s:%(name)s:%(message)s",
    handlers=[
        logging.FileHandler(str(_LOG_FILE), mode="a"),
        logging.StreamHandler(),
    ],
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .auth import AUTH_COOKIE_NAME, create_access_token, decode_access_token, hash_password, verify_password
from .database import (
    create_user,
    fetch_api_keys,
    fetch_history,
    get_user_by_username,
    initialize_database,
    save_analysis,
    save_api_key,
)
from .schemas import (
    AnalysisResponse,
    AnalyzeRequest,
    ApiKeysStatus,
    ApiKeysUpdate,
    AuthResponse,
    HistoryItem,
    LoginRequest,
    UserCreate,
)
from .admin_config import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    get_full_config,
    update_config,
)
from .services.analyzer import AnalyzerService


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(title="URL Trust Analyzer - Backend", version="0.1.0", lifespan=lifespan)
analyzer_service = AnalyzerService()

ADMIN_COOKIE_NAME = "admin_token"


def get_current_user(auth_token: str | None = Cookie(default=None)) -> dict[str, Any]:
    if not auth_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    payload = decode_access_token(auth_token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
        )

    user = get_user_by_username(payload["sub"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
        )
    return user


def create_auth_response(username: str) -> JSONResponse:
    access_token = create_access_token(username)
    response = JSONResponse({"username": username})
    response.set_cookie(
        AUTH_COOKIE_NAME,
        access_token,
        httponly=True,
        samesite="strict",
        secure=False,
        max_age=30 * 60,
        path="/",
    )
    return response


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.post("/auth/register", response_model=AuthResponse)
def register(user: UserCreate) -> JSONResponse:
    if get_user_by_username(user.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists.",
        )

    create_user(user.username, hash_password(user.password))
    return create_auth_response(user.username)


@app.post("/auth/login", response_model=AuthResponse)
def login(user: LoginRequest) -> JSONResponse:
    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        pass
    elif user.username == ADMIN_USERNAME and user.password == ADMIN_PASSWORD:
        token = hashlib.sha256(f"{ADMIN_USERNAME}:{ADMIN_PASSWORD}".encode()).hexdigest()
        response = JSONResponse({"username": user.username, "is_admin": True})
        response.set_cookie(AUTH_COOKIE_NAME, create_access_token(user.username), httponly=True, samesite="strict", secure=False, max_age=30 * 60, path="/")
        response.set_cookie(ADMIN_COOKIE_NAME, token, httponly=True, samesite="strict", secure=False, max_age=3600, path="/")
        return response

    stored_user = get_user_by_username(user.username)
    if not stored_user or not verify_password(user.password, stored_user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
        )

    return create_auth_response(user.username)


@app.post("/auth/logout")
def logout() -> JSONResponse:
    response = JSONResponse({"detail": "Logged out."})
    response.delete_cookie(AUTH_COOKIE_NAME, path="/")
    return response


@app.get("/auth/me", response_model=AuthResponse)
def me(current_user: dict[str, Any] = Depends(get_current_user)) -> AuthResponse:
    is_admin = current_user["username"] == ADMIN_USERNAME
    return {"username": current_user["username"], "is_admin": is_admin}


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze(
    request: AnalyzeRequest, current_user: dict[str, Any] = Depends(get_current_user)
) -> AnalysisResponse:
    api_keys = fetch_api_keys(current_user["username"])
    result = await analyzer_service.analyze(request, api_keys=api_keys)
    save_analysis(result.model_dump(), current_user["username"])
    return result


@app.get("/auth/api-keys", response_model=ApiKeysStatus)
def get_api_keys(current_user: dict[str, Any] = Depends(get_current_user)) -> ApiKeysStatus:
    api_keys = fetch_api_keys(current_user["username"])
    return ApiKeysStatus(
        has_urlscan=bool(api_keys.get("URLSCAN")),
        has_google_safebrowsing=bool(api_keys.get("GOOGLE_SAFEBROWSING")),
        has_virustotal=bool(api_keys.get("VIRUSTOTAL")),
        has_abuseipdb=bool(api_keys.get("ABUSEIPDB")),
    )


@app.put("/auth/api-keys", response_model=ApiKeysStatus)
def update_api_keys(
    update: ApiKeysUpdate, current_user: dict[str, Any] = Depends(get_current_user)
) -> ApiKeysStatus:
    save_api_key(current_user["username"], "URLSCAN", update.urlscan)
    save_api_key(current_user["username"], "GOOGLE_SAFEBROWSING", update.google_safebrowsing)
    save_api_key(current_user["username"], "VIRUSTOTAL", update.virustotal)
    save_api_key(current_user["username"], "ABUSEIPDB", update.abuseipdb)
    return get_api_keys(current_user)


@app.get("/history", response_model=list[HistoryItem])
def history(current_user: dict[str, Any] = Depends(get_current_user)) -> list[HistoryItem]:
    return fetch_history(username=current_user["username"])


def require_admin(request: Request):
    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Admin login not configured.")
    token = request.cookies.get(ADMIN_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin authentication required.")
    expected = hashlib.sha256(f"{ADMIN_USERNAME}:{ADMIN_PASSWORD}".encode()).hexdigest()
    if token != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin token.")
    return True


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class AdminConfigUpdate(BaseModel):
    dimension_weights: dict[str, int] | None = None
    providers: dict[str, dict] | None = None


@app.post("/admin/login")
def admin_login(body: AdminLoginRequest):
    if body.username != ADMIN_USERNAME or body.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect admin credentials.")
    token = hashlib.sha256(f"{ADMIN_USERNAME}:{ADMIN_PASSWORD}".encode()).hexdigest()
    response = JSONResponse({"admin": True})
    response.set_cookie(ADMIN_COOKIE_NAME, token, httponly=True, samesite="strict", secure=False, max_age=3600, path="/")
    return response


@app.post("/admin/logout")
def admin_logout():
    response = JSONResponse({"detail": "Admin logged out."})
    response.delete_cookie(ADMIN_COOKIE_NAME, path="/")
    return response


@app.get("/admin/config")
def admin_get_config(_=Depends(require_admin)):
    return get_full_config()


@app.put("/admin/config")
def admin_update_config(body: AdminConfigUpdate, _=Depends(require_admin)):
    return update_config(
        dimension_weights=body.dimension_weights,
        providers=body.providers,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
