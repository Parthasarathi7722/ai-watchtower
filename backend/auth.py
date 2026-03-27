"""
Authentication module for AI Watchtower.

Supported modes (AUTH_MODE env var):
  local           — credentials from env vars  (default, great for local dev)
  secrets_manager — credentials stored in AWS Secrets Manager  (recommended for production)
  cognito         — [future] AWS Cognito user pool with SAML / hosted UI
  okta            — [future] Okta OIDC / SAML federation

Credential format in Secrets Manager (JSON object, multiple users supported):
  {"admin": "$2b$12$<bcrypt-hash>", "analyst": "$2b$12$<bcrypt-hash>"}

Generate a bcrypt hash:
  python3 -c "from passlib.context import CryptContext; print(CryptContext(['bcrypt']).hash('your-password'))"

IAM note — Bedrock access:
  When running on EC2 / ECS / Lambda, boto3 uses the attached IAM role automatically.
  No AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY needed in that case.
  The _boto3_kwargs() helper in galactus.py already handles this fall-through.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt as pyjwt
from fastapi import Request, status
from fastapi.responses import JSONResponse, RedirectResponse

from config import settings

logger = logging.getLogger(__name__)

# Paths that never require a valid token
_PUBLIC_PATHS = frozenset({
    "/login",
    "/auth/login",
    "/auth/logout",
    "/auth/status",
    "/health",
    "/favicon.ico",
})


# ── Credential loading ────────────────────────────────────────────────────────

def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _check(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def _credentials_local() -> dict[str, str]:
    """
    Returns {username: bcrypt_hash} from env vars.
    ADMIN_PASSWORD_HASH takes priority over plaintext ADMIN_PASSWORD.
    """
    username = settings.ADMIN_USERNAME
    if settings.ADMIN_PASSWORD_HASH:
        return {username: settings.ADMIN_PASSWORD_HASH}
    if settings.ADMIN_PASSWORD:
        logger.warning(
            "AUTH: Using plaintext ADMIN_PASSWORD — set ADMIN_PASSWORD_HASH for production"
        )
        return {username: _hash(settings.ADMIN_PASSWORD)}
    raise RuntimeError(
        "No credentials configured. Set ADMIN_PASSWORD_HASH (or ADMIN_PASSWORD for dev) in .env"
    )


def _credentials_secrets_manager() -> dict[str, str]:
    """
    Loads {username: bcrypt_hash} from AWS Secrets Manager.
    Falls back to local credentials if the secret is unreachable.

    Expects a JSON secret like:
        {"admin": "$2b$12$...", "analyst": "$2b$12$..."}
    """
    try:
        import boto3
        client = boto3.client("secretsmanager", region_name=settings.AWS_REGION)
        resp = client.get_secret_value(SecretId=settings.AUTH_SECRET_NAME)
        creds: dict[str, str] = json.loads(resp["SecretString"])
        logger.info("AUTH: Loaded %d user(s) from Secrets Manager (%s)",
                    len(creds), settings.AUTH_SECRET_NAME)
        return creds
    except Exception as exc:
        logger.warning(
            "AUTH: Secrets Manager unavailable (%s) — falling back to local credentials", exc
        )
        return _credentials_local()


def load_credentials() -> dict[str, str]:
    """Load credentials for the configured AUTH_MODE."""
    mode = settings.AUTH_MODE.lower()
    if mode == "secrets_manager":
        if not settings.AUTH_SECRET_NAME:
            logger.warning("AUTH: AUTH_SECRET_NAME not set — falling back to local")
            return _credentials_local()
        return _credentials_secrets_manager()
    elif mode in ("cognito", "okta"):
        # SSO modes: credential check is handled by the IdP redirect, not by this function.
        # Return local creds as fallback so the platform still works while SSO is being set up.
        logger.info(
            "AUTH: Mode '%s' (SSO) — not yet fully implemented, using local fallback", mode
        )
        return _credentials_local()
    else:  # "local"
        return _credentials_local()


def verify_password(username: str, password: str, db=None) -> bool:
    """
    Verify username/password.
    If a DB session is supplied (normal operation), checks the watchtower_users table.
    Falls back to in-memory credentials (useful before DB is ready).
    """
    if db is not None:
        try:
            from models import WatchtowerUser
            user = (
                db.query(WatchtowerUser)
                .filter(WatchtowerUser.username == username, WatchtowerUser.is_active == True)
                .first()
            )
            if not user:
                return False
            ok = _check(password, user.password_hash)
            if ok:
                from datetime import datetime, timezone
                user.last_login = datetime.now(timezone.utc)
                db.commit()
            return ok
        except Exception as exc:
            logger.error("AUTH: DB verification failed: %s", exc)
            return False

    # Fallback path (no DB session — e.g. during startup)
    try:
        creds = load_credentials()
        hashed = creds.get(username)
        return _check(password, hashed) if hashed else False
    except Exception as exc:
        logger.error("AUTH: credential verification failed: %s", exc)
        return False


# ── User CRUD (used by settings API) ─────────────────────────────────────────

def list_users(db) -> list[dict]:
    from models import WatchtowerUser
    users = db.query(WatchtowerUser).order_by(WatchtowerUser.created_at).all()
    return [
        {
            "username": u.username,
            "role": u.role,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "last_login": u.last_login.isoformat() if u.last_login else None,
        }
        for u in users
    ]


def create_user(username: str, password: str, role: str, db) -> dict:
    from models import WatchtowerUser
    if db.query(WatchtowerUser).filter(WatchtowerUser.username == username).first():
        raise ValueError(f"User '{username}' already exists")
    user = WatchtowerUser(username=username, password_hash=_hash(password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"username": user.username, "role": user.role, "created_at": user.created_at.isoformat()}


def update_password(username: str, new_password: str, db) -> None:
    from models import WatchtowerUser
    user = db.query(WatchtowerUser).filter(WatchtowerUser.username == username).first()
    if not user:
        raise ValueError(f"User '{username}' not found")
    user.password_hash = _hash(new_password)
    db.commit()


def delete_user(username: str, db) -> None:
    from models import WatchtowerUser
    # Prevent deleting the last active admin
    active_admins = (
        db.query(WatchtowerUser)
        .filter(WatchtowerUser.role == "admin", WatchtowerUser.is_active == True)
        .count()
    )
    user = db.query(WatchtowerUser).filter(WatchtowerUser.username == username).first()
    if not user:
        raise ValueError(f"User '{username}' not found")
    if user.role == "admin" and active_admins <= 1:
        raise ValueError("Cannot delete the last active admin user")
    user.is_active = False
    db.commit()


# ── JWT ───────────────────────────────────────────────────────────────────────

def create_token(username: str) -> str:
    """Create a signed HS256 JWT for the given username."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES),
    }
    return pyjwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> Optional[str]:
    """
    Validate JWT signature and expiry.
    Returns the username (sub claim) on success, None on any failure.
    """
    try:
        payload = pyjwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload.get("sub")
    except pyjwt.ExpiredSignatureError:
        return None
    except pyjwt.PyJWTError:
        return None


# ── Cookie helpers ────────────────────────────────────────────────────────────

COOKIE_NAME = "wt_token"
COOKIE_MAX_AGE = settings.JWT_EXPIRE_MINUTES * 60


def set_auth_cookie(response, token: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,                              # not accessible via JS — XSS safe
        samesite="lax",                             # CSRF protection
        max_age=COOKIE_MAX_AGE,
        secure=(settings.APP_ENV == "production"),  # HTTPS-only in production
    )


def clear_auth_cookie(response) -> None:
    response.delete_cookie(COOKIE_NAME, samesite="lax")


# ── Token extraction ──────────────────────────────────────────────────────────

def _extract_token(request: Request) -> Optional[str]:
    """
    Extract JWT from:
      1. httpOnly cookie  wt_token      (browser UI)
      2. Authorization: Bearer <token>  (API clients, curl, scripts)
    """
    token = request.cookies.get(COOKIE_NAME)
    if token:
        return token
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


# ── Middleware ────────────────────────────────────────────────────────────────

async def auth_middleware(request: Request, call_next):
    """
    HTTP middleware — enforces authentication on all non-public paths.

    - Browser requests (Accept: text/html) with no valid token → redirect /login
    - API / JSON requests with no valid token → 401 JSON
    """
    if request.url.path in _PUBLIC_PATHS:
        return await call_next(request)

    token = _extract_token(request)
    if token and decode_token(token):
        return await call_next(request)

    accepts_html = "text/html" in request.headers.get("accept", "")
    if accepts_html:
        return RedirectResponse(url="/login", status_code=302)

    return JSONResponse(
        {"detail": "Not authenticated"},
        status_code=status.HTTP_401_UNAUTHORIZED,
    )


# ── Auth mode metadata (for login page) ──────────────────────────────────────

def auth_status() -> dict:
    """Returns metadata consumed by the login page UI."""
    mode = settings.AUTH_MODE.lower()
    return {
        "auth_mode": mode,
        "sso_available": mode in ("cognito", "okta"),
        "sso_provider": mode if mode in ("cognito", "okta") else None,
        "secrets_manager": mode == "secrets_manager",
        "secret_name": settings.AUTH_SECRET_NAME if mode == "secrets_manager" else None,
    }
