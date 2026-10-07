import base64
import io
import time

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import audit
from app.auth.schemas import (
    ChangePasswordRequest, CodeRequest, DisableRequest, LoginRequest, LoginResponse, MfaLoginRequest,
)
from app.auth.security import (
    create_access_token,
    create_mfa_token,
    decode_mfa_token,
    get_current_user,
    hash_password,
    verify_password,
)
from app.config import settings
from app.db.base import get_session
from app.db.models import User

router = APIRouter(prefix="/auth", tags=["auth"])

# Brute-force guard for the 6-digit code step: 5 wrong codes per user locks that user's 2FA
# login for 5 minutes. In-memory (resets on restart) - fine for a single-process deployment.
_MAX_FAILS = 5
_LOCK_SECS = 300
_fails: dict[str, tuple[int, float]] = {}


def _check_not_locked(user_id: str) -> None:
    count, since = _fails.get(user_id, (0, 0.0))
    if count >= _MAX_FAILS:
        if time.time() - since < _LOCK_SECS:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many wrong codes - try again in a few minutes")
        _fails.pop(user_id, None)


def _record_fail(user_id: str) -> None:
    count, since = _fails.get(user_id, (0, time.time()))
    _fails[user_id] = (count + 1, since if count else time.time())


def _verify_code(user: User, code: str) -> bool:
    return bool(user.totp_secret) and pyotp.TOTP(user.totp_secret).verify(code.strip().replace(" ", ""), valid_window=1)


def _session_response(user: User) -> LoginResponse:
    return LoginResponse(
        access_token=create_access_token(user), role=user.role, must_change_password=user.must_change_password,
    )


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    if user.totp_enabled:
        return LoginResponse(mfa_required=True, mfa_token=create_mfa_token(user))
    return _session_response(user)


@router.post("/2fa/login", response_model=LoginResponse)
async def login_with_code(body: MfaLoginRequest, session: AsyncSession = Depends(get_session)):
    payload = decode_mfa_token(body.mfa_token)
    user = await session.get(User, payload["sub"])
    if user is None or not user.totp_enabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid sign-in token")
    _check_not_locked(str(user.id))
    if not _verify_code(user, body.code):
        _record_fail(str(user.id))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect code")
    _fails.pop(str(user.id), None)
    return _session_response(user)


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    await session.commit()
    return {"ok": True}


# ---------- 2FA management (the logged-in user's own account) ----------

@router.get("/2fa/status")
async def two_factor_status(user: User = Depends(get_current_user)):
    return {"enabled": user.totp_enabled}


@router.post("/2fa/setup")
async def two_factor_setup(user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    """Generates a fresh secret + QR code. 2FA is NOT enforced until /2fa/enable confirms a code."""
    if user.totp_enabled:
        raise HTTPException(status_code=400, detail="Two-factor authentication is already enabled")
    user.totp_secret = pyotp.random_base32()
    await session.commit()
    uri = pyotp.TOTP(user.totp_secret).provisioning_uri(name=user.email, issuer_name=settings.app_name)
    buf = io.BytesIO()
    qrcode.make(uri, box_size=6, border=2).save(buf, format="PNG")
    return {
        "secret": user.totp_secret, "otpauth_uri": uri,
        "qr_png": "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode(),
    }


@router.post("/2fa/enable")
async def two_factor_enable(
    body: CodeRequest, user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session),
):
    if user.totp_enabled:
        raise HTTPException(status_code=400, detail="Two-factor authentication is already enabled")
    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="Start setup first")
    if not _verify_code(user, body.code):
        raise HTTPException(status_code=400, detail="That code is not correct - check your authenticator app and try again")
    user.totp_enabled = True
    await audit.log(session, user.id, "user.2fa_enabled", "user", str(user.id), {})
    await session.commit()
    return {"enabled": True}


@router.post("/2fa/disable")
async def two_factor_disable(
    body: DisableRequest, user: User = Depends(get_current_user), session: AsyncSession = Depends(get_session),
):
    """Needs both the password and a current code, so a stolen session alone can't turn 2FA off."""
    if not user.totp_enabled:
        raise HTTPException(status_code=400, detail="Two-factor authentication is not enabled")
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Password is incorrect")
    _check_not_locked(str(user.id))
    if not _verify_code(user, body.code):
        _record_fail(str(user.id))
        raise HTTPException(status_code=401, detail="Incorrect code")
    user.totp_enabled = False
    user.totp_secret = None
    await audit.log(session, user.id, "user.2fa_disabled", "user", str(user.id), {})
    await session.commit()
    return {"enabled": False}
