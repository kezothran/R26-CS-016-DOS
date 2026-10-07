from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str = ""
    role: str = ""
    must_change_password: bool = False
    # Set when the account has 2FA on: the client must then call /auth/2fa/login with this token + a code.
    mfa_required: bool = False
    mfa_token: str | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class MfaLoginRequest(BaseModel):
    mfa_token: str
    code: str


class CodeRequest(BaseModel):
    code: str


class DisableRequest(BaseModel):
    password: str
    code: str
