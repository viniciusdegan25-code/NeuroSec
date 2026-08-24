from pydantic import BaseModel, EmailStr
from typing import Optional

class LoginRequest(BaseModel):
    email: str
    password: str

class MfaVerifyRequest(BaseModel):
    email: str
    code: str
    temp_token: Optional[str] = None

class SetupMfaRequest(BaseModel):
    email: str

class SetupMfaResponse(BaseModel):
    status: str
    secret: str
    provisioning_uri: str
    qr_code_base64: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "UserResponse"

class LoginResponse(BaseModel):
    status: str
    mfa_required: bool
    temp_token: Optional[str] = None
    access_token: Optional[str] = None
    token_type: Optional[str] = "bearer"
    expires_in: Optional[int] = None
    user: Optional["UserResponse"] = None

class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    mfa_enabled: bool
    created_at: Optional[str] = None
    last_login: Optional[str] = None

    class Config:
        from_attributes = True

LoginResponse.model_rebuild()
TokenResponse.model_rebuild()
