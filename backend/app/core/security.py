import io
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
import bcrypt
import pyotp
import qrcode
from app.core.config import settings

def hash_password(password: str) -> str:
    """Gera hash seguro bcrypt com salt para a senha do operador."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica se a senha em texto plano confere com o hash bcrypt gravado."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Gera token JWT assinado com expiração segura."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodifica e valida assinatura e expiração do token JWT."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

def generate_mfa_secret() -> str:
    """Gera chave secreta base32 para TOTP (Google Authenticator / Microsoft Authenticator)."""
    return pyotp.random_base32()

def get_mfa_provisioning_uri(secret: str, email: str) -> str:
    """Gera a URI padrão otpauth:// para emparelhamento de autenticadores."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=settings.MFA_ISSUER_NAME)

def verify_totp_code(secret: str, code: str) -> bool:
    """Valida o código TOTP de 6 dígitos fornecido com tolerância temporal de 30s."""
    if not secret or not code:
        return False
    # Limpa espaços e formata
    cleaned_code = code.replace(" ", "").replace("-", "").strip()
    totp = pyotp.TOTP(secret)
    # valid_window=1 permite uma janela de tolerância de até 30s antes ou depois
    return totp.verify(cleaned_code, valid_window=1)

def generate_qr_code_base64(uri: str) -> str:
    """Gera imagem PNG em base64 do QR Code para escaneamento no aplicativo móvel."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#00FF41", back_color="#07090E")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    b64_str = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64_str}"
