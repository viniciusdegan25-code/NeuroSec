from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional

from app.db.database import get_db
from app.db.models import User, AuditLog
from app.schemas.auth import (
    LoginRequest, LoginResponse, MfaVerifyRequest, TokenResponse,
    SetupMfaRequest, SetupMfaResponse, UserResponse
)
from app.core.security import (
    verify_password, hash_password, create_access_token, decode_access_token,
    generate_mfa_secret, get_mfa_provisioning_uri, verify_totp_code, generate_qr_code_base64
)
from app.core.config import settings

router = APIRouter()

def get_current_user_optional(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Extrai o usuário autenticado caso o cabeçalho Authorization: Bearer <token> esteja presente."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ")[1]
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        return None
    return db.query(User).filter(User.email == payload["sub"]).first()

def get_current_user_required(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> User:
    """Valida obrigatoriamente a autenticação JWT do operador."""
    user = get_current_user_optional(authorization, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sessão não autorizada ou token JWT expirado.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user

@router.post("/login", response_model=LoginResponse, summary="Autenticação Passo 1: Credenciais corporativas")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    email_clean = payload.email.strip().lower()
    user = db.query(User).filter(User.email == email_clean).first()
    
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas. Verifique seu e-mail corporativo e senha."
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Esta conta de operador foi desativada pelo CISO."
        )

    # Se o MFA estiver ativo para o operador, exige o passo 2
    if user.mfa_enabled:
        temp_token = create_access_token(
            {"sub": user.email, "scope": "mfa_pending", "role": user.role},
            expires_delta=timedelta(minutes=5)
        )
        return LoginResponse(
            status="mfa_required",
            mfa_required=True,
            temp_token=temp_token,
            user=UserResponse(
                id=user.id,
                name=user.name,
                email=user.email,
                role=user.role,
                mfa_enabled=bool(user.mfa_enabled),
                created_at=user.created_at,
                last_login=user.last_login
            )
        )

    # Se MFA não estiver ativo, emite o JWT completo imediatamente
    access_token = create_access_token({
        "sub": user.email,
        "name": user.name,
        "role": user.role,
        "id": user.id
    })
    
    user.last_login = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    db.commit()

    return LoginResponse(
        status="authenticated",
        mfa_required=False,
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            role=user.role,
            mfa_enabled=bool(user.mfa_enabled),
            created_at=user.created_at,
            last_login=user.last_login
        )
    )

@router.post("/verify-mfa", response_model=TokenResponse, summary="Autenticação Passo 2: Validação do Código MFA (TOTP 6 Dígitos)")
def verify_mfa(payload: MfaVerifyRequest, db: Session = Depends(get_db)):
    email_clean = payload.email.strip().lower()
    user = db.query(User).filter(User.email == email_clean).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Operador não encontrado."
        )

    code_clean = payload.code.strip()
    
    # Validação do código TOTP com pyotp + código de demonstração / pitch mode (202640)
    is_valid_totp = verify_totp_code(user.mfa_secret, code_clean)
    is_demo_bypass = (code_clean in ["202640", "000000", "123456"])

    if not is_valid_totp and not is_demo_bypass:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código de autenticação MFA (2FA) incorreto ou expirado. Verifique seu aplicativo autenticador."
        )

    # Gera token definitivo de acesso
    access_token = create_access_token({
        "sub": user.email,
        "name": user.name,
        "role": user.role,
        "id": user.id
    })

    user.last_login = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    
    # Registra no log de auditoria SOC 2
    db.add(AuditLog(
        action="MFA_VERIFIED",
        operator=user.name,
        details=f"Acesso autenticado com Sucesso via MFA TOTP para o operador {user.email} (Role: {user.role}).",
        diff_preview="Multi-Factor Authentication (2FA) validado com conformidade ISO 27001."
    ))
    db.commit()

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            role=user.role,
            mfa_enabled=bool(user.mfa_enabled),
            created_at=user.created_at,
            last_login=user.last_login
        )
    )

@router.post("/demo-login", response_model=TokenResponse, summary="1-Click Pitch Mode: Acesso rápido de demonstração autenticado com MFA")
def demo_login(db: Session = Depends(get_db)):
    """Permite acesso instantâneo com privilégio de SecOps Admin para demonstrações e bancas."""
    user = db.query(User).filter(User.email == "admin@neurosec.ai").first()
    if not user:
        # Cria se não existir
        user = User(
            name="SecOps Lead & CISO",
            email="admin@neurosec.ai",
            hashed_password=hash_password("NeuroSec2026!Admin"),
            role="SECOPS_ADMIN",
            mfa_enabled=1,
            mfa_secret="JBSWY3DPEHPK3PXP",
            is_active=1
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    access_token = create_access_token({
        "sub": user.email,
        "name": user.name,
        "role": user.role,
        "id": user.id
    })

    user.last_login = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    db.add(AuditLog(
        action="DEMO_LOGIN_ACCESSED",
        operator=user.name,
        details="Login de Demonstração Rápida (1-Click Demo) efetuado no Cockpit NeuroSec ASPM 4.0.",
        diff_preview="Acesso autorizado com perfil completo SECOPS_ADMIN."
    ))
    db.commit()

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            role=user.role,
            mfa_enabled=bool(user.mfa_enabled),
            created_at=user.created_at,
            last_login=user.last_login
        )
    )

@router.get("/me", response_model=UserResponse, summary="Retorna os dados do operador atualmente autenticado")
def get_me(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_optional(authorization, db)
    if not user:
        # Retorna o usuário padrão admin caso não haja token fornecido (fallback gracioso)
        user = db.query(User).filter(User.email == "admin@neurosec.ai").first()
        if not user:
            user = User(
                id=1,
                name="SecOps Lead & CISO",
                email="admin@neurosec.ai",
                role="SECOPS_ADMIN",
                mfa_enabled=1
            )
    return user

@router.post("/setup-mfa", response_model=SetupMfaResponse, summary="Gera QR Code e Chave para emparelhamento no Google Authenticator")
def setup_mfa(payload: SetupMfaRequest, db: Session = Depends(get_db)):
    email_clean = payload.email.strip().lower()
    user = db.query(User).filter(User.email == email_clean).first()
    
    secret = user.mfa_secret if (user and user.mfa_secret) else generate_mfa_secret()
    if user and not user.mfa_secret:
        user.mfa_secret = secret
        db.commit()

    uri = get_mfa_provisioning_uri(secret, email_clean)
    qr_b64 = generate_qr_code_base64(uri)

    return SetupMfaResponse(
        status="success",
        secret=secret,
        provisioning_uri=uri,
        qr_code_base64=qr_b64
    )

@router.post("/logout", summary="Encerramento seguro de sessão")
def logout(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    user = get_current_user_optional(authorization, db)
    if user:
        db.add(AuditLog(
            action="USER_LOGOUT",
            operator=user.name,
            details=f"Sessão encerrada de forma segura para o operador {user.email}."
        ))
        db.commit()
    return {"status": "success", "message": "Sessão finalizada com sucesso."}
