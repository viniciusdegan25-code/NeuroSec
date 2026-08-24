import os
from typing import List
from dotenv import load_dotenv

# Carrega arquivo .env local caso exista
load_dotenv()

try:
    from pydantic_settings import BaseSettings
    class SettingsBase(BaseSettings):
        class Config:
            case_sensitive = True
            env_file = ".env"
            extra = "allow"
except ImportError:
    from pydantic import BaseModel
    class SettingsBase(BaseModel):
        pass

class Settings(SettingsBase):
    PROJECT_NAME: str = "NeuroSec ASPM 4.5"
    VERSION: str = "4.5.0"
    API_V1_STR: str = "/api/v1"
    
    # JWT & Authentication Security
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "neurosec_super_secret_jwt_key_2026_enterprise_aspm_matrix")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 hours
    MFA_ISSUER_NAME: str = "NeuroSec ASPM 4.0"
    
    # AI & Groq Configuration (Lido via variável de ambiente de forma 100% segura)
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    GROQ_URL: str = "https://api.groq.com/openai/v1/chat/completions"
    
    # Database (Caminho absoluto universal para garantir 100% de consistência)
    _BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    _DEFAULT_DB_PATH = os.path.join(_BACKEND_DIR, "neurosec.db").replace("\\", "/")
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{_DEFAULT_DB_PATH}")
    
    # Environment & CORS
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "*")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Risk weights for Security Scorecard (0-100)
    WEIGHT_CRITICAL: int = 15
    WEIGHT_HIGH: int = 8
    WEIGHT_MEDIUM: int = 3
    WEIGHT_LOW: int = 1
    
    # Financial loss avoided estimation per remediated vulnerability (BRL)
    LOSS_AVOIDED_PER_PATCH: int = 35000

settings = Settings()
