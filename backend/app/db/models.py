from sqlalchemy import Column, Integer, String, Text, Float, DateTime
from datetime import datetime
from app.db.database import Base

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)  # ex: sast_sql_1, dast_hsts_2
    internal_id = Column(Integer, index=True)
    client_id = Column(Integer, nullable=True, index=True) # ID do Cliente/Tenant associado
    asset_type = Column(String, default="CODE")     # CODE, URL, DEPENDENCY, CLOUD
    asset_name = Column(String)                     # login.py, https://app.empresa.com, etc.
    vuln_type = Column(String)                      # SQL Injection, Hardcoded Secrets, Missing CSP, etc.
    cve_id = Column(String, nullable=True)          # CVE-2024-1182, etc.
    owasp_category = Column(String, nullable=True)  # A03:2021 - Injection
    line_number = Column(Integer, default=0)
    severity = Column(String, default="MEDIUM")     # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score = Column(Float, default=5.0)
    status = Column(String, default="open")          # open, patch_ready, remediated, false_positive
    days_open = Column(Integer, default=1)
    ai_diagnosis = Column(Text, nullable=True)
    original_code = Column(Text, nullable=True)
    fixed_code = Column(Text, nullable=True)
    patch_file = Column(String, nullable=True)
    created_at = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M"))
    updated_at = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M"))

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String)                         # PATCH_APPROVED, SCAN_EXECUTED, STATUS_CHANGED, USER_LOGIN, MFA_VERIFIED
    target_vuln_id = Column(Integer, nullable=True)
    vuln_key = Column(String, nullable=True)
    operator = Column(String, default="SecOps Lead")
    details = Column(Text)
    diff_preview = Column(Text, nullable=True)
    timestamp = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String)                      # SAST, DAST, SCA, CLOUD, FULL
    target = Column(String)                         # Path, URL or Repo name
    client_id = Column(Integer, nullable=True)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    score_snapshot = Column(Integer, default=100)
    created_at = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(Integer, nullable=True, index=True)
    name = Column(String, unique=True, index=True)
    asset_type = Column(String, default="REPO")     # REPO, WEB_APP, API_SERVICE, CLOUD_CONTAINER
    criticality = Column(String, default="TIER_1_CRITICAL")
    environment = Column(String, default="production")
    last_scanned = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M"))

class EnterpriseLead(Base):
    __tablename__ = "enterprise_leads"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    corporate_email = Column(String, nullable=False, index=True)
    company_name = Column(String, nullable=False)
    job_title = Column(String, default="Executivo / Analista")
    company_size = Column(String, default="50-200")
    main_challenge = Column(String, default="ASPM & Postura de Segurança")
    status = Column(String, default="new")          # new, contacted, demo_scheduled
    created_at = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="SECOPS_ADMIN")   # SECOPS_ADMIN, CISO, APPSEC_ANALYST, AUDITOR
    mfa_enabled = Column(Integer, default=1)        # 1 = Ativo, 0 = Inativo
    mfa_secret = Column(String, nullable=True)      # Chave TOTP Base32
    is_active = Column(Integer, default=1)
    created_at = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M"))
    last_login = Column(String, nullable=True)

class ClientOrganization(Base):
    __tablename__ = "client_organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)   # Razão Social / Nome Fantasia
    cnpj = Column(String, nullable=True)                             # CNPJ do Cliente
    contact_name = Column(String, nullable=False)                    # CISO / Responsável Técnico
    contact_email = Column(String, nullable=False)
    contact_phone = Column(String, nullable=True)
    sla_tier = Column(String, default="ENTERPRISE_24_7")             # ENTERPRISE_24_7, BUSINESS_CRITICAL, STANDARD
    industry = Column(String, default="FINTECH")                     # FINTECH, HEALTHCARE, E_COMMERCE, GOV, LOGISTICS
    
    # Parâmetros Estruturais de Negócio & Modelo FAIR / LGPD
    annual_revenue_brl = Column(Float, default=50000000.0)           # Faturamento anual em R$
    sensitive_records_count = Column(Integer, default=100000)        # Volume de titulares/dados sensíveis sob custódia
    downtime_cost_per_hour = Column(Float, default=25000.0)          # Custo financeiro de hora de indisponibilidade
    financial_loss_avoided_brl = Column(Float, default=0.0)          # Prejuízo evitado acumulado (R$)
    financial_exposure_risk_brl = Column(Float, default=0.0)         # Risco financeiro total em aberto (R$)
    criticality_level = Column(String, default="TIER_1_SYSTEMIC")    # TIER_1_SYSTEMIC, TIER_2_SIGNIFICANT, TIER_3_STANDARD

    security_score = Column(Integer, default=88)                     # Score individual do cliente (0 a 100)
    monitored_assets_count = Column(Integer, default=4)
    open_vulns_count = Column(Integer, default=2)
    status = Column(String, default="active")                        # active, onboarding, audit_pending, suspended
    notes = Column(Text, nullable=True)
    created_at = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M"))
    updated_at = Column(String, default=lambda: datetime.now().strftime("%d/%m/%Y %H:%M"))
