from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

# Engine configuration with check_same_thread=False for SQLite compatibility
engine_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    engine_args["connect_args"] = {"check_same_thread": False}

engine = create_engine(settings.DATABASE_URL, **engine_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Dependency para injeção de sessão do banco de dados em endpoints FastAPI."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db(seed: bool = True):
    """Inicializa as tabelas do banco de dados relacional e popula sementes iniciais se vazio."""
    from app.db import models  # Importa para registrar todos os modelos
    Base.metadata.create_all(bind=engine)
    
    if seed:
        db = SessionLocal()
        try:
            if db.query(models.Vulnerability).count() == 0:
                seed_initial_data(db)
        finally:
            db.close()

def seed_initial_data(db):
    """Insere dados realistas de exemplo na primeira inicialização."""
    from app.db.models import Vulnerability, Asset, User, ClientOrganization
    from app.core.security import hash_password

    # 1. Usuário Administrador SecOps com MFA Ativo
    if db.query(User).count() == 0:
        admin_user = User(
            name="SecOps Lead & CISO",
            email="admin@neurosec.ai",
            hashed_password=hash_password("NeuroSec2026!Admin"),
            role="SECOPS_ADMIN",
            mfa_enabled=1,
            mfa_secret="JBSWY3DPEHPK3PXP",  # Chave TOTP Base32 de demonstração
            is_active=1
        )
        db.add(admin_user)

    # 2. Clientes Corporativos Iniciais (Multi-Tenant Hub com Parâmetros Estruturais e Financeiros)
    if db.query(ClientOrganization).count() == 0:
        clients = [
            ClientOrganization(
                id=1,
                name="Banco Aurora S.A.",
                cnpj="12.345.678/0001-90",
                contact_name="Carlos Menezes",
                contact_email="carlos.menezes@bancoaurora.com.br",
                contact_phone="+55 (11) 98765-4321",
                sla_tier="ENTERPRISE_24_7",
                industry="FINTECH",
                annual_revenue_brl=450000000.0,
                sensitive_records_count=1200000,
                downtime_cost_per_hour=120000.0,
                criticality_level="TIER_1_SYSTEMIC",
                security_score=92,
                monitored_assets_count=6,
                open_vulns_count=1,
                status="active",
                notes="Ambiente bancário com monitoramento contínuo de APIs Open Finance e Core Bancário."
            ),
            ClientOrganization(
                id=2,
                name="Nexus Pay Meios de Pagamento",
                cnpj="23.456.789/0001-01",
                contact_name="Mariana Duarte",
                contact_email="m.duarte@nexuspay.io",
                contact_phone="+55 (11) 97654-3210",
                sla_tier="ENTERPRISE_24_7",
                industry="FINTECH",
                annual_revenue_brl=80000000.0,
                sensitive_records_count=350000,
                downtime_cost_per_hour=45000.0,
                criticality_level="TIER_1_SYSTEMIC",
                security_score=74,
                monitored_assets_count=8,
                open_vulns_count=3,
                status="active",
                notes="Gateway de pagamentos PCI-DSS com auditoria diária de infraestrutura e dependências."
            ),
            ClientOrganization(
                id=3,
                name="AeroLog Logística Digital",
                cnpj="34.567.890/0001-12",
                contact_name="Roberto Silveira",
                contact_email="roberto@aerolog.com.br",
                contact_phone="+55 (21) 96543-2109",
                sla_tier="BUSINESS_CRITICAL",
                industry="LOGISTICS",
                annual_revenue_brl=35000000.0,
                sensitive_records_count=60000,
                downtime_cost_per_hour=18000.0,
                criticality_level="TIER_2_SIGNIFICANT",
                security_score=81,
                monitored_assets_count=4,
                open_vulns_count=2,
                status="active",
                notes="Plataforma de rastreamento e frotas conectadas em nuvem AWS."
            )
        ]
        for c in clients:
            db.add(c)

    # 3. Vulnerabilidades e Ativos
    if db.query(Vulnerability).count() == 0:
        initial_vulns = [
            Vulnerability(
                key="sast_sql_1",
                internal_id=1,
                client_id=1,
                asset_type="CODE",
                asset_name="auth/login_service.py",
                vuln_type="SQL Injection",
                owasp_category="A03:2021 - Injection",
                line_number=42,
                severity="HIGH",
                cvss_score=8.5,
                status="open",
                days_open=2,
                ai_diagnosis="Vulnerabilidade de injeção SQL crítica identificada no método authenticate_user(). Concatenação de variáveis de entrada diretamente na instrução SQL.",
                original_code='cursor.execute(f"SELECT * FROM users WHERE user=\'{username}\' AND pass=\'{password}\'")',
                fixed_code='cursor.execute("SELECT * FROM users WHERE user=%s AND pass=%s", (username, password_hash))',
                created_at="15/08/2026 10:30"
            ),
            Vulnerability(
                key="sast_sec_2",
                internal_id=2,
                client_id=1,
                asset_type="CODE",
                asset_name="config/database_client.py",
                vuln_type="Hardcoded Secrets & API Keys",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                line_number=18,
                severity="CRITICAL",
                cvss_score=9.4,
                status="open",
                days_open=3,
                ai_diagnosis="Chave de API de produção gravada em texto plano. Viola as políticas de conformidade ISO 27001 e SOC 2.",
                original_code='db_password = "SuperSecretProdDBKey2026!"',
                fixed_code='db_password = os.getenv("DB_PASSWORD")',
                created_at="14/08/2026 14:15"
            ),
            Vulnerability(
                key="dast_hsts_3",
                internal_id=3,
                client_id=2,
                asset_type="URL",
                asset_name="https://portal.empresa.com.br",
                vuln_type="Ausência de HSTS (Strict-Transport-Security)",
                owasp_category="A02:2021 - Cryptographic Failures",
                line_number=0,
                severity="MEDIUM",
                cvss_score=6.1,
                status="remediated",
                days_open=5,
                ai_diagnosis="O cabeçalho Strict-Transport-Security não estava sendo enviado pelo proxy reverso. Patch aplicado e validado.",
                original_code="Server: nginx/1.22.0 (sem HSTS)",
                fixed_code="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                created_at="12/08/2026 09:00"
            ),
            Vulnerability(
                key="sca_req_4",
                internal_id=4,
                client_id=2,
                asset_type="DEPENDENCY",
                asset_name="requirements.txt",
                vuln_type="Biblioteca Vulnerável: requests (2.28.0)",
                cve_id="CVE-2023-32681",
                owasp_category="A06:2021 - Vulnerable and Outdated Components",
                line_number=7,
                severity="HIGH",
                cvss_score=7.5,
                status="open",
                days_open=1,
                ai_diagnosis="CVE-2023-32681: Vazamento inadvertido de Proxy-Authorization header em redirecionamentos HTTPS.",
                original_code="requests==2.28.0",
                fixed_code="requests>=2.31.0",
                created_at="16/08/2026 08:20"
            )
        ]
        for v in initial_vulns:
            db.add(v)
            
    if db.query(Asset).count() == 0:
        initial_assets = [
            Asset(name="auth/login_service.py", client_id=1, asset_type="REPO", criticality="TIER_1_CRITICAL"),
            Asset(name="config/database_client.py", client_id=1, asset_type="REPO", criticality="TIER_1_CRITICAL"),
            Asset(name="https://portal.empresa.com.br", client_id=2, asset_type="WEB_APP", criticality="TIER_2_HIGH"),
            Asset(name="requirements.txt", client_id=2, asset_type="REPO", criticality="TIER_3_MEDIUM")
        ]
        for a in initial_assets:
            db.add(a)

    db.commit()
