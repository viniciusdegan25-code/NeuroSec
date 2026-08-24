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

    # 2. Clientes Corporativos Iniciais (PMEs Diversas e Realistas)
    if db.query(ClientOrganization).count() == 0:
        clients = [
            ClientOrganization(
                id=1,
                name="AgroTech Soluções Inteligentes Ltda.",
                cnpj="18.234.567/0001-89",
                contact_name="Lucas Mendonça",
                contact_email="lucas.mendonca@agrotech.com.br",
                contact_phone="+55 (16) 98123-4567",
                sla_tier="BUSINESS_CRITICAL",
                industry="AGRO",
                annual_revenue_brl=8500000.0,
                sensitive_records_count=15000,
                downtime_cost_per_hour=3500.0,
                criticality_level="TIER_2_SIGNIFICANT",
                security_score=82,
                monitored_assets_count=3,
                open_vulns_count=1,
                status="active",
                notes="Plataforma de telemetria de solo, drones e sensores IoT para cooperativas agrícolas."
            ),
            ClientOrganization(
                id=2,
                name="VittaHealth Telemedicina & Clínicas",
                cnpj="24.567.890/0001-32",
                contact_name="Dra. Beatriz Fontana",
                contact_email="beatriz.fontana@vittahealth.med.br",
                contact_phone="+55 (11) 97234-5678",
                sla_tier="ENTERPRISE_24_7",
                industry="HEALTHCARE",
                annual_revenue_brl=14200000.0,
                sensitive_records_count=45000,
                downtime_cost_per_hour=6000.0,
                criticality_level="TIER_1_SYSTEMIC",
                security_score=74,
                monitored_assets_count=3,
                open_vulns_count=2,
                status="active",
                notes="Prontuários eletrônicos de pacientes, teleconsultas e laudos digitais protegidos por LGPD."
            ),
            ClientOrganization(
                id=3,
                name="Nexus Pay Meios de Pagamento",
                cnpj="31.456.789/0001-45",
                contact_name="Mariana Duarte",
                contact_email="m.duarte@nexuspay.io",
                contact_phone="+55 (11) 98765-4321",
                sla_tier="ENTERPRISE_24_7",
                industry="FINTECH",
                annual_revenue_brl=4800000.0,
                sensitive_records_count=22000,
                downtime_cost_per_hour=4500.0,
                criticality_level="TIER_1_SYSTEMIC",
                security_score=88,
                monitored_assets_count=2,
                open_vulns_count=1,
                status="active",
                notes="Gateway de pagamentos e checkout PIX/Cartão para e-commerces e lojistas de pequeno porte."
            ),
            ClientOrganization(
                id=4,
                name="LogiExpress Entregas & Frotas",
                cnpj="42.678.901/0001-78",
                contact_name="Roberto Silveira",
                contact_email="roberto@logiexpress.com.br",
                contact_phone="+55 (21) 96543-2109",
                sla_tier="STANDARD",
                industry="LOGISTICS",
                annual_revenue_brl=2400000.0,
                sensitive_records_count=8000,
                downtime_cost_per_hour=1800.0,
                criticality_level="TIER_2_SIGNIFICANT",
                security_score=95,
                monitored_assets_count=2,
                open_vulns_count=0,
                status="active",
                notes="Roteirizador de entregas last-mile e aplicativo para frotistas e motoristas urbanos."
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
                client_id=2,  # VittaHealth
                asset_type="CODE",
                asset_name="prontuario/consulta_service.py",
                vuln_type="SQL Injection",
                owasp_category="A03:2021 - Injection",
                line_number=42,
                severity="HIGH",
                cvss_score=8.5,
                status="open",
                days_open=2,
                ai_diagnosis="Injeção SQL identificada no método buscar_prontuario_paciente(). Concatenação direta de parâmetros de busca sem sanitização.",
                original_code='cursor.execute(f"SELECT * FROM prontuarios WHERE cpf=\'{cpf_paciente}\'")',
                fixed_code='cursor.execute("SELECT * FROM prontuarios WHERE cpf=%s", (cpf_paciente,))',
                created_at="15/08/2026 10:30"
            ),
            Vulnerability(
                key="sast_sec_2",
                internal_id=2,
                client_id=1,  # AgroTech
                asset_type="CODE",
                asset_name="telemetria/iot_gateway.py",
                vuln_type="Hardcoded Secrets & API Keys",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                line_number=18,
                severity="CRITICAL",
                cvss_score=9.4,
                status="open",
                days_open=3,
                ai_diagnosis="Chave de API do broker MQTT de telemetria gravada em código fonte. Viola a ISO 27001 e normas de segurança em IoT.",
                original_code='mqtt_api_key = "AgroIoT_LiveMasterSecret_2026!"',
                fixed_code='mqtt_api_key = os.getenv("MQTT_API_KEY")',
                created_at="14/08/2026 14:15"
            ),
            Vulnerability(
                key="dast_hsts_3",
                internal_id=3,
                client_id=3,  # Nexus Pay
                asset_type="URL",
                asset_name="https://checkout.nexuspay.io",
                vuln_type="Ausência de HSTS (Strict-Transport-Security)",
                owasp_category="A02:2021 - Cryptographic Failures",
                line_number=0,
                severity="MEDIUM",
                cvss_score=6.1,
                status="remediated",
                days_open=5,
                ai_diagnosis="O cabeçalho Strict-Transport-Security não estava sendo enviado no checkout PIX. Patch aplicado e validado pelo motor DAST.",
                original_code="Server: nginx/1.22.0 (sem HSTS)",
                fixed_code="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                created_at="12/08/2026 09:00"
            ),
            Vulnerability(
                key="sca_req_4",
                internal_id=4,
                client_id=2,  # VittaHealth
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
                ai_diagnosis="CVE-2023-32681: Vazamento inadvertido de Proxy-Authorization header em redirecionamentos HTTPS no módulo de teleconsulta.",
                original_code="requests==2.28.0",
                fixed_code="requests>=2.31.0",
                created_at="16/08/2026 08:20"
            )
        ]
        for v in initial_vulns:
            db.add(v)
            
    if db.query(Asset).count() == 0:
        initial_assets = [
            Asset(name="telemetria/iot_gateway.py", client_id=1, asset_type="REPO", criticality="TIER_1_CRITICAL"),
            Asset(name="https://portal.agrotech.com.br", client_id=1, asset_type="WEB_APP", criticality="TIER_2_HIGH"),
            Asset(name="firmware-sensores-solo.bin", client_id=1, asset_type="CLOUD_STORAGE", criticality="TIER_3_MEDIUM"),
            Asset(name="prontuario/consulta_service.py", client_id=2, asset_type="REPO", criticality="TIER_1_CRITICAL"),
            Asset(name="https://app.vittahealth.med.br", client_id=2, asset_type="WEB_APP", criticality="TIER_1_CRITICAL"),
            Asset(name="requirements.txt", client_id=2, asset_type="REPO", criticality="TIER_2_HIGH"),
            Asset(name="https://checkout.nexuspay.io", client_id=3, asset_type="WEB_APP", criticality="TIER_1_CRITICAL"),
            Asset(name="api-pix-gateway.py", client_id=3, asset_type="REPO", criticality="TIER_1_CRITICAL"),
            Asset(name="https://rotas.logiexpress.com.br", client_id=4, asset_type="WEB_APP", criticality="TIER_2_HIGH"),
            Asset(name="roteirizador_frotas.py", client_id=4, asset_type="REPO", criticality="TIER_3_MEDIUM")
        ]
        for a in initial_assets:
            db.add(a)

    db.commit()
