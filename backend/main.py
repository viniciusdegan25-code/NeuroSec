from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
import os

from app.core.config import settings
from app.db.database import init_db, SessionLocal
from app.db.models import Vulnerability, Asset
from app.api.v1.api import api_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inicializa banco de dados
    init_db()
    
    # Popula com sementes iniciais se o banco estiver vazio
    db = SessionLocal()
    try:
        if db.query(Vulnerability).count() == 0:
            seed_initial_data(db)
    finally:
        db.close()
        
    yield

def seed_initial_data(db):
    """Insere dados realistas de exemplo na primeira inicialização."""
    initial_vulns = [
        Vulnerability(
            key="sast_sql_1",
            internal_id=1,
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
        
    initial_assets = [
        Asset(name="auth/login_service.py", asset_type="REPO", criticality="TIER_1_CRITICAL"),
        Asset(name="config/database_client.py", asset_type="REPO", criticality="TIER_1_CRITICAL"),
        Asset(name="https://portal.empresa.com.br", asset_type="WEB_APP", criticality="TIER_2_HIGH"),
        Asset(name="requirements.txt", asset_type="REPO", criticality="TIER_3_MEDIUM")
    ]
    for a in initial_assets:
        db.add(a)

    db.commit()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Plataforma de Application Security Posture Management (ASPM 4.0) — Neo-Matrix Enterprise",
    version=settings.VERSION,
    lifespan=lifespan
)

# CORS
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Roteador Principal v1
app.include_router(api_router, prefix=settings.API_V1_STR)

# Aliases de compatibilidade para conveniência
app.include_router(api_router, prefix="/api")

# Montagem do Frontend estático (CSS, JS, Assets e Rotas Multi-Page)
frontend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(frontend_path):
    css_path = os.path.join(frontend_path, "css")
    js_path = os.path.join(frontend_path, "js")
    assets_path = os.path.join(frontend_path, "assets")
    
    if os.path.exists(css_path):
        app.mount("/css", StaticFiles(directory=css_path), name="css")
    if os.path.exists(js_path):
        app.mount("/js", StaticFiles(directory=js_path), name="js")
    if os.path.exists(assets_path):
        app.mount("/assets", StaticFiles(directory=assets_path), name="assets")
        
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

    # 1. Rota Comercial Hub Principal (Multi-Page)
    @app.get("/")
    def serve_frontend_root():
        index_file = os.path.join(frontend_path, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "NeuroSec ASPM 4.0 Backend API is running."}

    # 2. Rota de Solicitação de Avaliação / Onboarding (Multi-Page)
    @app.get("/avaliacao")
    @app.get("/solicitar-avaliacao")
    def serve_avaliacao_page():
        page = os.path.join(frontend_path, "avaliacao.html")
        if os.path.exists(page):
            return FileResponse(page)
        return FileResponse(os.path.join(frontend_path, "index.html"))

    # 3. Rota do Portal de Notícias Reais & Threat Intelligence (Multi-Page)
    @app.get("/noticias")
    @app.get("/threat-intel")
    def serve_noticias_page():
        page = os.path.join(frontend_path, "noticias.html")
        if os.path.exists(page):
            return FileResponse(page)
        return FileResponse(os.path.join(frontend_path, "index.html"))

    # 4. Rota "Nossas Ferramentas" (Guia Técnico e Didático dos 11 Motores)
    @app.get("/ferramentas")
    @app.get("/nossas-ferramentas")
    def serve_ferramentas_page():
        page = os.path.join(frontend_path, "ferramentas.html")
        if os.path.exists(page):
            return FileResponse(page)
        return FileResponse(os.path.join(frontend_path, "index.html"))

    # 4. Rota do Dashboard / Cockpit SPA Logado (Single Page Application)
    @app.get("/dashboard")
    @app.get("/app")
    @app.get("/cockpit")
    def serve_dashboard_spa():
        page = os.path.join(frontend_path, "dashboard.html")
        if os.path.exists(page):
            return FileResponse(page)
        return FileResponse(os.path.join(frontend_path, "index.html"))

@app.get("/health", summary="Healthcheck da API")
def healthcheck():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=settings.PORT, reload=True)
