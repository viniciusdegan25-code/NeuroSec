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
    # Inicializa banco de dados com a fonte única centralizada de sementes (PMEs e MFA)
    init_db(seed=True)
    yield

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

@app.middleware("http")
async def add_no_cache_headers(request, call_next):
    response = await call_next(request)
    # Impede que o navegador sirva páginas ou scripts antigos em cache
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

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

    def _serve_file_no_cache(file_path: str):
        if os.path.exists(file_path):
            return FileResponse(
                file_path,
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Expires": "0"
                }
            )
        return FileResponse(os.path.join(frontend_path, "index.html"))

    # 1. Rota Comercial Hub Principal (Multi-Page)
    @app.get("/")
    def serve_frontend_root():
        index_file = os.path.join(frontend_path, "index.html")
        return _serve_file_no_cache(index_file)

    # 2. Rota de Solicitação de Avaliação / Onboarding (Multi-Page)
    @app.get("/avaliacao")
    @app.get("/solicitar-avaliacao")
    def serve_avaliacao_page():
        return _serve_file_no_cache(os.path.join(frontend_path, "avaliacao.html"))

    # 3. Rota do Portal de Notícias Reais & Threat Intelligence (Multi-Page)
    @app.get("/noticias")
    @app.get("/threat-intel")
    def serve_noticias_page():
        return _serve_file_no_cache(os.path.join(frontend_path, "noticias.html"))

    # 4. Rota "Nossas Ferramentas" (Guia Técnico e Didático dos 11 Motores)
    @app.get("/ferramentas")
    @app.get("/nossas-ferramentas")
    def serve_ferramentas_page():
        return _serve_file_no_cache(os.path.join(frontend_path, "ferramentas.html"))

    # 5. Rota do Dashboard / Cockpit SPA Logado (Single Page Application)
    @app.get("/dashboard")
    @app.get("/app")
    @app.get("/cockpit")
    def serve_dashboard_spa():
        return _serve_file_no_cache(os.path.join(frontend_path, "dashboard.html"))

    # 6. Rota de Autenticação Segura & MFA (Login Screen)
    @app.get("/login")
    @app.get("/entrar")
    @app.get("/auth")
    def serve_login_page():
        return _serve_file_no_cache(os.path.join(frontend_path, "login.html"))

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
