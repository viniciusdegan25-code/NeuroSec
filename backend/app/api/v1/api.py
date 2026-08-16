from fastapi import APIRouter

from app.api.v1.endpoints import (
    vulnerabilities,
    sast,
    dast,
    sca,
    cloud,
    remediation,
    copilot,
    scorecard,
    audit,
    terminal,
    reports,
    leads
)

api_router = APIRouter()

api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["Vulnerabilidades"])
api_router.include_router(sast.router, prefix="/scan/sast", tags=["SAST Scan"])
api_router.include_router(dast.router, prefix="/scan/dast", tags=["DAST Scan"])
api_router.include_router(sca.router, prefix="/scan/sca", tags=["SCA & SBOM"])
api_router.include_router(cloud.router, prefix="/scan/cloud", tags=["Cloud Audit"])
api_router.include_router(remediation.router, prefix="/remediate", tags=["AI Remediation"])
api_router.include_router(copilot.router, prefix="/copilot", tags=["AI Security Copilot"])
api_router.include_router(scorecard.router, prefix="/scorecard", tags=["Security Scorecard"])
api_router.include_router(audit.router, prefix="/audit", tags=["Trilha de Auditoria"])
api_router.include_router(terminal.router, prefix="/terminal", tags=["Cyber Terminal"])
api_router.include_router(reports.router, prefix="/reports", tags=["Relatórios Executivos"])
api_router.include_router(leads.router, prefix="/leads", tags=["Captação de Avaliação"])
