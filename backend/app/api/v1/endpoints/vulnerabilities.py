from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from app.db.database import get_db
from app.db.models import Vulnerability, AuditLog
from app.schemas.vulnerability import VulnerabilityResponse, VulnerabilityUpdateStatus

router = APIRouter()

@router.get("", response_model=List[VulnerabilityResponse], summary="Lista todas as vulnerabilidades")
def list_vulnerabilities(
    status: Optional[str] = Query(None, description="Filtra por status: open, patch_ready, remediated"),
    severity: Optional[str] = Query(None, description="Filtra por severidade: CRITICAL, HIGH, MEDIUM, LOW"),
    asset_type: Optional[str] = Query(None, description="Filtra por tipo de ativo: CODE, URL, DEPENDENCY, CLOUD"),
    db: Session = Depends(get_db)
):
    query = db.query(Vulnerability)
    if status:
        query = query.filter(Vulnerability.status == status)
    if severity:
        query = query.filter(Vulnerability.severity == severity.upper())
    if asset_type:
        query = query.filter(Vulnerability.asset_type == asset_type.upper())
    
    return query.order_by(Vulnerability.id.desc()).all()

@router.get("/{internal_id}", response_model=VulnerabilityResponse, summary="Obtém detalhes de uma vulnerabilidade por ID interno")
def get_vulnerability(internal_id: int, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.internal_id == internal_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerabilidade não encontrada.")
    return vuln

@router.patch("/{internal_id}/status", response_model=VulnerabilityResponse, summary="Atualiza o status de resolução da vulnerabilidade")
def update_vulnerability_status(
    internal_id: int,
    payload: VulnerabilityUpdateStatus,
    db: Session = Depends(get_db)
):
    vuln = db.query(Vulnerability).filter(Vulnerability.internal_id == internal_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerabilidade não encontrada.")
    
    old_status = vuln.status
    vuln.status = payload.status
    vuln.updated_at = datetime.now().strftime("%d/%m/%Y %H:%M")
    
    # Registra na trilha de auditoria
    audit_entry = AuditLog(
        action="STATUS_CHANGED",
        target_vuln_id=vuln.internal_id,
        vuln_key=vuln.key,
        operator=payload.operator or "SecOps Lead",
        details=f"Status alterado de '{old_status}' para '{payload.status}'. Notas: {payload.notes or 'N/A'}"
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(vuln)

    return vuln

@router.post("/seed-demo", summary="Popula o banco com o Cenário de Demonstração Enterprise (Fintech / Banking)")
def seed_demo_scenario(db: Session = Depends(get_db)):
    """Popula um ecossistema corporativo completo para apresentações de alto impacto."""
    
    # Limpa registros anteriores para criar um cenário limpo e coerente
    db.query(Vulnerability).delete()
    db.query(AuditLog).delete()
    db.commit()

    demo_vulns = [
        Vulnerability(
            internal_id=1,
            key="SAST-AUTH-001",
            asset_name="services/auth/jwt_provider.py",
            asset_type="CODE",
            vuln_type="Hardcoded JWT Secret Key",
            severity="CRITICAL",
            cvss_score=9.8,
            status="open",
            cve_id="CWE-798",
            line_number=18,
            owasp_category="A07:2021-Identification and Authentication Failures",
            original_code='JWT_SECRET = "super_secret_production_key_2026!"\nALGORITHM = "HS256"',
            days_open=2
        ),
        Vulnerability(
            internal_id=2,
            key="SAST-PAY-002",
            asset_name="services/payments/checkout.py",
            asset_type="CODE",
            vuln_type="SQL Injection (String Concatenation)",
            severity="CRITICAL",
            cvss_score=9.8,
            status="open",
            cve_id="CWE-89",
            line_number=45,
            owasp_category="A03:2021-Injection",
            original_code='query = f"SELECT * FROM transactions WHERE card_id = \'{card_id}\' AND user_id = \'{user_id}\'"\ncursor.execute(query)',
            days_open=3
        ),
        Vulnerability(
            internal_id=3,
            key="SAST-EXEC-003",
            asset_name="workers/report_generator.py",
            asset_type="CODE",
            vuln_type="Command Injection (OS Execution)",
            severity="CRITICAL",
            cvss_score=9.8,
            status="open",
            cve_id="CWE-78",
            line_number=62,
            owasp_category="A03:2021-Injection",
            original_code='os.system(f"wkhtmltopdf {template_path} {output_filename}")',
            days_open=1
        ),
        Vulnerability(
            internal_id=4,
            key="SCA-YAML-004",
            asset_name="requirements.txt:pyyaml==5.3.1",
            asset_type="PACKAGE",
            vuln_type="Remote Code Execution in YAML Parser",
            severity="CRITICAL",
            cvss_score=9.8,
            status="open",
            cve_id="CVE-2020-14343",
            line_number=4,
            owasp_category="A06:2021-Vulnerable and Outdated Components",
            original_code="pyyaml==5.3.1",
            days_open=4
        ),
        Vulnerability(
            internal_id=5,
            key="SCA-REQ-005",
            asset_name="requirements.txt:requests==2.25.1",
            asset_type="PACKAGE",
            vuln_type="Proxy Authorization Header Exfiltration",
            severity="HIGH",
            cvss_score=7.5,
            status="patch_ready",
            cve_id="CVE-2023-32681",
            line_number=2,
            owasp_category="A06:2021-Vulnerable and Outdated Components",
            original_code="requests==2.25.1",
            days_open=5
        ),
        Vulnerability(
            internal_id=6,
            key="CSPM-S3-006",
            asset_name="infra/terraform/storage.tf",
            asset_type="CLOUD",
            vuln_type="S3 Bucket Public Read/Write ACL Enabled",
            severity="HIGH",
            cvss_score=8.5,
            status="open",
            cve_id="CWE-732",
            line_number=14,
            owasp_category="A05:2021-Security Misconfiguration",
            original_code='resource "aws_s3_bucket" "client_docs" {\n  bucket = "fintech-client-documents-prod"\n  acl    = "public-read"\n}',
            days_open=6
        ),
        Vulnerability(
            internal_id=7,
            key="CSPM-IAM-007",
            asset_name="infra/terraform/iam.tf",
            asset_type="CLOUD",
            vuln_type="Over-privileged IAM Role (Wildcard Action '*: *')",
            severity="HIGH",
            cvss_score=8.2,
            status="open",
            cve_id="CWE-250",
            line_number=28,
            owasp_category="A01:2021-Broken Access Control",
            original_code='statement {\n  actions   = ["*"]\n  resources = ["*"]\n}',
            days_open=7
        ),
        Vulnerability(
            internal_id=8,
            key="DAST-WEB-008",
            asset_name="https://api.fintech-global.com.br",
            asset_type="ENDPOINT",
            vuln_type="Missing HTTP Strict Transport Security (HSTS)",
            severity="MEDIUM",
            cvss_score=5.3,
            status="remediated",
            cve_id="CWE-319",
            line_number=1,
            owasp_category="A05:2021-Security Misconfiguration",
            original_code="Strict-Transport-Security header not present in response headers.",
            days_open=0
        ),
        Vulnerability(
            internal_id=9,
            key="DAST-CSP-009",
            asset_name="https://app.fintech-global.com.br",
            asset_type="ENDPOINT",
            vuln_type="Missing Content-Security-Policy (CSP)",
            severity="MEDIUM",
            cvss_score=5.0,
            status="open",
            cve_id="CWE-693",
            line_number=1,
            owasp_category="A05:2021-Security Misconfiguration",
            original_code="Content-Security-Policy header is missing, allowing unrestricted cross-origin scripts.",
            days_open=9
        )
    ]

    for v in demo_vulns:
        db.add(v)

    # Adiciona eventos de auditoria para compor o histórico
    db.add(AuditLog(
        action="DEMO_SCENARIO_LOADED",
        target_vuln_id=1,
        vuln_key="SYSTEM",
        operator="Chief Security Officer",
        details="Cenário de Demonstração Enterprise (Fintech Banking) carregado para auditoria e apresentação de postura.",
        diff_preview="Infraestrutura e código auditados com 9 vetores ativos em monitoramento."
    ))
    db.add(AuditLog(
        action="PATCH_APPROVED",
        target_vuln_id=8,
        vuln_key="DAST-WEB-008",
        operator="SecOps Lead",
        details="Patch de configuração HSTS aprovado e propagado no proxy Cloudflare.",
        diff_preview="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    ))

    db.commit()

    return {
        "status": "success",
        "message": "Cenário de Demonstração Enterprise carregado com sucesso!",
        "total_vulns": len(demo_vulns),
        "posture_summary": "9 vulnerabilidades ativas distribuídas entre Código (SAST), Nuvem (CSPM), Dependências (SCA) e Web (DAST)."
    }
