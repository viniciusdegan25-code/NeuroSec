from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from app.db.database import get_db
from app.db.models import Vulnerability, AuditLog, ClientOrganization, Asset
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

    # Garante que as 3 empresas corporativas de demonstração existam
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
                security_score=66,
                monitored_assets_count=6,
                open_vulns_count=3,
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
                security_score=88,
                monitored_assets_count=8,
                open_vulns_count=1,
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
                security_score=100,
                monitored_assets_count=4,
                open_vulns_count=0,
                status="active",
                notes="Plataforma de rastreamento e frotas conectadas em nuvem AWS."
            )
        ]
        for c in clients:
            db.add(c)
        db.commit()

    demo_vulns = [
        Vulnerability(
            internal_id=1,
            client_id=1,
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
            client_id=1,
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
            client_id=1,
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
            client_id=1,
            key="SCA-YAML-004",
            asset_name="requirements.txt:pyyaml==5.3.1",
            asset_type="DEPENDENCY",
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
            client_id=2,
            key="SCA-REQ-005",
            asset_name="requirements.txt:requests==2.25.1",
            asset_type="DEPENDENCY",
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
            client_id=1,
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
            client_id=2,
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
            client_id=2,
            key="DAST-WEB-008",
            asset_name="https://api.nexuspay.io",
            asset_type="URL",
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
            client_id=3,
            key="DAST-CSP-009",
            asset_name="https://app.aerolog.com.br",
            asset_type="URL",
            vuln_type="Missing Content-Security-Policy (CSP)",
            severity="MEDIUM",
            cvss_score=5.0,
            status="remediated",
            cve_id="CWE-693",
            line_number=1,
            owasp_category="A05:2021-Security Misconfiguration",
            original_code="Content-Security-Policy header is missing, allowing unrestricted cross-origin scripts.",
            days_open=0
        )
    ]

    for v in demo_vulns:
        db.add(v)

    # Recalcula as métricas financeiras de cada cliente
    from app.services.scorecard_service import ScorecardService
    all_clients = db.query(ClientOrganization).all()
    for cl in all_clients:
        cl_vulns = [v for v in demo_vulns if v.client_id == cl.id]
        cl_assets = db.query(Asset).filter(Asset.client_id == cl.id).all()
        fin_calc = ScorecardService.calculate_client_financial_risk(cl, cl_vulns, cl_assets)
        cl.financial_exposure_risk_brl = fin_calc["financial_exposure_risk_brl"]
        cl.financial_loss_avoided_brl = fin_calc["financial_loss_avoided_brl"]
        cl.security_score = fin_calc["security_score"]
        cl.open_vulns_count = fin_calc["open_vulns_count"]

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
        details="Patch de configuração HSTS aprovado e propagado no proxy Cloudflare da Nexus Pay.",
        diff_preview="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    ))

    db.commit()

    return {
        "status": "success",
        "message": "Cenário de Demonstração Enterprise carregado com sucesso!",
        "total_vulns": len(demo_vulns),
        "posture_summary": "9 vulnerabilidades ativas distribuídas entre Código (SAST), Nuvem (CSPM), Dependências (SCA) e Web (DAST)."
    }
