from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from app.db.database import get_db
from app.db.models import Vulnerability, ScanHistory
from app.schemas.scan import CloudScanRequest, ScanResponse, ScanResultItem
from app.services.cloud_service import CloudAuditEngine
from app.services.scorecard_service import ScorecardService

router = APIRouter()

@router.post("/audit", response_model=ScanResponse, summary="Executa auditoria de postura em nuvem (CSPM-lite)")
def audit_cloud_config(payload: CloudScanRequest, db: Session = Depends(get_db)):
    config_text = payload.config_text or ""
    if not config_text.strip():
        # Exemplo padrão de auditoria se não passado texto
        config_text = """
        resource "aws_s3_bucket" "data_bucket" {
            bucket = "empresa-prod-customer-data"
            acl    = "public-read"
        }
        resource "aws_security_group" "allow_ssh" {
            from_port   = 22
            to_port     = 22
            protocol    = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
        }
        """

    findings = CloudAuditEngine.audit_iac_text(config_text, asset_name=f"{payload.provider or 'AWS'}-Infrastructure")
    
    max_id = db.query(Vulnerability).order_by(Vulnerability.internal_id.desc()).first()
    next_id = (max_id.internal_id + 1) if max_id else 1
    new_findings_count = 0
    findings_response = []

    for f in findings:
        key = f"cloud_audit_{next_id}"
        exists = db.query(Vulnerability).filter(
            Vulnerability.asset_name == f["asset_name"],
            Vulnerability.vuln_type == f["vuln_type"]
        ).first()

        if not exists:
            new_vuln = Vulnerability(
                key=key,
                internal_id=next_id,
                asset_type="CLOUD",
                asset_name=f["asset_name"],
                vuln_type=f["vuln_type"],
                owasp_category=f["owasp_category"],
                line_number=f["line_number"],
                severity=f["severity"],
                cvss_score=f["cvss_score"],
                status="open",
                days_open=1,
                ai_diagnosis=f["description"],
                original_code=f["code_snippet"],
                fixed_code="# Restrinja permissões de acesso ao menor privilégio",
                created_at=datetime.now().strftime("%d/%m/%Y %H:%M")
            )
            db.add(new_vuln)
            next_id += 1
            new_findings_count += 1

        findings_response.append(ScanResultItem(
            type=f["vuln_type"],
            severity=f["severity"],
            line=f["line_number"],
            asset=f["asset_name"],
            description=f["description"],
            code_snippet=f["code_snippet"],
            owasp=f["owasp_category"]
        ))

    db.commit()
    score = ScorecardService.calculate_metrics(db).score

    scan_history = ScanHistory(
        scan_type="CLOUD",
        target=f"{payload.provider or 'AWS'} Config",
        findings_count=len(findings_response),
        critical_count=sum(1 for f in findings if f["severity"] == "CRITICAL"),
        high_count=sum(1 for f in findings if f["severity"] == "HIGH"),
        score_snapshot=score
    )
    db.add(scan_history)
    db.commit()

    return ScanResponse(
        status="success",
        scan_type="CLOUD_CSPM",
        target=f"{payload.provider or 'AWS'} Config",
        new_findings=new_findings_count,
        total_findings=len(findings_response),
        findings=findings_response,
        score_after=score
    )
