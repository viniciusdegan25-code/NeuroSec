from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from app.db.database import get_db
from app.db.models import Vulnerability, ScanHistory
from app.schemas.scan import ScaFileScanRequest, ScanResponse, ScanResultItem
from app.services.sca_service import ScaEngine
from app.services.scorecard_service import ScorecardService

router = APIRouter()

@router.post("/file", response_model=ScanResponse, summary="Executa scan de dependências / SBOM em arquivo de manifesto")
def scan_sca_file(payload: ScaFileScanRequest, db: Session = Depends(get_db)):
    findings = ScaEngine.scan_manifest_text(payload.content, filename=payload.filename or "requirements.txt")
    
    max_id = db.query(Vulnerability).order_by(Vulnerability.internal_id.desc()).first()
    next_id = (max_id.internal_id + 1) if max_id else 1
    new_findings_count = 0
    findings_response = []

    for f in findings:
        key = f"sca_pkg_{next_id}"
        exists = db.query(Vulnerability).filter(
            Vulnerability.asset_name == f["asset_name"],
            Vulnerability.vuln_type == f["vuln_type"]
        ).first()

        if not exists:
            new_vuln = Vulnerability(
                key=key,
                internal_id=next_id,
                asset_type="DEPENDENCY",
                asset_name=f["asset_name"],
                vuln_type=f["vuln_type"],
                cve_id=f.get("cve_id"),
                owasp_category=f["owasp_category"],
                line_number=f["line_number"],
                severity=f["severity"],
                cvss_score=f["cvss_score"],
                status="open",
                days_open=1,
                ai_diagnosis=f["description"],
                original_code=f["code_snippet"],
                fixed_code=f"# Atualize a dependência para a versão estável mais recente",
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
            cve_id=f.get("cve_id"),
            owasp=f["owasp_category"]
        ))

    db.commit()
    score = ScorecardService.calculate_metrics(db).score

    scan_history = ScanHistory(
        scan_type="SCA",
        target=payload.filename or "requirements.txt",
        findings_count=len(findings_response),
        critical_count=sum(1 for f in findings if f["severity"] == "CRITICAL"),
        high_count=sum(1 for f in findings if f["severity"] == "HIGH"),
        score_snapshot=score
    )
    db.add(scan_history)
    db.commit()

    return ScanResponse(
        status="success",
        scan_type="SCA_DEPENDENCIES",
        target=payload.filename or "requirements.txt",
        new_findings=new_findings_count,
        total_findings=len(findings_response),
        findings=findings_response,
        score_after=score
    )
