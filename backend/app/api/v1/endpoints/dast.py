from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime

from app.db.database import get_db
from app.db.models import Vulnerability, ScanHistory
from app.schemas.scan import DastUrlScanRequest, ScanResponse, ScanResultItem
from app.services.dast_service import DastEngine
from app.services.scorecard_service import ScorecardService

router = APIRouter()

@router.post("/url", response_model=ScanResponse, summary="Executa scan DAST e auditoria de headers em uma URL alvo")
async def scan_dast_url(payload: DastUrlScanRequest, db: Session = Depends(get_db)):
    result = await DastEngine.scan_url(payload.url)
    
    findings = result.get("findings", [])
    
    # Tratamento gracioso para URLs inacessíveis ou offline
    if "error" in result and not findings:
        findings.append({
            "vuln_type": "Alvo Inacessível / Timeout de Conexão",
            "severity": "MEDIUM",
            "cvss_score": 5.0,
            "owasp_category": "A05:2021 - Security Misconfiguration",
            "line_number": 0,
            "asset_name": payload.url,
            "asset_type": "URL",
            "description": f"O servidor alvo não respondeu à tentativa de conexão ({result['error']}). Verifique se o endereço está correto e se o servidor aceita tráfego externo.",
            "code_snippet": f"Erro de Conexão: {result['error']}"
        })

    max_id = db.query(Vulnerability).order_by(Vulnerability.internal_id.desc()).first()
    next_id = (max_id.internal_id + 1) if max_id else 1
    new_findings_count = 0
    findings_response = []

    for f in findings:
        key = f"dast_url_{next_id}"
        exists = db.query(Vulnerability).filter(
            Vulnerability.asset_name == f["asset_name"],
            Vulnerability.vuln_type == f["vuln_type"]
        ).first()

        if not exists:
            new_vuln = Vulnerability(
                key=key,
                internal_id=next_id,
                asset_type="URL",
                asset_name=f["asset_name"],
                vuln_type=f["vuln_type"],
                owasp_category=f["owasp_category"],
                line_number=0,
                severity=f["severity"],
                cvss_score=f["cvss_score"],
                status="open",
                days_open=1,
                ai_diagnosis=f["description"],
                original_code=f["code_snippet"],
                fixed_code="# Configurar cabeçalho no Reverse Proxy / Web Server",
                created_at=datetime.now().strftime("%d/%m/%Y %H:%M")
            )
            db.add(new_vuln)
            next_id += 1
            new_findings_count += 1

        findings_response.append(ScanResultItem(
            type=f["vuln_type"],
            severity=f["severity"],
            line=0,
            asset=f["asset_name"],
            description=f["description"],
            code_snippet=f["code_snippet"],
            owasp=f["owasp_category"]
        ))

    db.commit()
    score = ScorecardService.calculate_metrics(db).score

    scan_history = ScanHistory(
        scan_type="DAST",
        target=payload.url,
        findings_count=len(findings_response),
        critical_count=sum(1 for f in findings if f["severity"] == "CRITICAL"),
        high_count=sum(1 for f in findings if f["severity"] == "HIGH"),
        score_snapshot=score
    )
    db.add(scan_history)
    db.commit()

    return ScanResponse(
        status="success",
        scan_type="DAST_URL",
        target=payload.url,
        new_findings=new_findings_count,
        total_findings=len(findings_response),
        findings=findings_response,
        score_after=score
    )
