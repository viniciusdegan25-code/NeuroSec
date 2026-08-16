from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from app.db.database import get_db
from app.db.models import Vulnerability, ScanHistory
from app.schemas.scan import SastCodeScanRequest, ScanResponse, ScanResultItem
from app.services.sast_service import SastEngine
from app.services.scorecard_service import ScorecardService

router = APIRouter()

@router.post("/snippet", response_model=ScanResponse, summary="Executa scan SAST em um trecho de código enviado pelo usuário")
def scan_sast_snippet(payload: SastCodeScanRequest, db: Session = Depends(get_db)):
    findings = SastEngine.scan_code_string(payload.code, filename=payload.filename or "snippet.py")
    
    # Obter próximo internal_id
    max_id = db.query(Vulnerability).order_by(Vulnerability.internal_id.desc()).first()
    next_id = (max_id.internal_id + 1) if max_id else 1
    
    new_findings_count = 0
    findings_response = []
    
    for f in findings:
        key = f"sast_{f['rule_id'].lower()}_{next_id}"
        
        # Verifica se já existe a mesma regra na mesma linha do ativo
        exists = db.query(Vulnerability).filter(
            Vulnerability.asset_name == f["asset_name"],
            Vulnerability.line_number == f["line_number"],
            Vulnerability.vuln_type == f["vuln_type"]
        ).first()
        
        if not exists:
            new_vuln = Vulnerability(
                key=key,
                internal_id=next_id,
                asset_type="CODE",
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
                fixed_code="# Aguardando acionamento da IA para remediação",
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
    
    # Registra no histórico de varreduras
    score = ScorecardService.calculate_metrics(db).score
    scan_history = ScanHistory(
        scan_type="SAST",
        target=payload.filename or "Code Snippet",
        findings_count=len(findings_response),
        critical_count=sum(1 for f in findings if f["severity"] == "CRITICAL"),
        high_count=sum(1 for f in findings if f["severity"] == "HIGH"),
        score_snapshot=score
    )
    db.add(scan_history)
    db.commit()

    total_vulns = db.query(Vulnerability).count()

    return ScanResponse(
        status="success",
        scan_type="SAST",
        target=payload.filename or "snippet.py",
        new_findings=new_findings_count,
        total_findings=len(findings_response),
        findings=findings_response,
        score_after=score
    )

@router.post("/directory", response_model=ScanResponse, summary="Executa scan SAST em arquivos do diretório do projeto")
def scan_sast_directory(path: str = ".", db: Session = Depends(get_db)):
    findings = SastEngine.scan_directory(path)
    
    max_id = db.query(Vulnerability).order_by(Vulnerability.internal_id.desc()).first()
    next_id = (max_id.internal_id + 1) if max_id else 1
    new_findings_count = 0
    findings_response = []

    for f in findings:
        key = f"sast_{f['rule_id'].lower()}_{next_id}"
        exists = db.query(Vulnerability).filter(
            Vulnerability.asset_name == f["asset_name"],
            Vulnerability.line_number == f["line_number"],
            Vulnerability.vuln_type == f["vuln_type"]
        ).first()

        if not exists:
            new_vuln = Vulnerability(
                key=key,
                internal_id=next_id,
                asset_type="CODE",
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
                fixed_code="# Aguardando acionamento da IA para remediação",
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

    return ScanResponse(
        status="success",
        scan_type="SAST_DIRECTORY",
        target=path,
        new_findings=new_findings_count,
        total_findings=len(findings_response),
        findings=findings_response,
        score_after=score
    )
