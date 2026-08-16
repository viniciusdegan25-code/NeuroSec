from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

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

@router.delete("/{internal_id}", summary="Exclui ou marca como falso positivo uma vulnerabilidade")
def delete_vulnerability(
    internal_id: int, 
    operator: str = "SecOps Lead", 
    reason: str = "Descarte manual",
    db: Session = Depends(get_db)
):
    vuln = db.query(Vulnerability).filter(Vulnerability.internal_id == internal_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerabilidade não encontrada.")
    
    audit_entry = AuditLog(
        action="VULN_DELETED",
        target_vuln_id=vuln.internal_id,
        vuln_key=vuln.key,
        operator=operator,
        details=f"Vulnerabilidade '{vuln.vuln_type}' no ativo '{vuln.asset_name}' excluída. Motivo: {reason}"
    )
    db.add(audit_entry)
    db.delete(vuln)
    db.commit()
    return {"status": "success", "message": f"Vulnerabilidade {internal_id} removida com sucesso."}
