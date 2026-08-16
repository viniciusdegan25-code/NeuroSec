from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from app.db.database import get_db
from app.db.models import AuditLog
from app.schemas.audit import AuditLogResponse, AuditLogCreate

router = APIRouter()

@router.get("", response_model=List[AuditLogResponse], summary="Lista a trilha de auditoria completa")
def get_audit_trail(limit: int = 50, db: Session = Depends(get_db)):
    return db.query(AuditLog).order_by(AuditLog.id.desc()).limit(limit).all()

@router.post("", response_model=AuditLogResponse, summary="Registra manualmente uma ação na trilha de auditoria")
def create_audit_entry(payload: AuditLogCreate, db: Session = Depends(get_db)):
    entry = AuditLog(
        action=payload.action,
        target_vuln_id=payload.target_vuln_id,
        vuln_key=payload.vuln_key,
        operator=payload.operator or "SecOps Lead",
        details=payload.details,
        diff_preview=payload.diff_preview
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
