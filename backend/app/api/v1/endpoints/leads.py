from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.db.database import get_db
from app.db.models import EnterpriseLead, AuditLog
from app.schemas.lead import EnterpriseLeadCreate, EnterpriseLeadResponse

router = APIRouter()

@router.post("", response_model=EnterpriseLeadResponse, summary="Registra uma solicitação de avaliação corporativa / onboarding")
def create_lead(payload: EnterpriseLeadCreate, db: Session = Depends(get_db)):
    if not payload.name or not payload.corporate_email or not payload.company_name:
        raise HTTPException(status_code=400, detail="Nome, e-mail corporativo e nome da empresa são obrigatórios.")

    lead = EnterpriseLead(
        name=payload.name.strip(),
        corporate_email=payload.corporate_email.strip(),
        company_name=payload.company_name.strip(),
        job_title=(payload.job_title or "Executivo / DevSecOps").strip(),
        company_size=(payload.company_size or "50-200").strip(),
        main_challenge=(payload.main_challenge or "ASPM & Postura de Segurança").strip(),
        status="new"
    )
    db.add(lead)
    db.commit()
    db.refresh(lead)

    # Registra no log de auditoria
    audit = AuditLog(
        action="LEAD_EVALUATION_REQUESTED",
        operator=lead.name,
        details=f"Solicitação de avaliação recebida da empresa '{lead.company_name}' ({lead.corporate_email}). Porte: {lead.company_size}. Desafio: {lead.main_challenge}"
    )
    db.add(audit)
    db.commit()

    return lead

@router.get("", response_model=List[EnterpriseLeadResponse], summary="Lista as solicitações de avaliação empresarial sob gestão")
def list_leads(limit: int = 50, db: Session = Depends(get_db)):
    return db.query(EnterpriseLead).order_by(EnterpriseLead.id.desc()).limit(limit).all()
