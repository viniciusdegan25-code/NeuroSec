import os
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional

from app.db.database import get_db
from app.db.models import Vulnerability, AuditLog
from app.schemas.ai import RemediationRequest, RemediationResponse
from app.services.ai_service import AISecurityEngine

router = APIRouter()

PATCHES_DIR = "patches"
if not os.path.exists(PATCHES_DIR):
    os.makedirs(PATCHES_DIR)

@router.post("/{internal_id}", response_model=RemediationResponse, summary="Gera remediação, código corrigido e diff via IA")
async def remediate_vulnerability(
    internal_id: int, 
    payload: Optional[RemediationRequest] = Body(default=None),
    db: Session = Depends(get_db)
):
    vuln = db.query(Vulnerability).filter(Vulnerability.internal_id == internal_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail=f"Vulnerabilidade #{internal_id} não encontrada no banco.")

    custom_notes = payload.custom_instructions if payload else None

    # Dispara a IA Groq para gerar a correção e o diff
    ai_result = await AISecurityEngine.generate_remediation_patch(
        vuln_type=vuln.vuln_type,
        asset_name=vuln.asset_name,
        original_code=vuln.original_code or "",
        severity=vuln.severity,
        custom_prompt=custom_notes
    )

    # Grava arquivo físico de patch
    sanitized_asset = vuln.asset_name.replace("https://", "").replace("http://", "").replace("/", "_").replace("\\", "_")
    patch_filename = f"fix_id_{vuln.internal_id}_{sanitized_asset}"
    if not patch_filename.endswith((".py", ".conf", ".tf", ".json", ".txt")):
        patch_filename += ".py"

    patch_path = os.path.join(PATCHES_DIR, patch_filename)
    try:
        with open(patch_path, "w", encoding="utf-8") as f:
            f.write(ai_result["fixed_code"])
    except Exception:
        pass

    # Atualiza registro no banco relacional
    vuln.ai_diagnosis = ai_result["diagnosis"]
    vuln.fixed_code = ai_result["fixed_code"]
    vuln.patch_file = patch_path
    vuln.status = "patch_ready"
    vuln.updated_at = datetime.now().strftime("%d/%m/%Y %H:%M")

    # Registra no Audit Log
    audit = AuditLog(
        action="AI_PATCH_GENERATED",
        target_vuln_id=vuln.internal_id,
        vuln_key=vuln.key,
        operator="NeuroSec IA",
        details=f"Patch de segurança gerado pela NeuroSec IA para a falha '{vuln.vuln_type}' no ativo '{vuln.asset_name}'.",
        diff_preview=ai_result["diff"][:500]
    )
    db.add(audit)
    db.commit()
    db.refresh(vuln)

    return RemediationResponse(
        status="success",
        internal_id=vuln.internal_id,
        vuln_key=vuln.key,
        diagnosis=ai_result["diagnosis"],
        fixed_code=ai_result["fixed_code"],
        diff=ai_result["diff"],
        patch_file=patch_path,
        owasp_category=vuln.owasp_category,
        bandit_compliance=ai_result.get("bandit_compliance", True)
    )

@router.get("/{internal_id}/dossier", summary="Gera o Dossiê Técnico Completo e Aprofundado de Remediação com IA")
async def get_remediation_dossier(
    internal_id: int,
    db: Session = Depends(get_db)
):
    vuln = db.query(Vulnerability).filter(Vulnerability.internal_id == internal_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail=f"Vulnerabilidade #{internal_id} não encontrada.")

    dossier = await AISecurityEngine.generate_deep_remediation_dossier(
        vuln_type=vuln.vuln_type,
        asset_name=vuln.asset_name,
        original_code=vuln.original_code or "",
        severity=vuln.severity,
        cve_id=vuln.cve_id,
        owasp_category=vuln.owasp_category
    )

    return dossier

@router.post("/{internal_id}/approve", summary="Aprova formalmente o patch de segurança e aplica remediação")
def approve_patch(
    internal_id: int, 
    operator: str = "SecOps Lead",
    notes: str = "Patch validado e aprovado para deploy em produção",
    db: Session = Depends(get_db)
):
    vuln = db.query(Vulnerability).filter(Vulnerability.internal_id == internal_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail=f"Vulnerabilidade #{internal_id} não encontrada.")

    vuln.status = "remediated"
    vuln.updated_at = datetime.now().strftime("%d/%m/%Y %H:%M")

    audit = AuditLog(
        action="PATCH_APPROVED",
        target_vuln_id=vuln.internal_id,
        vuln_key=vuln.key,
        operator=operator,
        details=f"Patch aprovado por '{operator}'. Notas: {notes}",
        diff_preview=f"Patch aplicado no arquivo: {vuln.patch_file}"
    )
    db.add(audit)
    db.commit()
    db.refresh(vuln)

    return {
        "status": "success",
        "message": f"Patch da vulnerabilidade {internal_id} aprovado com sucesso.",
        "vuln_status": vuln.status
    }
