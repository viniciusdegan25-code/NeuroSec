from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from datetime import datetime

from app.db.database import get_db
from app.db.models import ClientOrganization, Vulnerability, Asset, AuditLog, ScanHistory
from app.services.scorecard_service import ScorecardService
from app.schemas.client import (
    ClientCreateRequest, ClientUpdateRequest, ClientResponse, 
    ClientSummaryResponse, ClientFinancialAnalysisResponse
)

router = APIRouter()

@router.get("", response_model=List[ClientResponse], summary="Lista todas as empresas clientes e seus níveis de postura")
def list_clients(db: Session = Depends(get_db)):
    clients = db.query(ClientOrganization).order_by(ClientOrganization.id.asc()).all()
    
    # Atualiza contadores dinâmicos e riscos financeiros contextualizados
    for c in clients:
        vulns = db.query(Vulnerability).filter(Vulnerability.client_id == c.id).all()
        assets = db.query(Asset).filter(Asset.client_id == c.id).all()
        
        c.monitored_assets_count = len(assets) or c.monitored_assets_count
        c.open_vulns_count = sum(1 for v in vulns if v.status in ["open", "patch_ready"])
        
        # Análise financeira estocástica
        fin_data = ScorecardService.calculate_client_financial_risk(c, vulns, assets)
        c.financial_exposure_risk_brl = fin_data["financial_exposure_risk_brl"]
        c.financial_loss_avoided_brl = fin_data["financial_loss_avoided_brl"]
        c.security_score = fin_data["security_score"]

    return clients

@router.get("/summary", response_model=ClientSummaryResponse, summary="Resumo executivo do portfólio de clientes corporativos")
def get_clients_summary(db: Session = Depends(get_db)):
    clients = db.query(ClientOrganization).order_by(ClientOrganization.id.asc()).all()
    
    total_loss_avoided = 0.0
    total_exposure = 0.0

    for c in clients:
        vulns = db.query(Vulnerability).filter(Vulnerability.client_id == c.id).all()
        assets = db.query(Asset).filter(Asset.client_id == c.id).all()
        c.monitored_assets_count = len(assets) or c.monitored_assets_count
        c.open_vulns_count = sum(1 for v in vulns if v.status in ["open", "patch_ready"])

        fin_data = ScorecardService.calculate_client_financial_risk(c, vulns, assets)
        c.financial_exposure_risk_brl = fin_data["financial_exposure_risk_brl"]
        c.financial_loss_avoided_brl = fin_data["financial_loss_avoided_brl"]
        c.security_score = fin_data["security_score"]

        total_loss_avoided += fin_data["financial_loss_avoided_brl"]
        total_exposure += fin_data["financial_exposure_risk_brl"]

    total = len(clients)
    active = sum(1 for c in clients if c.status == "active")
    avg_score = int(sum(c.security_score for c in clients) / total) if total > 0 else 100
    crit_risk = sum(1 for c in clients if c.security_score < 75 or c.open_vulns_count >= 2)
    total_assets = sum(c.monitored_assets_count for c in clients)

    return ClientSummaryResponse(
        total_clients=total,
        active_clients=active,
        average_score=avg_score,
        critical_risk_clients=crit_risk,
        total_monitored_assets=total_assets,
        total_financial_loss_avoided_brl=round(total_loss_avoided, 2),
        total_financial_exposure_risk_brl=round(total_exposure, 2),
        clients=clients
    )

@router.get("/{client_id}/financial-analysis", response_model=ClientFinancialAnalysisResponse, summary="Análise de impacto financeiro personalizada por empresa (FAIR/NIST/LGPD)")
def get_client_financial_analysis(client_id: int, db: Session = Depends(get_db)):
    client = db.query(ClientOrganization).filter(ClientOrganization.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail=f"Cliente #{client_id} não encontrado.")

    vulns = db.query(Vulnerability).filter(Vulnerability.client_id == client_id).all()
    assets = db.query(Asset).filter(Asset.client_id == client_id).all()

    fin_analysis = ScorecardService.calculate_client_financial_risk(client, vulns, assets)
    return ClientFinancialAnalysisResponse(**fin_analysis)

@router.get("/{client_id}", summary="Detalhes aprofundados do cliente e seus ativos vinculados")
def get_client_details(client_id: int, db: Session = Depends(get_db)):
    client = db.query(ClientOrganization).filter(ClientOrganization.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail=f"Cliente #{client_id} não encontrado.")
    
    assets = db.query(Asset).filter(Asset.client_id == client_id).all()
    vulns = db.query(Vulnerability).filter(Vulnerability.client_id == client_id).all()
    fin_analysis = ScorecardService.calculate_client_financial_risk(client, vulns, assets)

    return {
        "client": client,
        "assets": assets,
        "vulnerabilities": vulns,
        "financial_analysis": fin_analysis,
        "metrics": {
            "total_assets": len(assets),
            "open_vulns": sum(1 for v in vulns if v.status in ["open", "patch_ready"]),
            "remediated_vulns": sum(1 for v in vulns if v.status == "remediated"),
            "security_score": fin_analysis["security_score"],
            "grade": fin_analysis["grade"],
            "posture_status": fin_analysis["posture_status"],
            "financial_exposure_risk_brl": fin_analysis["financial_exposure_risk_brl"],
            "financial_loss_avoided_brl": fin_analysis["financial_loss_avoided_brl"]
        }
    }

@router.post("", response_model=ClientResponse, summary="Cadastra uma nova empresa cliente na esteira de monitoramento ASPM")
def create_client(payload: ClientCreateRequest, db: Session = Depends(get_db)):
    exists = db.query(ClientOrganization).filter(ClientOrganization.name == payload.name.strip()).first()
    if exists:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Já existe uma empresa cadastrada com a razão social/nome '{payload.name}'."
        )

    new_client = ClientOrganization(
        name=payload.name.strip(),
        cnpj=payload.cnpj.strip() if payload.cnpj else None,
        contact_name=payload.contact_name.strip(),
        contact_email=payload.contact_email.strip().lower(),
        contact_phone=payload.contact_phone.strip() if payload.contact_phone else None,
        sla_tier=payload.sla_tier or "ENTERPRISE_24_7",
        industry=payload.industry or "FINTECH",
        annual_revenue_brl=payload.annual_revenue_brl or 50000000.0,
        sensitive_records_count=payload.sensitive_records_count or 100000,
        downtime_cost_per_hour=payload.downtime_cost_per_hour or 25000.0,
        criticality_level=payload.criticality_level or "TIER_1_SYSTEMIC",
        security_score=85,
        monitored_assets_count=2,
        open_vulns_count=1,
        status="active",
        notes=payload.notes
    )
    db.add(new_client)
    db.commit()
    db.refresh(new_client)

    # Cria ativo inicial de demonstração para a nova organização (idempotente)
    asset_domain = f"api.{new_client.name.lower().replace(' ', '-').replace('.', '')}-{new_client.id}.com.br"
    exists_asset = db.query(Asset).filter(Asset.name == asset_domain).first()
    if not exists_asset:
        demo_asset = Asset(
            client_id=new_client.id,
            name=asset_domain,
            asset_type="WEB_APP",
            criticality="TIER_1_CRITICAL"
        )
        db.add(demo_asset)

    # Registra no log de auditoria
    db.add(AuditLog(
        action="CLIENT_ORGANIZATION_CREATED",
        operator="SecOps Lead",
        details=f"Nova empresa cliente '{new_client.name}' (CNPJ: {new_client.cnpj or 'N/A'}) integrada ao ecossistema NeuroSec ASPM.",
        diff_preview=f"SLA: {new_client.sla_tier} | Faturamento: R$ {new_client.annual_revenue_brl:,.2f} | Registros LGPD: {new_client.sensitive_records_count:,}"
    ))
    db.commit()
    db.refresh(new_client)

    return new_client

@router.put("/{client_id}", response_model=ClientResponse, summary="Atualiza dados corporativos ou SLA de um cliente")
def update_client(client_id: int, payload: ClientUpdateRequest, db: Session = Depends(get_db)):
    client = db.query(ClientOrganization).filter(ClientOrganization.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail=f"Cliente #{client_id} não encontrado.")

    if payload.name: client.name = payload.name.strip()
    if payload.cnpj is not None: client.cnpj = payload.cnpj.strip()
    if payload.contact_name: client.contact_name = payload.contact_name.strip()
    if payload.contact_email: client.contact_email = payload.contact_email.strip().lower()
    if payload.contact_phone is not None: client.contact_phone = payload.contact_phone.strip()
    if payload.sla_tier: client.sla_tier = payload.sla_tier
    if payload.industry: client.industry = payload.industry
    if payload.annual_revenue_brl is not None: client.annual_revenue_brl = payload.annual_revenue_brl
    if payload.sensitive_records_count is not None: client.sensitive_records_count = payload.sensitive_records_count
    if payload.downtime_cost_per_hour is not None: client.downtime_cost_per_hour = payload.downtime_cost_per_hour
    if payload.criticality_level is not None: client.criticality_level = payload.criticality_level
    if payload.status: client.status = payload.status
    if payload.notes is not None: client.notes = payload.notes
    client.updated_at = datetime.now().strftime("%d/%m/%Y %H:%M")

    db.add(AuditLog(
        action="CLIENT_ORGANIZATION_UPDATED",
        operator="SecOps Lead",
        details=f"Dados cadastrais e parâmetros de risco da organização '{client.name}' atualizados com sucesso."
    ))
    db.commit()
    db.refresh(client)

    return client

@router.delete("/{client_id}", summary="Remove ou desativa um cliente corporativo")
def delete_client(client_id: int, db: Session = Depends(get_db)):
    client = db.query(ClientOrganization).filter(ClientOrganization.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail=f"Cliente #{client_id} não encontrado.")

    client_name = client.name
    # Remove ativos associados
    db.query(Asset).filter(Asset.client_id == client_id).delete()
    db.delete(client)
    db.add(AuditLog(
        action="CLIENT_ORGANIZATION_DELETED",
        operator="SecOps Lead",
        details=f"Organização cliente '{client_name}' removida da plataforma pelo operador."
    ))
    db.commit()

    return {"status": "success", "message": f"Cliente '{client_name}' removido com sucesso."}

@router.post("/{client_id}/scan", summary="Dispara uma varredura de integridade completa em todos os ativos do cliente")
def trigger_client_scan(client_id: int, db: Session = Depends(get_db)):
    client = db.query(ClientOrganization).filter(ClientOrganization.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail=f"Cliente #{client_id} não encontrado.")

    # Simula cálculo de melhoria de postura e auditoria
    client.security_score = min(100, client.security_score + 3)
    client.updated_at = datetime.now().strftime("%d/%m/%Y %H:%M")

    db.add(ScanHistory(
        scan_type="FULL_CLIENT_AUDIT",
        target=f"Cliente: {client.name}",
        client_id=client.id,
        findings_count=client.open_vulns_count,
        score_snapshot=client.security_score
    ))

    db.add(AuditLog(
        action="CLIENT_SCAN_EXECUTED",
        operator="NeuroSec IA",
        details=f"Varredura autônoma concluída para {client.name}. Score consolidado: {client.security_score}/100."
    ))
    db.commit()
    db.refresh(client)

    return {
        "status": "success",
        "message": f"Varredura autônoma para o cliente '{client.name}' concluída com sucesso!",
        "new_security_score": client.security_score,
        "monitored_assets": client.monitored_assets_count,
        "open_vulns": client.open_vulns_count
    }
