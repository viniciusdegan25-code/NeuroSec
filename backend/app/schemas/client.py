from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any

class ClientCreateRequest(BaseModel):
    name: str
    cnpj: Optional[str] = None
    contact_name: str
    contact_email: str
    contact_phone: Optional[str] = None
    sla_tier: Optional[str] = "ENTERPRISE_24_7"
    industry: Optional[str] = "FINTECH"
    annual_revenue_brl: Optional[float] = 50000000.0
    sensitive_records_count: Optional[int] = 100000
    downtime_cost_per_hour: Optional[float] = 25000.0
    criticality_level: Optional[str] = "TIER_1_SYSTEMIC"
    notes: Optional[str] = None

class ClientUpdateRequest(BaseModel):
    name: Optional[str] = None
    cnpj: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    sla_tier: Optional[str] = None
    industry: Optional[str] = None
    annual_revenue_brl: Optional[float] = None
    sensitive_records_count: Optional[int] = None
    downtime_cost_per_hour: Optional[float] = None
    criticality_level: Optional[str] = None
    status: Optional[str] = None
    notes: Optional[str] = None

class ClientResponse(BaseModel):
    id: int
    name: str
    cnpj: Optional[str] = None
    contact_name: str
    contact_email: str
    contact_phone: Optional[str] = None
    sla_tier: str
    industry: str
    annual_revenue_brl: Optional[float] = 50000000.0
    sensitive_records_count: Optional[int] = 100000
    downtime_cost_per_hour: Optional[float] = 25000.0
    financial_loss_avoided_brl: Optional[float] = 0.0
    financial_exposure_risk_brl: Optional[float] = 0.0
    criticality_level: Optional[str] = "TIER_1_SYSTEMIC"
    security_score: int
    monitored_assets_count: int
    open_vulns_count: int
    status: str
    notes: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    class Config:
        from_attributes = True

class ClientFinancialAnalysisResponse(BaseModel):
    client_id: int
    client_name: str
    industry: str
    annual_revenue_brl: float
    sensitive_records_count: int
    downtime_cost_per_hour: float
    cost_per_record_brl: float
    financial_exposure_risk_brl: float
    financial_loss_avoided_brl: float
    data_breach_risk_brl: float
    downtime_risk_brl: float
    regulatory_fine_risk_brl: float
    security_score: int
    grade: str
    posture_status: str
    open_vulns_count: int
    remediated_vulns_count: int
    compliance_matrix: Optional[Dict[str, Any]] = None
    methodology: str

class ClientSummaryResponse(BaseModel):
    total_clients: int
    active_clients: int
    average_score: int
    critical_risk_clients: int
    total_monitored_assets: int
    total_financial_loss_avoided_brl: float
    total_financial_exposure_risk_brl: float
    clients: List[ClientResponse]

