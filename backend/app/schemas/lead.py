from pydantic import BaseModel, EmailStr
from typing import Optional

class EnterpriseLeadCreate(BaseModel):
    name: str
    corporate_email: str
    company_name: str
    job_title: Optional[str] = "Executivo / DevSecOps"
    company_size: Optional[str] = "50-200"
    main_challenge: Optional[str] = "Automação de Segurança & ASPM"

class EnterpriseLeadResponse(BaseModel):
    id: int
    name: str
    corporate_email: str
    company_name: str
    job_title: str
    company_size: str
    main_challenge: str
    status: str
    created_at: str

    class Config:
        from_attributes = True
