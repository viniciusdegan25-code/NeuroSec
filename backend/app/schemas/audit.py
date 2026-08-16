from pydantic import BaseModel
from typing import Optional

class AuditLogCreate(BaseModel):
    action: str
    target_vuln_id: Optional[int] = None
    vuln_key: Optional[str] = None
    operator: Optional[str] = "SecOps Lead"
    details: str
    diff_preview: Optional[str] = None

class AuditLogResponse(BaseModel):
    id: int
    action: str
    target_vuln_id: Optional[int] = None
    vuln_key: Optional[str] = None
    operator: str
    details: str
    diff_preview: Optional[str] = None
    timestamp: str

    class Config:
        from_attributes = True
