from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class SastCodeScanRequest(BaseModel):
    code: str
    filename: Optional[str] = "snippet.py"
    language: Optional[str] = "python"

class DastUrlScanRequest(BaseModel):
    url: str
    deep_scan: Optional[bool] = True

class ScaFileScanRequest(BaseModel):
    content: str
    filename: Optional[str] = "requirements.txt"

class CloudScanRequest(BaseModel):
    provider: Optional[str] = "AWS"
    config_text: Optional[str] = None

class ScanResultItem(BaseModel):
    type: str
    severity: str
    line: int
    asset: str
    description: str
    code_snippet: Optional[str] = None
    cve_id: Optional[str] = None
    owasp: Optional[str] = None

class ScanResponse(BaseModel):
    status: str
    scan_type: str
    target: str
    new_findings: int
    total_findings: int
    findings: List[ScanResultItem]
    score_after: int
