from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    message: str
    context_vuln_id: Optional[int] = None
    history: Optional[List[ChatMessage]] = []

class ChatResponse(BaseModel):
    reply: str
    suggested_actions: Optional[List[str]] = []
    timestamp: str

class RemediationRequest(BaseModel):
    internal_id: int
    custom_instructions: Optional[str] = None

class RemediationResponse(BaseModel):
    status: str
    internal_id: int
    vuln_key: str
    diagnosis: str
    fixed_code: str
    diff: str
    patch_file: Optional[str] = None
    owasp_category: Optional[str] = None
    bandit_compliance: bool = True
