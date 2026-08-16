from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime

from app.db.database import get_db
from app.db.models import Vulnerability
from app.schemas.ai import ChatRequest, ChatResponse
from app.services.ai_service import AISecurityEngine

router = APIRouter()

@router.post("/chat", response_model=ChatResponse, summary="Conversa ativa com o NeuroSec AI Copilot")
async def chat_copilot(payload: ChatRequest, db: Session = Depends(get_db)):
    context_str = None
    if payload.context_vuln_id:
        vuln = db.query(Vulnerability).filter(Vulnerability.internal_id == payload.context_vuln_id).first()
        if vuln:
            context_str = f"Falha ID {vuln.internal_id}: {vuln.vuln_type} no ativo {vuln.asset_name} ({vuln.severity}). Status: {vuln.status}."

    reply = await AISecurityEngine.chat_with_copilot(payload.message, context=context_str)

    # Sugestões de ação rápida contextuais
    suggestions = [
        "Como calcular a pontuação CVSS v3.1 desta falha?",
        "Qual o impacto no relatório de conformidade LGPD?",
        "Gere um script de teste unitário para validar o patch."
    ]

    return ChatResponse(
        reply=reply,
        suggested_actions=suggestions,
        timestamp=datetime.now().strftime("%H:%M:%S")
    )
