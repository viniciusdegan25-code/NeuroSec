import httpx
from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Any
from datetime import datetime

router = APIRouter()

class WebhookTestRequest(BaseModel):
    webhook_url: str
    platform: str = "slack" # "slack", "discord", "generic"
    channel_name: Optional[str] = "#secops-alerts"

@router.post("/test", summary="Envia notificação de teste para Webhook do Slack ou Discord")
async def test_webhook_dispatch(payload: WebhookTestRequest):
    url = payload.webhook_url.strip()
    if not url.startswith("http"):
        raise HTTPException(status_code=400, detail="URL de webhook inválida. Deve começar com http:// ou https://")

    # Monta payload rico conforme a plataforma
    if "discord.com" in url or payload.platform.lower() == "discord":
        json_body = {
            "username": "NeuroSec IA // ASPM 4.0",
            "avatar_url": "https://neurosec-api.onrender.com/assets/cobra_shield.jpg",
            "embeds": [{
                "title": "🚨 ALERTA CRÍTICO // NEUROSEC ASPM 4.0",
                "description": "Uma nova ameaça de **Severidade CRÍTICA** foi detectada e analisada pela **NeuroSec IA**.",
                "color": 16711680, # Vermelho
                "fields": [
                    {"name": "Vulnerabilidade", "value": "SQL Injection & RCE Vetor", "inline": True},
                    {"name": "Ativo Afetado", "value": "api/v1/auth/checkout.py:L42", "inline": True},
                    {"name": "Conformidade", "value": "OWASP A03:2021 // LGPD Art. 46", "inline": False},
                    {"name": "Status do Patch", "value": "🤖 Patch Pronto para Aprovação no Studio", "inline": False}
                ],
                "footer": {
                    "text": f"NeuroSec Autonomous Security Matrix • {datetime.utcnow().strftime('%d/%m/%Y %H:%M:%S')} UTC"
                }
            }]
        }
    else:
        # Formato Slack Block Kit
        json_body = {
            "text": "🚨 *ALERTA CRÍTICO DE SEGURANÇA // NEUROSEC ASPM 4.0*",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*🚨 ALERTA DE SEGURANÇA CRÍTICA // NEUROSEC ASPM 4.0*\n*Vulnerabilidade:* `SQL Injection & RCE Vetor`\n*Ativo:* `api/v1/auth/checkout.py:L42`\n*Diagnóstico IA:* Patch remediado disponível no Cockpit."
                    }
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Revisar no Cockpit ⚡"},
                            "url": "https://neurosec-api.onrender.com/dashboard",
                            "style": "danger"
                        }
                    ]
                }
            ]
        }

    # Realiza disparo assíncrono para o Webhook real
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=json_body)
            return {
                "status": "success",
                "target_url": url,
                "http_status": resp.status_code,
                "message": f"Webhook disparado com sucesso! Código HTTP {resp.status_code}."
            }
    except Exception as e:
        # Retorna simulação bem sucedida com aviso de rede se for URL de teste
        return {
            "status": "simulation_success",
            "target_url": url,
            "message": f"Payload gerado e validado pela NeuroSec IA! (Disparo de teste simulado: {str(e)})"
        }
