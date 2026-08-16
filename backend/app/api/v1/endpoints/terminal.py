from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, Any, List
import shlex

from app.db.database import get_db
from app.db.models import Vulnerability, AuditLog
from app.services.scorecard_service import ScorecardService
from app.services.sast_service import SastEngine
from app.services.dast_service import DastEngine

router = APIRouter()

class TerminalCommandRequest(BaseModel):
    command: str

@router.post("/execute", summary="Executa comandos no Cyber Terminal Interativo do NeuroSec")
async def execute_terminal_command(payload: TerminalCommandRequest, db: Session = Depends(get_db)):
    cmd_raw = payload.command.strip()
    if not cmd_raw:
        return {"output": "", "type": "empty"}

    parts = shlex.split(cmd_raw)
    root_cmd = parts[0].lower()

    if root_cmd in ["help", "?"]:
        output = (
            "NEUROSEC CYBER CLI v3.0.0 — Comandos Disponíveis:\n"
            "-----------------------------------------------------------------\n"
            "  help                      Exibe este menu de ajuda com a sintaxe.\n"
            "  scorecard                 Exibe o resumo executivo da postura atual.\n"
            "  list [status/severidade]  Lista vulnerabilidades ativas (ex: list open).\n"
            "  scan --sast [codigo]      Executa varredura SAST inline.\n"
            "  recon --url [alvo]        Executa varredura DAST em uma URL.\n"
            "  remediate --id [num]      Dispara a IA para gerar patch para o ID.\n"
            "  approve --id [num]        Aprova o patch e registra em auditoria.\n"
            "  audit                     Exibe os últimos 5 registros de governança.\n"
            "  clear                     Limpa a tela do terminal interativo.\n"
        )
        return {"output": output, "type": "text"}

    elif root_cmd == "scorecard":
        metrics = ScorecardService.calculate_metrics(db)
        output = (
            f"[+] SECURITY SCORECARD STATUS: {metrics.score}/100 ({metrics.grade})\n"
            f"[+] Postura: {metrics.posture_status}\n"
            f"[+] Vulnerabilidades Abertas: {metrics.open_vulnerabilities} | Remediadas: {metrics.remediated_vulnerabilities}\n"
            f"[+] Prejuizo Evitado Estimado: R$ {metrics.loss_avoided_brl:,.2f}\n"
            f"[+] MTTR Medio: {metrics.mttr_days} dias\n"
        )
        return {"output": output, "type": "success"}

    elif root_cmd == "list":
        vulns = db.query(Vulnerability).all()
        if not vulns:
            return {"output": "[*] Nenhuma vulnerabilidade registrada no banco relacional.", "type": "info"}
        
        lines = ["ID  | SEV      | TIPO                      | ATIVO", "--------------------------------------------------------"]
        for v in vulns[:10]:
            lines.append(f"#{v.internal_id:<3} | {v.severity:<8} | {v.vuln_type[:24]:<24} | {v.asset_name[:20]}")
        return {"output": "\n".join(lines), "type": "text"}

    elif root_cmd in ["recon", "dast"]:
        url = None
        for i, p in enumerate(parts):
            if p in ["--url", "-u"] and i + 1 < len(parts):
                url = parts[i + 1]
        if not url:
            return {"output": "[!] Uso: recon --url https://alvo.com.br", "type": "error"}
        
        res = await DastEngine.scan_url(url)
        findings = res.get("findings", [])
        lines = [
            f"[+] Reconhecimento DAST finalizado para {url}",
            f"[+] Status HTTP: {res.get('status_code', 'N/A')} | HTTPS: {res.get('is_https')}",
            f"[+] Falhas detectadas: {len(findings)}"
        ]
        for f in findings:
            lines.append(f"    -> [{f['severity']}] {f['vuln_type']}")
        return {"output": "\n".join(lines), "type": "success"}

    elif root_cmd == "audit":
        audits = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(5).all()
        if not audits:
            return {"output": "[*] Trilha de auditoria vazia.", "type": "info"}
        lines = ["[+] ULTIMOS EVENTOS DE GOVERNANCA:"]
        for a in audits:
            lines.append(f"  [{a.timestamp}] {a.operator} -> {a.action}: {a.details[:60]}")
        return {"output": "\n".join(lines), "type": "text"}

    elif root_cmd == "clear":
        return {"output": "CLEAR", "type": "clear"}

    else:
        return {
            "output": f"Comando desconhecido: '{cmd_raw}'. Digite 'help' para ver os comandos suportados.",
            "type": "error"
        }
