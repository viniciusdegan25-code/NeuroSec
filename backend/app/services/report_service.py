import os
import io
import csv
import json
from typing import Dict, Any, List
from datetime import datetime
from sqlalchemy.orm import Session
from app.db.models import Vulnerability, AuditLog
from app.services.scorecard_service import ScorecardService

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

if HAS_FPDF:
    class ExecutivePDF(FPDF):
        def header(self):
            self.set_fill_color(7, 9, 14)
            self.rect(0, 0, 210, 35, 'F')
            
            self.set_font("Helvetica", "B", 18)
            self.set_text_color(0, 255, 65) # Neon Matrix Green
            self.set_xy(15, 10)
            self.cell(0, 8, "NEUROSEC // ASPM 4.0 ENTERPRISE", ln=1)
            
            self.set_font("Helvetica", "", 10)
            self.set_text_color(148, 163, 184)
            self.set_xy(15, 20)
            self.cell(0, 6, "Relatório Executivo de Postura de Segurança & Conformidade C-Level", ln=1)
            self.ln(15)

        def footer(self):
            self.set_y(-18)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(100, 116, 139)
            self.cell(0, 10, f"NeuroSec AI Security Platform 4.0 - Documento Confidencial | Pagina {self.page_no()}", align="C")

class ReportService:
    """Gerador de Relatórios Executivos em PDF, CSV e CycloneDX SBOM de Alto Padrão."""

    @classmethod
    def generate_pdf_report(cls, db: Session, output_path: str = "neurosec_executive_report.pdf") -> str:
        metrics = ScorecardService.calculate_metrics(db)
        vulns = db.query(Vulnerability).all()
        audits = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(10).all()

        if not HAS_FPDF:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="utf-8"><title>Relatório Executivo NeuroSec 4.0</title>
            <style>body{{font-family:sans-serif; padding:40px; background:#07090E; color:#fff;}}</style>
            </head>
            <body>
            <h1 style="color:#00FF41;">NEUROSEC ASPM 4.0 ENTERPRISE</h1>
            <h2>Relatório Executivo de Postura de Segurança</h2>
            <p>Score Global: <strong>{metrics.score}/100 ({metrics.grade})</strong> - {metrics.posture_status}</p>
            <p>Prejuízo Financeiro Evitado: <strong>R$ {metrics.loss_avoided_brl:,.2f}</strong></p>
            <p>Vulnerabilidades Abertas: {metrics.open_vulnerabilities} | Remediadas: {metrics.remediated_vulnerabilities}</p>
            </body>
            </html>
            """
            html_path = output_path.replace(".pdf", ".html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            return html_path

        pdf = ExecutivePDF(orientation='P', unit='mm', format='A4')
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()
        
        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 10, "1. RESUMO EXECUTIVO DE POSTURA", ln=1)
        
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(203, 213, 225)
        pdf.cell(50, 7, f"Data da Auditoria:", 0)
        pdf.cell(0, 7, f"{datetime.utcnow().strftime('%d/%m/%Y %H:%M:%S')} UTC", ln=1)
        pdf.cell(50, 7, f"Security Score:", 0)
        pdf.cell(0, 7, f"{metrics.score} / 100 ({metrics.grade}) - {metrics.posture_status}", ln=1)
        pdf.cell(50, 7, f"Prejuizo Evitado:", 0)
        pdf.cell(0, 7, f"R$ {metrics.loss_avoided_brl:,.2f}", ln=1)
        pdf.cell(50, 7, f"Tempo Medio Remediado (MTTR):", 0)
        pdf.cell(0, 7, f"{metrics.mttr_days} dias", ln=1)
        
        pdf.ln(8)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 10, "2. DISTRIBUICAO DE VULNERABILIDADES (ATUAL)", ln=1)
        
        pdf.set_fill_color(17, 24, 39)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(0, 255, 65)
        pdf.cell(20, 8, "ID", 1, 0, 'C', True)
        pdf.cell(55, 8, "Vulnerabilidade", 1, 0, 'L', True)
        pdf.cell(45, 8, "Ativo / Modulo", 1, 0, 'L', True)
        pdf.cell(25, 8, "Severidade", 1, 0, 'C', True)
        pdf.cell(20, 8, "CVSS", 1, 0, 'C', True)
        pdf.cell(25, 8, "Status", 1, 1, 'C', True)
        
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(226, 232, 240)
        
        for v in vulns:
            pdf.cell(20, 7, f"#{v.internal_id}", 1, 0, 'C')
            pdf.cell(55, 7, str(v.vuln_type)[:30], 1, 0, 'L')
            pdf.cell(45, 7, str(v.asset_name)[:25], 1, 0, 'L')
            
            if v.severity == "CRITICAL":
                pdf.set_text_color(239, 68, 68)
            elif v.severity == "HIGH":
                pdf.set_text_color(245, 158, 11)
            else:
                pdf.set_text_color(16, 185, 129)
                
            pdf.cell(25, 7, str(v.severity), 1, 0, 'C')
            pdf.set_text_color(226, 232, 240)
            pdf.cell(20, 7, f"{v.cvss_score:.1f}", 1, 0, 'C')
            pdf.cell(25, 7, str(v.status), 1, 1, 'C')

        pdf.output(output_path)
        return output_path

    @classmethod
    def generate_csv_inventory(cls, db: Session) -> str:
        """Gera o arquivo CSV de exportação de inventário de vulnerabilidades."""
        vulns = db.query(Vulnerability).all()
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        writer.writerow([
            "ID_Interno", "Nome_Ativo", "Tipo_Ativo", "Tipo_Vulnerabilidade",
            "Severidade", "CVSS_Score", "Status", "CVE_ID", "Linha_Codigo",
            "Categoria_OWASP", "Data_Identificacao", "Data_Remediado"
        ])

        for v in vulns:
            writer.writerow([
                f"#{v.internal_id}",
                v.asset_name,
                v.asset_type,
                v.vuln_type,
                v.severity,
                f"{v.cvss_score:.1f}" if v.cvss_score else "5.0",
                v.status,
                v.cve_id or "N/A",
                v.line_number or 0,
                v.owasp_category or "A03:2021",
                v.created_at or "",
                v.updated_at or ""
            ])

        return output.getvalue()

    @classmethod
    def generate_cyclonedx_sbom(cls, db: Session) -> Dict[str, Any]:
        """Gera o SBOM no padrão internacional CycloneDX v1.5 JSON para auditoria corporativa."""
        vulns = db.query(Vulnerability).all()

        components = []
        vulnerabilities_list = []

        for v in vulns:
            comp_name = v.asset_name.split(":")[0].replace("/", "-")
            comp_version = "1.0.0"
            if "==" in v.asset_name:
                parts = v.asset_name.split("==")
                comp_name = parts[0]
                comp_version = parts[1]

            purl = f"pkg:generic/{comp_name}@{comp_version}"

            components.append({
                "type": "library" if v.asset_type == "PACKAGE" else "application",
                "name": comp_name,
                "version": comp_version,
                "purl": purl,
                "scope": "required"
            })

            if v.severity in ["CRITICAL", "HIGH", "MEDIUM"]:
                vulnerabilities_list.append({
                    "id": v.cve_id or f"NEURO-{v.internal_id}",
                    "source": {"name": "NeuroSec ASPM 4.0 Threat Radar"},
                    "ratings": [{
                        "score": v.cvss_score,
                        "severity": v.severity.lower(),
                        "method": "CVSSv31"
                    }],
                    "description": v.vuln_type,
                    "affects": [{"ref": purl}]
                })

        cyclonedx_doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:neurosec-aspm-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [{
                    "vendor": "NeuroSec Enterprise",
                    "name": "NeuroSec ASPM",
                    "version": "4.0.0"
                }],
                "component": {
                    "type": "application",
                    "name": "Enterprise Target Stack",
                    "version": "4.0"
                }
            },
            "components": components,
            "vulnerabilities": vulnerabilities_list
        }

        return cyclonedx_doc
