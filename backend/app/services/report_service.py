import os
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
            self.set_fill_color(9, 13, 22)
            self.rect(0, 0, 210, 35, 'F')
            
            self.set_font("Helvetica", "B", 18)
            self.set_text_color(0, 240, 255) # Cyan neon
            self.set_xy(15, 10)
            self.cell(0, 8, "NEUROSEC // ASPM ENTERPRISE", ln=1)
            
            self.set_font("Helvetica", "", 10)
            self.set_text_color(148, 163, 184)
            self.set_xy(15, 20)
            self.cell(0, 6, "Relatório Executivo de Postura de Segurança & Conformidade C-Level", ln=1)
            self.ln(15)

        def footer(self):
            self.set_y(-18)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(100, 116, 139)
            self.cell(0, 10, f"NeuroSec AI Security Platform - Documento Confidencial | Pagina {self.page_no()}", align="C")

class ReportService:
    """Gerador de Relatórios Executivos em PDF e HTML de Alto Padrão."""

    @classmethod
    def generate_pdf_report(cls, db: Session, output_path: str = "neurosec_executive_report.pdf") -> str:
        metrics = ScorecardService.calculate_metrics(db)
        vulns = db.query(Vulnerability).all()
        audits = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(10).all()

        if not HAS_FPDF:
            # Fallback para relatório HTML executivo caso a biblioteca fpdf ainda não esteja instalada no ambiente local
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head><meta charset="utf-8"><title>Relatório Executivo NeuroSec</title>
            <style>body{{font-family:sans-serif; padding:40px; background:#040711; color:#fff;}}</style>
            </head>
            <body>
            <h1 style="color:#00f0ff;">NEUROSEC ASPM ENTERPRISE</h1>
            <h2>Relatório Executivo de Postura de Segurança</h2>
            <p>Score Global: <strong>{metrics.score}/100 ({metrics.grade})</strong> - {metrics.posture_status}</p>
            <p>Prejuízo Financeiro Evitado: <strong>R$ {metrics.loss_avoided_brl:,.2f}</strong></p>
            <p>Vulnerabilidades Abertas: {metrics.open_vulnerabilities} | Remediadas: {metrics.remediated_vulnerabilities}</p>
            </body>
            </html>
            """
            with open(output_path.replace(".pdf", ".html"), "w", encoding="utf-8") as f:
                f.write(html_content)
            return output_path.replace(".pdf", ".html")

        pdf = ExecutivePDF(orientation='P', unit='mm', format='A4')
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()

        # Data de emissão
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(0, 6, f"Data de Emissao: {datetime.now().strftime('%d/%m/%Y as %H:%M')}", ln=1, align="R")
        pdf.ln(4)

        # 1. Resumo Executivo e Scorecard
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 8, "1. Indice Global de Postura de Seguranca (Security Scorecard)", ln=1)
        pdf.ln(2)

        # Tabela de KPIs Principais
        pdf.set_fill_color(241, 245, 249)
        pdf.set_draw_color(203, 213, 225)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(15, 23, 42)

        col_w = 47
        pdf.cell(col_w, 10, "Score de Seguranca", 1, 0, 'C', True)
        pdf.cell(col_w, 10, "Classificacao", 1, 0, 'C', True)
        pdf.cell(col_w, 10, "Ameacas Abertas", 1, 0, 'C', True)
        pdf.cell(col_w, 10, "Prejuizo Evitado", 1, 1, 'C', True)

        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(0, 100, 150)
        pdf.cell(col_w, 12, f"{metrics.score}/100 ({metrics.grade})", 1, 0, 'C')
        pdf.cell(col_w, 12, metrics.posture_status, 1, 0, 'C')
        
        pdf.set_text_color(220, 38, 38 if metrics.open_vulnerabilities > 0 else 22, 163, 74)
        pdf.cell(col_w, 12, str(metrics.open_vulnerabilities), 1, 0, 'C')
        
        pdf.set_text_color(16, 185, 129)
        pdf.cell(col_w, 12, f"R$ {metrics.loss_avoided_brl:,.2f}", 1, 1, 'C')
        pdf.ln(6)

        # 2. Distribuição por Severidade
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 8, "2. Distribuicao por Severidade & Criticidade", ln=1)
        pdf.ln(2)

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(0, 6, f"- Falhas Criticas (Risco Imediato): {metrics.severity_breakdown.critical}", ln=1)
        pdf.cell(0, 6, f"- Falhas Altas (Elevada Explotabilidade): {metrics.severity_breakdown.high}", ln=1)
        pdf.cell(0, 6, f"- Falhas Medias (Vulnerabilidade Relevante): {metrics.severity_breakdown.medium}", ln=1)
        pdf.cell(0, 6, f"- Falhas Baixas / Informativas: {metrics.severity_breakdown.low + metrics.severity_breakdown.info}", ln=1)
        pdf.cell(0, 6, f"- Taxa de Eficacia de Remediacao: {metrics.remediation_rate}%", ln=1)
        pdf.ln(6)

        # 3. Inventário de Ameaças Prioritárias
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 8, "3. Inventario de Vulnerabilidades Prioritarias", ln=1)
        pdf.ln(2)

        pdf.set_fill_color(241, 245, 249)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(15, 8, "ID", 1, 0, 'C', True)
        pdf.cell(25, 8, "Tipo Ativo", 1, 0, 'C', True)
        pdf.cell(60, 8, "Nome do Ativo", 1, 0, 'L', True)
        pdf.cell(50, 8, "Vulnerabilidade", 1, 0, 'L', True)
        pdf.cell(20, 8, "Severidade", 1, 0, 'C', True)
        pdf.cell(20, 8, "Status", 1, 1, 'C', True)

        pdf.set_font("Helvetica", "", 8)
        for v in vulns[:15]:
            pdf.cell(15, 7, str(v.internal_id), 1, 0, 'C')
            pdf.cell(25, 7, v.asset_type[:12], 1, 0, 'C')
            pdf.cell(60, 7, v.asset_name[:32], 1, 0, 'L')
            pdf.cell(50, 7, v.vuln_type[:28], 1, 0, 'L')
            pdf.cell(20, 7, v.severity, 1, 0, 'C')
            pdf.cell(20, 7, v.status[:10], 1, 1, 'C')

        pdf.ln(6)

        # 4. Trilha de Auditoria
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 8, "4. Trilha de Auditoria e Governanca Recente", ln=1)
        pdf.ln(2)

        pdf.set_font("Helvetica", "", 9)
        if not audits:
            pdf.cell(0, 6, "Nenhuma acao de auditoria registrada ainda.", ln=1)
        else:
            for a in audits[:5]:
                pdf.cell(0, 6, f"[{a.timestamp}] {a.operator} -> {a.action}: {a.details[:80]}", ln=1)

        pdf.output(output_path)
        return output_path
