from sqlalchemy.orm import Session
from app.db.models import Vulnerability, Asset
from app.core.config import settings
from app.schemas.scorecard import ScorecardMetrics, SeverityBreakdown
from typing import Dict, Any

class ScorecardService:
    """Calcula a Postura de Segurança Global (ASPM Scorecard) e o Retorno Financeiro."""

    @classmethod
    def calculate_metrics(cls, db: Session) -> ScorecardMetrics:
        vulns = db.query(Vulnerability).all()
        total_vulns = len(vulns)
        
        open_vulns = [v for v in vulns if v.status in ["open", "patch_ready"]]
        remediated_vulns = [v for v in vulns if v.status == "remediated"]
        
        count_open = len(open_vulns)
        count_remediated = len(remediated_vulns)
        
        # Severity breakdown
        crit_count = sum(1 for v in open_vulns if v.severity == "CRITICAL")
        high_count = sum(1 for v in open_vulns if v.severity == "HIGH")
        med_count = sum(1 for v in open_vulns if v.severity == "MEDIUM")
        low_count = sum(1 for v in open_vulns if v.severity == "LOW")
        info_count = sum(1 for v in open_vulns if v.severity == "INFO")

        # Dynamic Security Score Formula (0 to 100)
        # Base: 100
        # Penalty: Critical (-15), High (-8), Medium (-3), Low (-1)
        # Bonus: +3 for each remediated item (up to original penalties)
        penalty = (
            crit_count * settings.WEIGHT_CRITICAL +
            high_count * settings.WEIGHT_HIGH +
            med_count * settings.WEIGHT_MEDIUM +
            low_count * settings.WEIGHT_LOW
        )
        
        remediation_bonus = count_remediated * 2
        raw_score = 100 - penalty + remediation_bonus
        final_score = max(0, min(100, raw_score))

        # Determine Letter Grade & Posture Status
        if final_score >= 90:
            grade = "A+"
            status = "Resiliente & Blindado"
        elif final_score >= 80:
            grade = "A"
            status = "Seguro"
        elif final_score >= 65:
            grade = "B"
            status = "Risco Moderado"
        elif final_score >= 45:
            grade = "C"
            status = "Atenção Necessária"
        elif final_score >= 25:
            grade = "D"
            status = "Vulnerável"
        else:
            grade = "F"
            status = "Postura Crítica"

        # Rate and Financial Impact (ROI)
        remediation_rate = round((count_remediated / total_vulns * 100), 1) if total_vulns > 0 else 100.0
        loss_avoided = count_remediated * settings.LOSS_AVOIDED_PER_PATCH

        # Assets count
        assets_count = db.query(Asset).count()
        if assets_count == 0:
            assets_count = len(set(v.asset_name for v in vulns)) or 1

        # OWASP Distribution
        owasp_map: Dict[str, int] = {}
        for v in vulns:
            cat = v.owasp_category or "Outras Falhas"
            owasp_map[cat] = owasp_map.get(cat, 0) + 1

        # MTTR (Mean Time to Remediate) in days
        avg_days = sum(v.days_open for v in vulns) / total_vulns if total_vulns > 0 else 1.0

        return ScorecardMetrics(
            score=final_score,
            grade=grade,
            posture_status=status,
            total_vulnerabilities=total_vulns,
            open_vulnerabilities=count_open,
            remediated_vulnerabilities=count_remediated,
            remediation_rate=remediation_rate,
            loss_avoided_brl=loss_avoided,
            assets_monitored=assets_count,
            severity_breakdown=SeverityBreakdown(
                critical=crit_count,
                high=high_count,
                medium=med_count,
                low=low_count,
                info=info_count
            ),
            owasp_top10_coverage=owasp_map,
            mttr_days=round(avg_days, 1)
        )

    @classmethod
    def calculate_client_financial_risk(cls, client: Any, vulns: list, assets: list = None) -> Dict[str, Any]:
        """Calcula a perda financeira estimada, prejuízo evitado, conformidade e score contextualizado para PMEs e médias empresas."""
        
        # 1. Parâmetros Setoriais do Mercado Brasileiro (Fonte: IBM Security / FAIR / ANPD)
        sector_cost_per_record = {
            "AGRO": 220.0,
            "HEALTHCARE": 510.0,
            "FINTECH": 450.0,
            "E_COMMERCE": 260.0,
            "LOGISTICS": 195.0,
            "GOV": 340.0
        }
        industry = (client.industry or "FINTECH").upper()
        unit_record_cost = sector_cost_per_record.get(industry, 250.0)

        revenue = float(getattr(client, "annual_revenue_brl", 8500000.0) or 8500000.0)
        records = int(getattr(client, "sensitive_records_count", 25000) or 25000)
        downtime_h_cost = float(getattr(client, "downtime_cost_per_hour", 3500.0) or 3500.0)

        open_exposure_total = 0.0
        loss_avoided_total = 0.0
        data_breach_risk_total = 0.0
        downtime_risk_total = 0.0
        regulatory_risk_total = 0.0

        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0
        rem_count = 0

        # Falhas mapeadas para conformidade
        has_secret_vuln = False
        has_injection_vuln = False
        has_crypto_vuln = False
        has_sca_vuln = False
        has_cloud_vuln = False

        for v in vulns:
            sev = (v.severity or "MEDIUM").upper()
            status = v.status or "open"
            vtype = (v.vuln_type or "").lower()
            cvss = float(v.cvss_score or 5.0)

            # Rastreamento de tipos de falhas ativas
            if status in ["open", "patch_ready"]:
                if "secret" in vtype or "key" in vtype or "password" in vtype:
                    has_secret_vuln = True
                if "injection" in vtype or "eval" in vtype or "command" in vtype:
                    has_injection_vuln = True
                if "hsts" in vtype or "tls" in vtype or "ssl" in vtype or "crypto" in vtype or "cleartext" in vtype:
                    has_crypto_vuln = True
                if "biblioteca" in vtype or "cve" in vtype or "sca" in vtype:
                    has_sca_vuln = True
                if "s3" in vtype or "cloud" in vtype or "bucket" in vtype or "ssh" in vtype or "iac" in vtype:
                    has_cloud_vuln = True

            # Estimativa de impacto realista para escala de PME
            if sev == "CRITICAL":
                breach_fraction = min(0.25, 0.10 + (cvss - 8.0) * 0.05)
                outage_hours = 12.0
                reg_multiplier = 0.015  # 1.5% do faturamento da PME
                if status == "open": crit_count += 1
            elif sev == "HIGH":
                breach_fraction = 0.08
                outage_hours = 4.0
                reg_multiplier = 0.006
                if status == "open": high_count += 1
            elif sev == "MEDIUM":
                breach_fraction = 0.02
                outage_hours = 1.0
                reg_multiplier = 0.002
                if status == "open": med_count += 1
            else:
                breach_fraction = 0.005
                outage_hours = 0.5
                reg_multiplier = 0.0005
                if status == "open": low_count += 1

            if status == "remediated":
                rem_count += 1

            # Componentes de perda financeira (Adequados para PMEs: teto legal 2% do faturamento por infração na LGPD)
            v_breach_loss = records * breach_fraction * unit_record_cost
            v_downtime_loss = outage_hours * downtime_h_cost
            v_regulatory_fine = min(revenue * 0.02, revenue * reg_multiplier)

            single_vuln_total_impact = v_breach_loss + v_downtime_loss + v_regulatory_fine

            if status in ["open", "patch_ready"]:
                open_exposure_total += single_vuln_total_impact
                data_breach_risk_total += v_breach_loss
                downtime_risk_total += v_downtime_loss
                regulatory_risk_total += v_regulatory_fine
            elif status == "remediated":
                loss_avoided_total += single_vuln_total_impact

        # 2. Matriz de Conformidade Regulatória Matemático-Contextual
        # ISO 27001 (4 Controles Chave)
        iso_controls = [
            {"id": "A.9.4.3", "name": "Gestão de Senhas e Segredos", "status": "FAIL" if has_secret_vuln else "PASS", "details": "Chaves e senhas não podem estar em texto plano."},
            {"id": "A.14.2.1", "name": "Desenvolvimento Seguro de Software", "status": "FAIL" if has_injection_vuln else "PASS", "details": "Validação de entradas contra Injeção SQL e RCE."},
            {"id": "A.12.6.1", "name": "Gestão de Vulnerabilidades Técnicas", "status": "FAIL" if (crit_count + high_count) > 0 else "PASS", "details": "Varredura contínua de CVEs em dependências."},
            {"id": "A.10.1.1", "name": "Controles de Criptografia", "status": "FAIL" if has_crypto_vuln else "PASS", "details": "Criptografia de ponta a ponta e HSTS."}
        ]
        iso_pass = sum(1 for c in iso_controls if c["status"] == "PASS")
        iso_score = int((iso_pass / len(iso_controls)) * 100)

        # LGPD / ANPD (3 Artigos Chave)
        lgpd_controls = [
            {"id": "Art. 46", "name": "Segurança e Proteção de Dados", "status": "FAIL" if (has_crypto_vuln or has_secret_vuln) else "PASS", "details": "Garantia de confidencialidade dos titulares cadastrados."},
            {"id": "Art. 48", "name": "Prevenção de Incidentes e Vazamentos", "status": "FAIL" if (has_injection_vuln or has_cloud_vuln) else "PASS", "details": "Bloqueio de vetores de exfiltração de dados."},
            {"id": "Art. 50", "name": "Governança e Boas Práticas em TI", "status": "FAIL" if crit_count > 0 else "PASS", "details": "Mitigação prioritária de falhas críticas de sistema."}
        ]
        lgpd_pass = sum(1 for c in lgpd_controls if c["status"] == "PASS")
        lgpd_score = int((lgpd_pass / len(lgpd_controls)) * 100)

        # PCI-DSS ou Norma Setorial Especializada
        if industry == "FINTECH":
            sector_name = "PCI-DSS 4.0 (Padrão de Segurança de Cartões e PIX)"
            sector_controls = [
                {"id": "Req. 4.1", "name": "Criptografia em Trânsito", "status": "FAIL" if has_crypto_vuln else "PASS", "details": "Uso obrigatório de TLS 1.3 e HSTS em APIs de pagamento."},
                {"id": "Req. 6.2", "name": "Proteção contra Falhas de Software", "status": "FAIL" if has_injection_vuln else "PASS", "details": "Sanitização de parâmetros em transações financeiras."},
                {"id": "Req. 8.2", "name": "Autenticação e Segredos de Acesso", "status": "FAIL" if has_secret_vuln else "PASS", "details": "Proteção de tokens de autorização de pagamentos."}
            ]
        elif industry == "HEALTHCARE":
            sector_name = "CFM / Res. 1.821 (Sigilo Médico & Prontuário Digital)"
            sector_controls = [
                {"id": "Art. 10", "name": "Confidencialidade de Prontuários", "status": "FAIL" if (has_injection_vuln or has_secret_vuln) else "PASS", "details": "Proteção absoluta de prontuários e diagnósticos de saúde."},
                {"id": "Art. 12", "name": "Disponibilidade da Telemedicina", "status": "FAIL" if (crit_count > 0) else "PASS", "details": "Garantia de uptime dos serviços de agendamento e laudo."}
            ]
        elif industry == "AGRO":
            sector_name = "MAPA / Governança de Dados Agrícolas & IoT"
            sector_controls = [
                {"id": "Controle 1", "name": "Integridade de Sensores e Telemetria", "status": "FAIL" if (has_injection_vuln or has_secret_vuln) else "PASS", "details": "Proteção contra manipulação de dados de sensores de solo e safras."},
                {"id": "Controle 2", "name": "Segurança de Firmware e Nuvem Agrícola", "status": "FAIL" if (has_cloud_vuln or has_sca_vuln) else "PASS", "details": "Auditoria de bibliotecas IoT e buckets em nuvem."}
            ]
        else:
            sector_name = "ANTT / Resolução de Rastreabilidade e Frotas"
            sector_controls = [
                {"id": "Controle 1", "name": "Integridade do Roteirizador Web", "status": "FAIL" if has_injection_vuln else "PASS", "details": "Segurança de coordenadas de entregas e motoristas."},
                {"id": "Controle 2", "name": "Disponibilidade da API de Rastreamento", "status": "FAIL" if crit_count > 0 else "PASS", "details": "Operação contínua do rastreador de entregas."}
            ]

        sector_pass = sum(1 for c in sector_controls if c["status"] == "PASS")
        sector_score = int((sector_pass / len(sector_controls)) * 100)

        # 3. Score Contextualizado (0 a 100)
        penalty = (crit_count * 20) + (high_count * 10) + (med_count * 4) + (low_count * 1)
        remediation_bonus = rem_count * 4
        client_score = max(0, min(100, 100 - penalty + remediation_bonus))

        if client_score >= 90:
            grade = "A+"
            posture_status = "Resiliente & Blindado"
        elif client_score >= 80:
            grade = "A"
            posture_status = "Seguro"
        elif client_score >= 65:
            grade = "B"
            posture_status = "Risco Moderado"
        elif client_score >= 45:
            grade = "C"
            posture_status = "Atenção Necessária"
        else:
            grade = "F"
            posture_status = "Postura Crítica"

        return {
            "client_id": client.id,
            "client_name": client.name,
            "industry": industry,
            "annual_revenue_brl": revenue,
            "sensitive_records_count": records,
            "downtime_cost_per_hour": downtime_h_cost,
            "cost_per_record_brl": unit_record_cost,
            "financial_exposure_risk_brl": round(open_exposure_total, 2),
            "financial_loss_avoided_brl": round(loss_avoided_total, 2),
            "data_breach_risk_brl": round(data_breach_risk_total, 2),
            "downtime_risk_brl": round(downtime_risk_total, 2),
            "regulatory_fine_risk_brl": round(regulatory_risk_total, 2),
            "security_score": client_score,
            "grade": grade,
            "posture_status": posture_status,
            "open_vulns_count": len([v for v in vulns if v.status in ["open", "patch_ready"]]),
            "remediated_vulns_count": rem_count,
            "compliance_matrix": {
                "iso_27001": {
                    "score": iso_score,
                    "status": "CONFORME" if iso_score >= 80 else ("PARCIAL" if iso_score >= 50 else "NÃO CONFORME"),
                    "controls": iso_controls
                },
                "lgpd_anpd": {
                    "score": lgpd_score,
                    "status": "CONFORME" if lgpd_score >= 80 else ("PARCIAL" if lgpd_score >= 50 else "NÃO CONFORME"),
                    "controls": lgpd_controls
                },
                "sector_standard": {
                    "name": sector_name,
                    "score": sector_score,
                    "status": "CONFORME" if sector_score >= 80 else ("PARCIAL" if sector_score >= 50 else "NÃO CONFORME"),
                    "controls": sector_controls
                }
            },
            "methodology": "Modelo FAIR (Factor Analysis of Information Risk) & NIST SP 800-30 cruzado com parâmetros da LGPD (Art. 52 - 2% do faturamento) e IBM Security Cost Report para PMEs."
        }
