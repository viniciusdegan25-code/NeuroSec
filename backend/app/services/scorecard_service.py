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
        """Calcula a perda financeira estimada, prejuízo evitado e score contextualizado para a realidade estrutural daquela empresa."""
        
        # 1. Parâmetros Setoriais do Mercado Brasileiro (Fonte: IBM Security / FAIR / ANPD)
        sector_cost_per_record = {
            "FINTECH": 450.0,
            "HEALTHCARE": 510.0,
            "E_COMMERCE": 260.0,
            "LOGISTICS": 195.0,
            "GOV": 340.0
        }
        industry = (client.industry or "FINTECH").upper()
        unit_record_cost = sector_cost_per_record.get(industry, 250.0)

        revenue = float(getattr(client, "annual_revenue_brl", 50000000.0) or 50000000.0)
        records = int(getattr(client, "sensitive_records_count", 100000) or 100000)
        downtime_h_cost = float(getattr(client, "downtime_cost_per_hour", 25000.0) or 25000.0)

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

        for v in vulns:
            sev = (v.severity or "MEDIUM").upper()
            status = v.status or "open"
            cvss = float(v.cvss_score or 5.0)

            # Estimativa estocástica de impacto por severidade
            if sev == "CRITICAL":
                breach_fraction = min(0.20, 0.08 + (cvss - 8.0) * 0.06)
                outage_hours = 18.0
                reg_multiplier = 0.012  # 1.2% do faturamento
                if status == "open": crit_count += 1
            elif sev == "HIGH":
                breach_fraction = 0.05
                outage_hours = 6.0
                reg_multiplier = 0.004
                if status == "open": high_count += 1
            elif sev == "MEDIUM":
                breach_fraction = 0.01
                outage_hours = 1.5
                reg_multiplier = 0.001
                if status == "open": med_count += 1
            else:
                breach_fraction = 0.001
                outage_hours = 0.5
                reg_multiplier = 0.0002
                if status == "open": low_count += 1

            if status == "remediated":
                rem_count += 1

            # Componentes de perda financeira
            v_breach_loss = records * breach_fraction * unit_record_cost
            v_downtime_loss = outage_hours * downtime_h_cost
            v_regulatory_fine = min(50000000.0, revenue * reg_multiplier)

            single_vuln_total_impact = v_breach_loss + v_downtime_loss + v_regulatory_fine

            if status in ["open", "patch_ready"]:
                open_exposure_total += single_vuln_total_impact
                data_breach_risk_total += v_breach_loss
                downtime_risk_total += v_downtime_loss
                regulatory_risk_total += v_regulatory_fine
            elif status == "remediated":
                loss_avoided_total += single_vuln_total_impact

        # Cálculo do Score Contextualizado da Empresa (0 a 100)
        penalty = (crit_count * 22) + (high_count * 12) + (med_count * 5) + (low_count * 2)
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
            "methodology": "Modelo FAIR (Factor Analysis of Information Risk) & NIST SP 800-30 cruzado com parâmetros da LGPD (Art. 52) e IBM Security Cost Report."
        }
