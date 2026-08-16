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
