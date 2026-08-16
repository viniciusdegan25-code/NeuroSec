from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

class ScorecardMetrics(BaseModel):
    score: int                           # 0 - 100
    grade: str                           # A+, A, B, C, D, F
    posture_status: str                  # Resiliente, Seguro, Atenção, Crítico
    total_vulnerabilities: int
    open_vulnerabilities: int
    remediated_vulnerabilities: int
    remediation_rate: float              # Percentage
    loss_avoided_brl: int                # Prejuízo evitado em R$
    assets_monitored: int
    severity_breakdown: SeverityBreakdown
    owasp_top10_coverage: Dict[str, int]
    mttr_days: float                     # Mean Time to Remediate
