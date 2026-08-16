import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.db.database import SessionLocal, init_db
from app.services.scorecard_service import ScorecardService
from app.services.sast_service import SastEngine
from app.services.sca_service import ScaEngine
from app.services.cloud_service import CloudAuditEngine
from app.services.report_service import ReportService
from main import app

def run_tests():
    print("=== INICIANDO BATERIA DE TESTES DO NEUROSEC ASPM ===")
    
    # 1. Banco de Dados
    init_db()
    db = SessionLocal()
    print("[OK] Banco de dados relacional e tabelas inicializadas com sucesso.")

    # 2. Scorecard
    metrics = ScorecardService.calculate_metrics(db)
    print(f"[OK] Scorecard Calculado: {metrics.score}/100 ({metrics.grade}) - {metrics.posture_status}")
    print(f"[OK] Prejuizo Evitado: R$ {metrics.loss_avoided_brl:,.2f}")

    # 3. SAST Engine
    sast_test_code = "cursor.execute('SELECT * FROM accounts WHERE user=' + username)"
    sast_findings = SastEngine.scan_code_string(sast_test_code, "auth_test.py")
    assert len(sast_findings) >= 1, "SAST falhou ao detectar SQL Injection"
    print(f"[OK] SAST Engine: Detectou {len(sast_findings)} falha(s) com sucesso ({sast_findings[0]['vuln_type']}).")

    # 4. SCA Engine
    sca_test_content = "requests==2.28.0\ndjango==3.2.0\npyyaml==5.3.1"
    sca_findings = ScaEngine.scan_manifest_text(sca_test_content, "requirements.txt")
    assert len(sca_findings) >= 2, "SCA falhou ao detectar dependencias vulneraveis"
    print(f"[OK] SCA Engine: Detectou {len(sca_findings)} pacotes com CVEs conhecidas.")

    # 5. Cloud Audit Engine
    cloud_test_code = 'resource "aws_s3_bucket" "b" { acl = "public-read" }'
    cloud_findings = CloudAuditEngine.audit_iac_text(cloud_test_code, "main.tf")
    assert len(cloud_findings) >= 1, "Cloud Audit falhou ao detectar S3 bucket publico"
    print(f"[OK] Cloud Engine: Detectou {len(cloud_findings)} desvio(s) de postura em nuvem.")

    # 6. Relatório Executivo
    report_path = ReportService.generate_pdf_report(db, "test_report.pdf")
    print(f"[OK] Relatorio Executivo gerado: {report_path}")

    print("\n=======================================================")
    print("TODOS OS MOTORES E TESTES PASSARAM COM 100% DE SUCESSO!")
    print("=======================================================")

if __name__ == "__main__":
    run_tests()
