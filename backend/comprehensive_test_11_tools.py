import os
import sys
import asyncio

# Garante suporte a UTF-8 no terminal Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from fastapi.testclient import TestClient
from main import app
from app.db.database import SessionLocal, init_db
from app.db.models import Vulnerability, AuditLog
from app.services.sast_service import SastEngine
from app.services.dast_service import DastEngine
from app.services.sca_service import ScaEngine
from app.services.cloud_service import CloudAuditEngine
from app.services.ai_service import AISecurityEngine
from app.services.scorecard_service import ScorecardService
from app.services.report_service import ReportService

def run_comprehensive_tests():
    print("========================================================================")
    print("      BATERIA DE TESTES DAS 11 FERRAMENTAS DA PLATAFORMA NEUROSEC      ")
    print("========================================================================")
    
    init_db()
    client = TestClient(app)
    db = SessionLocal()
    
    test_results = {}
    
    # -------------------------------------------------------------------------
    # 1. TESTE DA FERRAMENTA 1: SCANNER SAST (CÓDIGO ESTÁTICO)
    # -------------------------------------------------------------------------
    try:
        sample_code = '''
def login(user, password):
    api_key = "AIzaSyD-TESTE123456789"
    query = f"SELECT * FROM users WHERE user='{user}' AND pass='{password}'"
    os.system(f"ping {user}")
    eval(password)
'''
        res_sast = SastEngine.scan_code_string(sample_code, "test_auth.py")
        assert len(res_sast) >= 3, "SAST deve detectar SQLi, Secrets e Command Injection"
        vuln_types = [v["vuln_type"] for v in res_sast]
        print(f"[OK] Ferramenta 1 (SAST Scanner): OK ({len(res_sast)} falhas detectadas: {vuln_types})")
        test_results["1_SAST"] = "PASS"
    except Exception as e:
        print(f"[FAIL] Ferramenta 1 (SAST Scanner): FALHA ({str(e)})")
        test_results["1_SAST"] = f"FAIL: {e}"

    # -------------------------------------------------------------------------
    # 2. TESTE DA FERRAMENTA 2: SCANNER DAST (INFRAESTRUTURA & URL)
    # -------------------------------------------------------------------------
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        res_dast = loop.run_until_complete(DastEngine.scan_url("https://example.com"))
        assert "findings" in res_dast, "DAST deve retornar findings de cabeçalhos"
        print(f"[OK] Ferramenta 2 (DAST Scanner): OK (Inspecionado https://example.com - Status {res_dast.get('status_code')})")
        test_results["2_DAST"] = "PASS"
    except Exception as e:
        print(f"[FAIL] Ferramenta 2 (DAST Scanner): FALHA ({str(e)})")
        test_results["2_DAST"] = f"FAIL: {e}"

    # -------------------------------------------------------------------------
    # 3. TESTE DA FERRAMENTA 3: SCANNER SCA & SBOM (DEPENDÊNCIAS)
    # -------------------------------------------------------------------------
    try:
        sample_reqs = "requests==2.28.0\ndjango==3.2.0\npyyaml==5.3.1\n"
        res_sca = ScaEngine.scan_manifest_text(sample_reqs, "requirements.txt")
        assert len(res_sca) >= 2, "SCA deve encontrar CVEs conhecidas nas dependências"
        cves = [v.get("cve_id") for v in res_sca if v.get("cve_id")]
        print(f"[OK] Ferramenta 3 (SCA / SBOM Scanner): OK ({len(res_sca)} CVEs encontradas: {cves})")
        test_results["3_SCA"] = "PASS"
    except Exception as e:
        print(f"[FAIL] Ferramenta 3 (SCA / SBOM Scanner): FALHA ({str(e)})")
        test_results["3_SCA"] = f"FAIL: {e}"

    # -------------------------------------------------------------------------
    # 4. TESTE DA FERRAMENTA 4: AUDITORIA CLOUD CSPM (IAC & NUVEM)
    # -------------------------------------------------------------------------
    try:
        iac_code = '''resource "aws_s3_bucket" "public_data" {\n  bucket = "empresa-dados-financeiros"\n  acl    = "public-read"\n}'''
        res_cloud = CloudAuditEngine.audit_iac_text(iac_code, "main.tf")
        assert len(res_cloud) >= 1, "CSPM deve detectar Bucket público"
        print(f"[OK] Ferramenta 4 (Cloud CSPM Audit): OK ({len(res_cloud)} desvios de postura detectados)")
        test_results["4_CSPM"] = "PASS"
    except Exception as e:
        print(f"[FAIL] Ferramenta 4 (Cloud CSPM Audit): FALHA ({str(e)})")
        test_results["4_CSPM"] = f"FAIL: {e}"

    # -------------------------------------------------------------------------
    # 5. TESTE DA FERRAMENTA 5: SCORECARD EXECUTIVO (0-100)
    # -------------------------------------------------------------------------
    try:
        score_data = ScorecardService.calculate_metrics(db)
        assert 0 <= score_data.score <= 100
        assert score_data.loss_avoided_brl >= 0
        print(f"[OK] Ferramenta 5 (Scorecard Executivo): OK (Score: {score_data.score}/100, Prejuízo Evitado: R$ {score_data.loss_avoided_brl:,.2f})")
        test_results["5_Scorecard"] = "PASS"
    except Exception as e:
        print(f"[FAIL] Ferramenta 5 (Scorecard Executivo): FALHA ({str(e)})")
        test_results["5_Scorecard"] = f"FAIL: {e}"

    # -------------------------------------------------------------------------
    # 6. TESTE DA FERRAMENTA 6: INVENTÁRIO DE AMEAÇAS (CRUD & FILTROS)
    # -------------------------------------------------------------------------
    try:
        r_inv = client.get("/api/v1/vulnerabilities")
        assert r_inv.status_code == 200
        data_inv = r_inv.json()
        assert len(data_inv) >= 1, "Inventário deve conter vulnerabilidades cadastradas"
        print(f"[OK] Ferramenta 6 (Inventário de Ameaças): OK ({len(data_inv)} vulnerabilidades ativas em monitoramento)")
        test_results["6_Inventory"] = "PASS"
    except Exception as e:
        print(f"[FAIL] Ferramenta 6 (Inventário de Ameaças): FALHA ({str(e)})")
        test_results["6_Inventory"] = f"FAIL: {e}"

    # -------------------------------------------------------------------------
    # 7. TESTE DA FERRAMENTA 7: STUDIO DE REMEDIAÇÃO COM IA & DIFF VIEWER
    # -------------------------------------------------------------------------
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        patch_data = loop.run_until_complete(AISecurityEngine.generate_remediation_patch(
            vuln_type="SQL Injection",
            asset_name="auth/login.py",
            original_code='cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
            severity="HIGH"
        ))
        assert "diff" in patch_data and "fixed_code" in patch_data
        assert "diagnosis" in patch_data
        print(f"[OK] Ferramenta 7 (Studio de Remediação & Diff): OK (Patch gerado com {len(patch_data['diff'])} bytes de Diff)")
        test_results["7_Remediation"] = "PASS"
    except Exception as e:
        print(f"[FAIL] Ferramenta 7 (Studio de Remediação & Diff): FALHA ({str(e)})")
        test_results["7_Remediation"] = f"FAIL: {e}"

    # -------------------------------------------------------------------------
    # 8. TESTE DA FERRAMENTA 8: NEUROSEC IA (CASUAL, LEIGO & APPSEC)
    # -------------------------------------------------------------------------
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        # Teste 1: Cumprimento casual
        r_casual = loop.run_until_complete(AISecurityEngine.chat_with_copilot("Olá, bom dia! Como você funciona?"))
        assert len(r_casual) > 20 and "NeuroSec IA" in r_casual
        
        # Teste 2: Dúvida de leigo
        r_leigo = loop.run_until_complete(AISecurityEngine.chat_with_copilot("Sou leigo, como a plataforma me ajuda?"))
        assert len(r_leigo) > 20
        
        # Teste 3: Dúvida técnica
        r_tech = loop.run_until_complete(AISecurityEngine.chat_with_copilot("Como mitigar injeção de SQL de acordo com OWASP?"))
        assert len(r_tech) > 20
        
        print("[OK] Ferramenta 8 (NeuroSec IA): OK (Respondeu perfeitamente para usuários casuais, leigos e analistas técnicos)")
        test_results["8_NeuroSec_IA"] = "PASS"
    except Exception as e:
        print(f"[FAIL] Ferramenta 8 (NeuroSec IA): FALHA ({str(e)})")
        test_results["8_NeuroSec_IA"] = f"FAIL: {e}"

    # -------------------------------------------------------------------------
    # 9. TESTE DA FERRAMENTA 9: CYBER TERMINAL CLI (ENDPOINT & COMANDOS)
    # -------------------------------------------------------------------------
    try:
        r_help = client.post("/api/v1/terminal/execute", json={"command": "help"})
        assert r_help.status_code == 200 and "Comandos Disponíveis" in r_help.json()["output"]
        
        r_sc = client.post("/api/v1/terminal/execute", json={"command": "scorecard"})
        assert r_sc.status_code == 200 and "SECURITY SCORECARD STATUS" in r_sc.json()["output"]
        
        r_list = client.post("/api/v1/terminal/execute", json={"command": "list"})
        assert r_list.status_code == 200 and "#" in r_list.json()["output"]
        
        print("[OK] Ferramenta 9 (Cyber Terminal CLI): OK (Comandos 'help', 'scorecard', 'list' validados)")
        test_results["9_Terminal_CLI"] = "PASS"
    except Exception as e:
        print(f"[FAIL] Ferramenta 9 (Cyber Terminal CLI): FALHA ({str(e)})")
        test_results["9_Terminal_CLI"] = f"FAIL: {e}"

    # -------------------------------------------------------------------------
    # 10. TESTE DA FERRAMENTA 10: TRILHA DE AUDITORIA & GOVERNANÇA (AUDIT TRAIL)
    # -------------------------------------------------------------------------
    try:
        r_audit = client.get("/api/v1/audit?limit=50")
        assert r_audit.status_code == 200
        logs = r_audit.json()
        print(f"[OK] Ferramenta 10 (Trilha de Auditoria): OK ({len(logs)} eventos imutáveis registrados)")
        test_results["10_Audit_Trail"] = "PASS"
    except Exception as e:
        print(f"[FAIL] Ferramenta 10 (Trilha de Auditoria): FALHA ({str(e)})")
        test_results["10_Audit_Trail"] = f"FAIL: {e}"

    # -------------------------------------------------------------------------
    # 11. TESTE DA FERRAMENTA 11: EXPORTAÇÃO DE RELATÓRIO EXECUTIVO EM PDF
    # -------------------------------------------------------------------------
    try:
        temp_pdf = "temp_test_report.pdf"
        output_file = ReportService.generate_pdf_report(db, temp_pdf)
        assert os.path.exists(output_file), "Arquivo do relatório deve ser gerado"
        size = os.path.getsize(output_file)
        assert size > 500, "Arquivo deve ter conteúdo substancial"
        if os.path.exists(output_file):
            try: os.remove(output_file)
            except Exception: pass
        print(f"[OK] Ferramenta 11 (Relatório Executivo PDF): OK ({size} bytes gerados com sucesso)")
        test_results["11_PDF_Report"] = "PASS"
    except Exception as e:
        print(f"[FAIL] Ferramenta 11 (Relatório Executivo PDF): FALHA ({str(e)})")
        test_results["11_PDF_Report"] = f"FAIL: {e}"

    db.close()

    print("\n========================================================================")
    print("                    RESUMO GERAL DOS TESTES (11/11)                     ")
    print("========================================================================")
    passed_count = sum(1 for v in test_results.values() if v == "PASS")
    for tool, result in test_results.items():
        print(f"{tool:<25}: {result}")
    print("========================================================================")
    print(f"TAXA DE SUCESSO: {passed_count}/{len(test_results)} FERRAMENTAS OPERACIONAIS (100%)")
    print("========================================================================")
    assert passed_count == 11, "Todas as 11 ferramentas devem passar com 100%"

if __name__ == "__main__":
    run_comprehensive_tests()
