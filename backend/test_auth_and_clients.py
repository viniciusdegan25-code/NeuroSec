import os
import sys

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
from app.db.models import User, ClientOrganization
import pyotp

def run_auth_and_clients_tests():
    print("========================================================================")
    print("     TESTES DO SISTEMA DE LOGIN COM MFA & GESTÃO DE CLIENTES MULTI-TENANT")
    print("========================================================================")

    init_db(seed=True)
    
    with TestClient(app) as client:
        # ---------------------------------------------------------------------
        # 1. TESTE DE LOGIN PASSO 1 (CREDENCIAIS)
        # ---------------------------------------------------------------------
        # Caso 1.1: Senha Incorreta
        r_fail = client.post("/api/v1/auth/login", json={"email": "admin@neurosec.ai", "password": "WrongPassword!"})
        assert r_fail.status_code == 401, f"Deve rejeitar senha incorreta: {r_fail.status_code}"
        print("[OK] Teste 1.1: Credenciais inválidas rejeitadas com HTTP 401.")

        # Caso 1.2: Senha Correta com MFA Ativo
        r_step1 = client.post("/api/v1/auth/login", json={"email": "admin@neurosec.ai", "password": "NeuroSec2026!Admin"})
        assert r_step1.status_code == 200, f"Login Passo 1 deve retornar 200: {r_step1.status_code}"
        data_step1 = r_step1.json()
        assert data_step1.get("mfa_required") is True
        assert data_step1.get("temp_token") is not None
        print(f"[OK] Teste 1.2: Credenciais válidas aceitas. Desafio MFA ativado (temp_token gerado).")

        # ---------------------------------------------------------------------
        # 2. TESTE DE LOGIN PASSO 2 (MFA / 2FA TOTP)
        # ---------------------------------------------------------------------
        # Caso 2.1: Código Invalido
        r_mfa_fail = client.post("/api/v1/auth/verify-mfa", json={
            "email": "admin@neurosec.ai",
            "code": "999999",
            "temp_token": data_step1.get("temp_token")
        })
        assert r_mfa_fail.status_code == 400
        print("[OK] Teste 2.1: Código 2FA inválido rejeitado com HTTP 400.")

        # Caso 2.2: Código TOTP Válido gerado com pyotp
        totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")
        valid_code = totp.now()
        r_mfa_ok = client.post("/api/v1/auth/verify-mfa", json={
            "email": "admin@neurosec.ai",
            "code": valid_code,
            "temp_token": data_step1.get("temp_token")
        })
        assert r_mfa_ok.status_code == 200
        auth_data = r_mfa_ok.json()
        jwt_token = auth_data.get("access_token")
        assert jwt_token is not None and len(jwt_token) > 20
        print(f"[OK] Teste 2.2: Código TOTP válido ({valid_code}) autenticado com sucesso! JWT gerado.")

        # Caso 2.3: Código de Demonstração Rápida (202640)
        r_mfa_demo = client.post("/api/v1/auth/verify-mfa", json={
            "email": "admin@neurosec.ai",
            "code": "202640"
        })
        assert r_mfa_demo.status_code == 200
        print("[OK] Teste 2.3: Código de Contingência / Demo (202640) validado com sucesso.")

        # ---------------------------------------------------------------------
        # 3. TESTE DE 1-CLICK DEMO LOGIN (PITCH MODE)
        # ---------------------------------------------------------------------
        r_demo = client.post("/api/v1/auth/demo-login")
        assert r_demo.status_code == 200
        demo_data = r_demo.json()
        assert demo_data["user"]["role"] == "SECOPS_ADMIN"
        print("[OK] Teste 3: 1-Click Demo Login autenticado com sucesso.")

        # ---------------------------------------------------------------------
        # 4. TESTE DE SETUP MFA COM QR CODE BASE64
        # ---------------------------------------------------------------------
        r_setup = client.post("/api/v1/auth/setup-mfa", json={"email": "admin@neurosec.ai"})
        assert r_setup.status_code == 200
        setup_data = r_setup.json()
        assert setup_data["qr_code_base64"].startswith("data:image/png;base64,")
        assert "otpauth://" in setup_data["provisioning_uri"]
        print(f"[OK] Teste 4: QR Code e URI otpauth gerados com sucesso para o autenticador móvel.")

        # ---------------------------------------------------------------------
        # 5. TESTE DE GESTÃO DE CLIENTES (CRUD & MULTI-TENANT HUB)
        # ---------------------------------------------------------------------
        # 5.1 Listar Clientes e Resumo Executivo
        r_clients = client.get("/api/v1/clients")
        assert r_clients.status_code == 200
        clients_list = r_clients.json()
        assert len(clients_list) >= 3
        print(f"[OK] Teste 5.1: Lista de clientes corporativos ({len(clients_list)} organizações encontradas).")

        r_summary = client.get("/api/v1/clients/summary")
        assert r_summary.status_code == 200
        sum_data = r_summary.json()
        assert sum_data["total_clients"] >= 3
        assert sum_data["average_score"] > 0
        print(f"[OK] Teste 5.2: Resumo Executivo de Clientes (Média Score: {sum_data['average_score']}/100, Ativos: {sum_data['total_monitored_assets']}).")

        # 5.2 Cadastrar Novo Cliente
        import time
        dyn_name = f"Fintech Alpha Test {int(time.time() * 1000)}"
        new_client_payload = {
            "name": dyn_name,
            "cnpj": "99.888.777/0001-66",
            "contact_name": "Juliana Prado",
            "contact_email": "juliana.prado@alphabrasil.com.br",
            "contact_phone": "+55 11 99999-8888",
            "sla_tier": "ENTERPRISE_24_7",
            "industry": "FINTECH",
            "notes": "Cliente corporativo de teste automatizado."
        }
        r_create = client.post("/api/v1/clients", json=new_client_payload)
        assert r_create.status_code == 200
        created_client = r_create.json()
        client_id = created_client["id"]
        print(f"[OK] Teste 5.3: Novo cliente '{created_client['name']}' cadastrado com ID #{client_id}.")

        # 5.3 Detalhes do Cliente
        r_detail = client.get(f"/api/v1/clients/{client_id}")
        assert r_detail.status_code == 200
        detail_data = r_detail.json()
        assert len(detail_data["assets"]) >= 1
        print(f"[OK] Teste 5.4: Detalhes do cliente #{client_id} obtidos (Ativos vinculados: {len(detail_data['assets'])}).")

        # 5.4 Disparar Varredura para o Cliente
        r_scan = client.post(f"/api/v1/clients/{client_id}/scan")
        assert r_scan.status_code == 200
        scan_data = r_scan.json()
        assert scan_data["new_security_score"] >= 85
        print(f"[OK] Teste 5.5: Varredura autônoma disparada para o cliente #{client_id} (Novo Score: {scan_data['new_security_score']}/100).")

        # 5.5 Atualizar Dados do Cliente
        r_update = client.put(f"/api/v1/clients/{client_id}", json={"sla_tier": "BUSINESS_CRITICAL"})
        assert r_update.status_code == 200
        assert r_update.json()["sla_tier"] == "BUSINESS_CRITICAL"
        print(f"[OK] Teste 5.6: Dados do cliente #{client_id} atualizados com sucesso.")

        # 5.6 Remover Cliente de Teste
        r_del = client.delete(f"/api/v1/clients/{client_id}")
        assert r_del.status_code == 200
        print(f"[OK] Teste 5.7: Cliente #{client_id} removido com sucesso.")

        # 5.7 Teste da Rota /login e /dashboard do Frontend
        r_page_login = client.get("/login")
        assert r_page_login.status_code == 200
        assert "Controle de Acesso SecOps" in r_page_login.text or "NeuroSec" in r_page_login.text
        print("[OK] Teste 6: Rota frontend /login operacional com HTML5 e Matrix Glassmorphism.")

    print("\n========================================================================")
    print("      TODOS OS TESTES DE LOGIN, MFA E GESTÃO DE CLIENTES PASSARAM!      ")
    print("========================================================================")

if __name__ == "__main__":
    run_auth_and_clients_tests()
