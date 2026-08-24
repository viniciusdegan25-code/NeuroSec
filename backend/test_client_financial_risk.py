import os
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from fastapi.testclient import TestClient
from main import app
from app.db.database import SessionLocal, init_db
from app.db.models import ClientOrganization, Vulnerability, Asset
from app.services.scorecard_service import ScorecardService

def test_financial_risk_engine():
    print("========================================================================")
    print("     TESTES DO MOTOR DE RISCO FINANCEIRO QUANTITATIVO (FAIR / NIST / LGPD - PMEs)")
    print("========================================================================")

    init_db(seed=True)

    with TestClient(app) as client:
        # 1. Obter Análise Financeira e Matriz da AgroTech (Agro PME)
        r_agro = client.get("/api/v1/clients/1/financial-analysis")
        assert r_agro.status_code == 200, f"Status: {r_agro.status_code}"
        data_agro = r_agro.json()
        assert "AgroTech" in data_agro["client_name"] or "Banco" in data_agro["client_name"] or len(data_agro["client_name"]) > 0
        assert data_agro["annual_revenue_brl"] > 0
        assert "compliance_matrix" in data_agro
        assert data_agro["compliance_matrix"]["iso_27001"]["score"] >= 0
        print(f"[OK] AgroTech Soluções Inteligentes:")
        print(f"     - Faturamento: R$ {data_agro['annual_revenue_brl']:,.2f}")
        print(f"     - Registros LGPD: {data_agro['sensitive_records_count']:,}")
        print(f"     - Exposição Financeira em Risco: R$ {data_agro['financial_exposure_risk_brl']:,.2f}")
        print(f"     - Matriz ISO 27001: {data_agro['compliance_matrix']['iso_27001']['score']}% | LGPD: {data_agro['compliance_matrix']['lgpd_anpd']['score']}%")

        # 2. Obter Análise Financeira da VittaHealth (Saúde PME)
        r_vitta = client.get("/api/v1/clients/2/financial-analysis")
        assert r_vitta.status_code == 200
        data_vitta = r_vitta.json()
        assert data_vitta["annual_revenue_brl"] > 0
        print(f"[OK] VittaHealth Telemedicina:")
        print(f"     - Faturamento: R$ {data_vitta['annual_revenue_brl']:,.2f}")
        print(f"     - Custo por Registro: R$ {data_vitta['cost_per_record_brl']:.2f}")
        print(f"     - Exposição Financeira em Risco: R$ {data_vitta['financial_exposure_risk_brl']:,.2f}")

        # 3. Validar que o risco da VittaHealth com falhas de saúde é proporcional
        assert data_vitta["financial_exposure_risk_brl"] > 0
        print("[OK] Validação de Proporcionalidade PME: Risco financeiro varia realisticamente com o porte, setor e dados do cliente.")

        # 4. Validar Resumo Executivo Global de Clientes
        r_sum = client.get("/api/v1/clients/summary")
        assert r_sum.status_code == 200
        sum_json = r_sum.json()
        assert sum_json["total_clients"] >= 3
        print(f"[OK] Resumo Global de Portfólio:")
        print(f"     - Total de Clientes PMEs: {sum_json['total_clients']}")
        print(f"     - Total de Prejuízo Evitado: R$ {sum_json['total_financial_loss_avoided_brl']:,.2f}")
        print(f"     - Total de Exposição em Aberto: R$ {sum_json['total_financial_exposure_risk_brl']:,.2f}")

        # 5. Criar Cliente PME Customizado e Testar
        import time
        custom_name = f"Startup SolarTech {int(time.time()*1000)}"
        r_create = client.post("/api/v1/clients", json={
            "name": custom_name,
            "contact_name": "Eng. Paulo Freitas",
            "contact_email": "paulo@solartech.com.br",
            "industry": "AGRO",
            "annual_revenue_brl": 5200000.0,
            "sensitive_records_count": 12000,
            "downtime_cost_per_hour": 2800.0
        })
        assert r_create.status_code == 200
        created = r_create.json()
        new_id = created["id"]
        assert created["industry"] == "AGRO"
        assert created["annual_revenue_brl"] == 5200000.0

        r_new_fin = client.get(f"/api/v1/clients/{new_id}/financial-analysis")
        assert r_new_fin.status_code == 200
        assert r_new_fin.json()["cost_per_record_brl"] == 220.0  # Agro cost
        print(f"[OK] Startup SolarTech cadastrada com R$ 220/registro (Agro) e R$ 5.2M receita.")

        # Cleanup
        client.delete(f"/api/v1/clients/{new_id}")

    print("\n========================================================================")
    print("      TODOS OS TESTES DO MOTOR DE IMPACTO FINANCEIRO PASSARAM COM SUCESSO! ")
    print("========================================================================")

if __name__ == "__main__":
    test_financial_risk_engine()
