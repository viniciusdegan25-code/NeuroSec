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
    print("     TESTES DO MOTOR DE RISCO FINANCEIRO QUANTITATIVO (FAIR / NIST / LGPD)")
    print("========================================================================")

    init_db(seed=True)

    with TestClient(app) as client:
        # 1. Obter Análise Financeira do Banco Aurora (Fintech Tier 1)
        r_aurora = client.get("/api/v1/clients/1/financial-analysis")
        assert r_aurora.status_code == 200, f"Status: {r_aurora.status_code}"
        data_aurora = r_aurora.json()
        assert data_aurora["client_name"] == "Banco Aurora S.A."
        assert data_aurora["annual_revenue_brl"] == 450000000.0
        assert data_aurora["sensitive_records_count"] == 1200000
        assert data_aurora["cost_per_record_brl"] == 450.0  # Setor Fintech
        assert data_aurora["financial_exposure_risk_brl"] > 0
        print(f"[OK] Banco Aurora S.A.:")
        print(f"     - Faturamento: R$ {data_aurora['annual_revenue_brl']:,.2f}")
        print(f"     - Registros LGPD: {data_aurora['sensitive_records_count']:,}")
        print(f"     - Exposição Financeira em Risco: R$ {data_aurora['financial_exposure_risk_brl']:,.2f}")
        print(f"     - Scorecard Contextualizado: {data_aurora['security_score']}/100 ({data_aurora['grade']})")

        # 2. Obter Análise Financeira da AeroLog (Logística Tier 2)
        r_aerolog = client.get("/api/v1/clients/3/financial-analysis")
        assert r_aerolog.status_code == 200
        data_aerolog = r_aerolog.json()
        assert data_aerolog["cost_per_record_brl"] == 195.0  # Setor Logística
        assert data_aerolog["annual_revenue_brl"] == 35000000.0
        print(f"[OK] AeroLog Logística Digital:")
        print(f"     - Faturamento: R$ {data_aerolog['annual_revenue_brl']:,.2f}")
        print(f"     - Custo por Registro: R$ {data_aerolog['cost_per_record_brl']:.2f}")
        print(f"     - Exposição Financeira em Risco: R$ {data_aerolog['financial_exposure_risk_brl']:,.2f}")

        # 3. Validar que o risco do Banco Aurora é proporcionalmente maior que da AeroLog
        assert data_aurora["financial_exposure_risk_brl"] > data_aerolog["financial_exposure_risk_brl"], "Instituição bancária com 1.2M clientes deve ter risco financeiro maior que transportadora com 60k clientes."
        print("[OK] Validação de Proporcionalidade: Risco financeiro varia realisticamente com o porte, setor e dados do cliente.")

        # 4. Validar Resumo Executivo Global de Clientes
        r_sum = client.get("/api/v1/clients/summary")
        assert r_sum.status_code == 200
        sum_json = r_sum.json()
        assert sum_json["total_financial_exposure_risk_brl"] > 0
        print(f"[OK] Resumo Global de Portfólio:")
        print(f"     - Total de Prejuízo Evitado: R$ {sum_json['total_financial_loss_avoided_brl']:,.2f}")
        print(f"     - Total de Exposição em Aberto: R$ {sum_json['total_financial_exposure_risk_brl']:,.2f}")

        # 5. Criar Cliente com Parâmetros Customizados e Testar
        import time
        custom_name = f"HealthTech Vitalis {int(time.time()*1000)}"
        r_create = client.post("/api/v1/clients", json={
            "name": custom_name,
            "contact_name": "Dr. Fernando Costa",
            "contact_email": "fernando@vitalis.med.br",
            "industry": "HEALTHCARE",
            "annual_revenue_brl": 120000000.0,
            "sensitive_records_count": 500000,
            "downtime_cost_per_hour": 75000.0
        })
        assert r_create.status_code == 200
        created = r_create.json()
        new_id = created["id"]
        assert created["industry"] == "HEALTHCARE"
        assert created["annual_revenue_brl"] == 120000000.0

        r_new_fin = client.get(f"/api/v1/clients/{new_id}/financial-analysis")
        assert r_new_fin.status_code == 200
        assert r_new_fin.json()["cost_per_record_brl"] == 510.0  # Healthcare cost
        print(f"[OK] HealthTech Vitalis cadastrada com R$ 510/registro (Healthcare) e R$ 120M receita.")

        # Cleanup
        client.delete(f"/api/v1/clients/{new_id}")

    print("\n========================================================================")
    print("      TODOS OS TESTES DO MOTOR DE IMPACTO FINANCEIRO PASSARAM COM SUCESSO! ")
    print("========================================================================")

if __name__ == "__main__":
    test_financial_risk_engine()
