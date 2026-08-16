import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from fastapi.testclient import TestClient
from main import app

def test_routes():
    client = TestClient(app)

    # 1. Test Root
    r_root = client.get("/")
    print(f"[OK] Root / -> Status {r_root.status_code}")
    assert r_root.status_code == 200

    # 2. Test CSS
    r_css = client.get("/css/styles.css")
    print(f"[OK] CSS /css/styles.css -> Status {r_css.status_code} (Size: {len(r_css.text)} bytes)")
    assert r_css.status_code == 200

    # 3. Test JS
    r_js = client.get("/js/api.js")
    print(f"[OK] JS /js/api.js -> Status {r_js.status_code} (Size: {len(r_js.text)} bytes)")
    assert r_js.status_code == 200

    # 4. Test Scorecard API
    r_sc = client.get("/api/v1/scorecard")
    data = r_sc.json()
    print(f"[OK] API /api/v1/scorecard -> Status {r_sc.status_code}, Score: {data.get('score')}/100")
    assert r_sc.status_code == 200

    print("\n=======================================================")
    print("TODAS AS ROTAS ESTATICAS E APIs ESTAO 100% FUNCIONANDO!")
    print("=======================================================")

if __name__ == "__main__":
    test_routes()
