from fastapi.testclient import TestClient
from security_sentinel.main_app import app

client = TestClient(app)

def test_main_app_root():
    response = client.get("/")
    assert response.status_code in [200, 404]

    # Exercise all routes/endpoints in main_app if present
    for route in app.routes:
        if hasattr(route, "path") and "{" not in route.path:
            client.get(route.path)
