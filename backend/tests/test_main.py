import importlib

from fastapi.testclient import TestClient


def load_app_module(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/cloudthreat")
    monkeypatch.setenv("JWT_SECRET_KEY", "supersecretkeyforlocaltestingatleast32chars")
    import app.main as main_module

    importlib.reload(main_module)
    return main_module


def test_health_endpoint_reports_service_status(monkeypatch) -> None:
    main_module = load_app_module(monkeypatch)
    client = TestClient(main_module.app)

    response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["service"] == "cloud-threat-detection-system"
    assert payload["status"] in {"ok", "degraded"}
    assert "timestamp" in payload


def test_auth_router_is_registered(monkeypatch) -> None:
    main_module = load_app_module(monkeypatch)

    routes = [route.path for route in main_module.app.router.routes]

    assert "/auth/register" in routes
    assert "/auth/login" in routes
    assert "/auth/me" in routes


def test_cors_headers_are_present_for_origin_requests(monkeypatch) -> None:
    main_module = load_app_module(monkeypatch)
    client = TestClient(main_module.app)

    response = client.get("/health", headers={"Origin": "https://example.com"})

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "*"
