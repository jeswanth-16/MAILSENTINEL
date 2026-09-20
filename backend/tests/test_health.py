import pytest
from fastapi.testclient import TestClient
from app.main import app

public_client = TestClient(app)

def test_health_check_endpoint():
    """
    Tests GET /api/v1/health endpoint meets exact required specification (public).
    """
    response = public_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "mailsentinel-api"

def test_investigations_list_endpoint(client):
    """
    Tests GET /api/v1/investigations returns seeded investigation cases.
    """
    response = client.get("/api/v1/investigations")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "investigations" in data
    assert data["total"] > 0
