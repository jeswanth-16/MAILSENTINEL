import os
import pytest
from fastapi.testclient import TestClient

from app.core.security import create_access_token
from app.main import app
from app.services.auth import default_user_repository


@pytest.fixture(scope="session", autouse=True)
def isolated_test_db(tmp_path_factory):
    """Ensure test suite runs against an isolated hermetic SQLite database."""
    temp_dir = tmp_path_factory.mktemp("mailsentinel_tests")
    test_db_path = str(temp_dir / "test_suite.db")
    os.environ["MAILSENTINEL_DB_PATH"] = test_db_path
    from app.core.database import init_db
    init_db(test_db_path)
    yield test_db_path


@pytest.fixture(autouse=True)
def seed_users():
    default_user_repository.ensure_seeded()


@pytest.fixture
def admin_token():
    admin = default_user_repository.get_by_email("admin@mailsentinel.local")
    return create_access_token({
        "sub": admin.id,
        "email": admin.email,
        "role": admin.role.value,
        "name": admin.full_name,
    })


@pytest.fixture
def analyst_token():
    analyst = default_user_repository.get_by_email("analyst@mailsentinel.local")
    return create_access_token({
        "sub": analyst.id,
        "email": analyst.email,
        "role": analyst.role.value,
        "name": analyst.full_name,
    })


@pytest.fixture
def senior_token():
    senior = default_user_repository.get_by_email("senior@mailsentinel.local")
    return create_access_token({
        "sub": senior.id,
        "email": senior.email,
        "role": senior.role.value,
        "name": senior.full_name,
    })


@pytest.fixture
def responder_token():
    resp = default_user_repository.get_by_email("responder@mailsentinel.local")
    return create_access_token({
        "sub": resp.id,
        "email": resp.email,
        "role": resp.role.value,
        "name": resp.full_name,
    })


@pytest.fixture
def auditor_token():
    auditor = default_user_repository.get_by_email("auditor@mailsentinel.local")
    return create_access_token({
        "sub": auditor.id,
        "email": auditor.email,
        "role": auditor.role.value,
        "name": auditor.full_name,
    })


@pytest.fixture
def viewer_token():
    viewer = default_user_repository.get_by_email("viewer@mailsentinel.local")
    return create_access_token({
        "sub": viewer.id,
        "email": viewer.email,
        "role": viewer.role.value,
        "name": viewer.full_name,
    })


@pytest.fixture
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def client(auth_headers):
    # TestClient with default admin authorization header
    c = TestClient(app)
    c.headers.update(auth_headers)
    return c
