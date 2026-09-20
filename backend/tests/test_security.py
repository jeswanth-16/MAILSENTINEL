from datetime import datetime, timezone, timedelta
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    sanitize_filename,
    sanitize_identifier,
)
from app.services.auth import (
    User,
    UserRole,
    LoginRequest,
    default_auth_service,
    default_user_repository,
    default_security_audit_logger,
    default_rate_limiter,
)
from app.services.auth.rbac import (
    has_permission,
    ROLE_PERMISSIONS,
    PERM_MANAGE_USERS,
    PERM_SIMULATE_TAMPER,
    PERM_EXECUTE_ACTION,
    PERM_CREATE_CASE,
    PERM_VIEW_INVESTIGATION,
    PERM_VIEW_AUDIT,
)


# ============================================================================
# 1. CRYPTO & TOKEN TESTS
# ============================================================================

def test_password_hashing_and_verification():
    raw_pass = "SOC_Secure_Password_2026!"
    pw_hash = hash_password(raw_pass)
    
    assert pw_hash.startswith("pbkdf2_sha256$200000$")
    assert verify_password(raw_pass, pw_hash) is True
    assert verify_password("WrongPassword123!", pw_hash) is False
    assert verify_password("", pw_hash) is False


def test_jwt_token_lifecycle():
    user_id = "usr-test-01"
    role = "ADMIN"
    claims = {"sub": user_id, "role": role, "email": "test@mailsentinel.local", "name": "Security Test User", "type": "access"}
    
    token = create_access_token(data=claims, expires_delta=timedelta(minutes=15))
    assert isinstance(token, str)
    assert len(token) > 20
    
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == user_id
    assert payload["role"] == role
    assert payload["email"] == "test@mailsentinel.local"
    assert payload["type"] == "access"


def test_jwt_token_tampering_and_expiration():
    token = create_access_token(data={"sub": "usr-123", "role": "ADMIN", "type": "access"}, expires_delta=timedelta(seconds=-10))
    # Expired token
    payload = decode_access_token(token)
    assert payload is None
    
    # Tampered token
    valid_token = create_access_token(data={"sub": "usr-123", "role": "ADMIN", "type": "access"})
    parts = valid_token.split(".")
    tampered_token = f"{parts[0]}.{parts[1]}A.{parts[2]}"
    assert decode_access_token(tampered_token) is None


def test_path_and_identifier_sanitization():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\windows\\system32\\calc.exe") == "calc.exe"
    assert sanitize_filename("normal_file.eml") == "normal_file.eml"
    
    assert sanitize_identifier("CASE-2026-001") == "CASE-2026-001"
    assert sanitize_identifier("../CASE-2026-001\x00") == "CASE-2026-001"
    assert sanitize_identifier("INV/123/..") == "INV123"


# ============================================================================
# 2. RBAC PERMISSIONS MATRIX TESTS
# ============================================================================

def test_rbac_permission_matrix():
    assert has_permission(UserRole.ADMIN, PERM_MANAGE_USERS) is True
    assert has_permission(UserRole.ADMIN, PERM_SIMULATE_TAMPER) is True
    assert has_permission(UserRole.ADMIN, PERM_EXECUTE_ACTION) is True
    
    assert has_permission(UserRole.SOC_ANALYST, PERM_MANAGE_USERS) is False
    assert has_permission(UserRole.SOC_ANALYST, PERM_SIMULATE_TAMPER) is False
    assert has_permission(UserRole.SOC_ANALYST, PERM_CREATE_CASE) is True
    assert has_permission(UserRole.SOC_ANALYST, PERM_VIEW_INVESTIGATION) is True
    
    assert has_permission(UserRole.VIEWER, PERM_CREATE_CASE) is False
    assert has_permission(UserRole.VIEWER, PERM_EXECUTE_ACTION) is False
    assert has_permission(UserRole.VIEWER, PERM_VIEW_INVESTIGATION) is True
    
    assert has_permission(UserRole.AUDITOR, PERM_VIEW_AUDIT) is True
    assert has_permission(UserRole.AUDITOR, PERM_CREATE_CASE) is False


# ============================================================================
# 3. AUTH SERVICE & LOCKOUT LOGIC
# ============================================================================

def test_auth_service_login_and_lockout():
    # Setup test user
    test_email = "lockout_test@mailsentinel.local"
    test_pass = "ValidPass123!"
    test_user = User(
        id="USR-TEST-LOCKOUT",
        email=test_email,
        full_name="Lockout Test Analyst",
        role=UserRole.SOC_ANALYST,
        is_active=True,
        is_locked=False,
        failed_login_attempts=0,
        locked_until=None,
        created_at=datetime.now(timezone.utc),
        hashed_password=hash_password(test_pass),
    )
    default_user_repository.save(test_user)
    
    # 1. Success login
    user, err = default_auth_service.authenticate_user(LoginRequest(email=test_email, password=test_pass))
    assert user is not None
    assert err is None
    assert user.failed_login_attempts == 0
    
    # 2. Fail 5 times
    for i in range(5):
        u_fail, err_fail = default_auth_service.authenticate_user(LoginRequest(email=test_email, password="WrongPassword!"))
        assert u_fail is None
        assert err_fail is not None
        
    # Check locked status
    u_locked = default_user_repository.get_by_email(test_email)
    assert u_locked is not None
    assert u_locked.failed_login_attempts >= 5
    assert u_locked.is_locked is True
    
    # Attempting with correct password while locked must fail
    u_blocked, err_blocked = default_auth_service.authenticate_user(LoginRequest(email=test_email, password=test_pass))
    assert u_blocked is None
    assert "locked" in (err_blocked or "").lower()


# ============================================================================
# 4. API AUTH & RBAC ENDPOINT TESTS
# ============================================================================

def test_auth_login_api_endpoint(client: TestClient):
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@mailsentinel.local", "password": "Admin@12345!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["role"] == "ADMIN"
    assert data["user"]["email"] == "admin@mailsentinel.local"


def test_auth_login_invalid_credentials(client: TestClient):
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@mailsentinel.local", "password": "IncorrectPassword!"},
    )
    assert resp.status_code == 401


def test_auth_me_endpoint(client: TestClient, admin_token: str):
    # Without token -> 401
    unauth_client = TestClient(app)
    unauth_resp = unauth_client.get("/api/v1/auth/me")
    assert unauth_resp.status_code == 401
    
    # With valid admin token -> 200
    auth_resp = unauth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert auth_resp.status_code == 200
    user_info = auth_resp.json()
    assert user_info["email"] == "admin@mailsentinel.local"
    assert user_info["role"] == "ADMIN"


def test_admin_rbac_protection(client: TestClient, admin_token: str, analyst_token: str, viewer_token: str):
    unauth_client = TestClient(app)
    
    # Admin can list users
    admin_resp = unauth_client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert admin_resp.status_code == 200
    assert len(admin_resp.json()) >= 6
    
    # Analyst cannot access admin users endpoint (403)
    analyst_resp = unauth_client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert analyst_resp.status_code == 403
    
    # Viewer cannot access admin users endpoint (403)
    viewer_resp = unauth_client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert viewer_resp.status_code == 403


def test_admin_user_management_lifecycle(client: TestClient, admin_token: str):
    headers = {"Authorization": f"Bearer {admin_token}"}
    unauth_client = TestClient(app)
    
    # 1. Create a new user
    new_user_email = "new_soc_analyst_2026@mailsentinel.local"
    create_resp = unauth_client.post(
        "/api/v1/admin/users",
        headers=headers,
        json={
            "email": new_user_email,
            "password": "TemporaryPassword123!",
            "full_name": "New Junior Analyst",
            "role": "SOC_ANALYST",
        },
    )
    assert create_resp.status_code == 201
    created_user = create_resp.json()
    user_id = created_user["id"]
    assert created_user["email"] == new_user_email
    assert created_user["role"] == "SOC_ANALYST"
    
    # 2. Update role to SENIOR_ANALYST
    role_resp = unauth_client.patch(
        f"/api/v1/admin/users/{user_id}/role",
        headers=headers,
        json={"role": "SENIOR_ANALYST"},
    )
    assert role_resp.status_code == 200
    assert role_resp.json()["role"] == "SENIOR_ANALYST"
    
    # 3. Disable user
    status_resp = unauth_client.patch(
        f"/api/v1/admin/users/{user_id}/status",
        headers=headers,
        json={"is_active": False},
    )
    assert status_resp.status_code == 200
    assert status_resp.json()["is_active"] is False
    
    # 4. Reset password
    reset_resp = unauth_client.post(
        f"/api/v1/admin/users/{user_id}/reset-password",
        headers=headers,
        json={"new_password": "NewSecurePassword456!"},
    )
    assert reset_resp.status_code == 200


def test_admin_security_metrics_and_audit_logs(client: TestClient, admin_token: str):
    headers = {"Authorization": f"Bearer {admin_token}"}
    unauth_client = TestClient(app)
    
    # Metrics
    metrics_resp = unauth_client.get("/api/v1/admin/security/metrics", headers=headers)
    assert metrics_resp.status_code == 200
    metrics = metrics_resp.json()
    assert "total_users" in metrics
    assert "active_users" in metrics
    assert "failed_logins_24h" in metrics
    
    # Audit logs
    logs_resp = unauth_client.get("/api/v1/admin/security/audit-logs?limit=20", headers=headers)
    assert logs_resp.status_code == 200
    logs = logs_resp.json()
    assert isinstance(logs, list)
    assert len(logs) > 0


# ============================================================================
# 5. SECURITY HEADERS MIDDLEWARE TESTS
# ============================================================================

def test_security_headers_present(client: TestClient):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    headers = resp.headers
    
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "content-security-policy" in headers
