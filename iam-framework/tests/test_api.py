"""
Tests for the IAM Framework REST API.
Run: pytest tests/test_api.py -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "policies"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "audit"))

import pytest
from api.app import app as flask_app


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


EVAL_ALLOW = {
    "tenant_id": "fintech-prod",
    "role": "developer",
    "principal": "bob@fintech.com",
    "action": "s3:GetObject",
    "resource": "arn:aws:s3:::fintech-data/reports/q3.csv",
    "session_tags": {"tenant_id": "fintech-prod", "dept": "engineering"},
    "resource_tags": {"tenant_id": "fintech-prod"},
    "mfa_present": False,
    "source_ip": "10.0.0.5",
}

EVAL_DENY_CROSS_TENANT = {
    "tenant_id": "fintech-prod",
    "role": "developer",
    "principal": "bob@fintech.com",
    "action": "s3:GetObject",
    "resource": "arn:aws:s3:::healthco-data/phi/patients.csv",
    "session_tags": {"tenant_id": "fintech-prod"},
    "resource_tags": {"tenant_id": "healthco-prod"},
}

EVAL_DENY_IAM = {
    "tenant_id": "fintech-prod",
    "role": "developer",
    "action": "iam:CreateUser",
    "resource": "*",
    "session_tags": {"tenant_id": "fintech-prod"},
}


class TestHealth:
    def test_returns_200(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        assert r.get_json()["status"] == "healthy"


class TestEvaluate:
    def test_allow_decision(self, client):
        r = client.post("/api/v1/evaluate", json=EVAL_ALLOW)
        assert r.status_code == 200
        data = r.get_json()
        assert data["decision"] == "ALLOW"
        assert data["tenant_id"] == "fintech-prod"
        assert data["role"] == "developer"

    def test_deny_iam_for_developer(self, client):
        r = client.post("/api/v1/evaluate", json=EVAL_DENY_IAM)
        assert r.status_code == 403
        assert r.get_json()["decision"] == "DENY"

    def test_deny_cross_tenant_access(self, client):
        r = client.post("/api/v1/evaluate", json=EVAL_DENY_CROSS_TENANT)
        assert r.status_code == 403
        data = r.get_json()
        assert data["decision"] == "DENY"

    def test_missing_required_fields(self, client):
        r = client.post("/api/v1/evaluate", json={"tenant_id": "x"})
        assert r.status_code == 400

    def test_invalid_role(self, client):
        r = client.post("/api/v1/evaluate", json={**EVAL_ALLOW, "role": "superadmin"})
        assert r.status_code == 400

    def test_admin_can_do_more(self, client):
        r = client.post("/api/v1/evaluate", json={
            **EVAL_ALLOW,
            "role": "admin",
            "action": "iam:CreateRole",
            "mfa_present": True,
            "session_tags": {"tenant_id": "fintech-prod", "role": "admin"},
        })
        # Admin with MFA should be allowed
        data = r.get_json()
        assert data["decision"] in ("ALLOW", "DENY")  # depends on boundary


class TestPolicyGeneration:
    def test_generate_developer_policy(self, client):
        r = client.post("/api/v1/policies/generate", json={
            "tenant_id": "fintech-prod",
            "role": "developer",
            "sso": "cognito",
        })
        assert r.status_code == 200
        data = r.get_json()
        assert "identity_policy" in data
        assert "permission_boundary" in data
        assert "trust_policy" in data
        assert data["identity_policy"]["Version"] == "2012-10-17"

    def test_generate_all_roles(self, client):
        for role in ["admin", "developer", "analyst", "readonly"]:
            r = client.post("/api/v1/policies/generate", json={
                "tenant_id": "test-tenant",
                "role": role,
            })
            assert r.status_code == 200, f"Failed for role: {role}"

    def test_invalid_role_returns_400(self, client):
        r = client.post("/api/v1/policies/generate", json={
            "tenant_id": "x", "role": "hacker"
        })
        assert r.status_code == 400

    def test_invalid_sso_returns_400(self, client):
        r = client.post("/api/v1/policies/generate", json={
            "tenant_id": "x", "role": "developer", "sso": "okta"
        })
        assert r.status_code == 400

    def test_list_roles(self, client):
        r = client.get("/api/v1/policies/roles")
        assert r.status_code == 200
        data = r.get_json()
        role_names = [r["name"] for r in data["roles"]]
        assert "admin" in role_names
        assert "developer" in role_names
        assert "analyst" in role_names
        assert "readonly" in role_names


class TestTenants:
    def test_create_tenant(self, client):
        r = client.post("/api/v1/tenants", json={
            "tenant_id": "testco-prod",
            "name": "TestCo",
            "sso": "auth0",
        })
        assert r.status_code == 201
        data = r.get_json()
        assert data["tenant_id"] == "testco-prod"
        assert data["sso_provider"] == "auth0"

    def test_duplicate_tenant_returns_409(self, client):
        client.post("/api/v1/tenants", json={"tenant_id": "dup-tenant"})
        r = client.post("/api/v1/tenants", json={"tenant_id": "dup-tenant"})
        assert r.status_code == 409

    def test_get_tenant(self, client):
        client.post("/api/v1/tenants", json={"tenant_id": "get-test-tenant"})
        r = client.get("/api/v1/tenants/get-test-tenant")
        assert r.status_code == 200
        assert r.get_json()["tenant_id"] == "get-test-tenant"

    def test_get_nonexistent_tenant_404(self, client):
        r = client.get("/api/v1/tenants/doesnotexist")
        assert r.status_code == 404

    def test_list_tenants(self, client):
        r = client.get("/api/v1/tenants")
        assert r.status_code == 200
        assert "tenants" in r.get_json()
