"""
IAM Framework REST API

Exposes policy generation and evaluation over HTTP.
Useful for integrating with internal tooling, SOAR, or just
testing access decisions from curl/Postman.

Endpoints:
    POST /api/v1/evaluate          — evaluate an access request
    POST /api/v1/policies/generate — generate IAM policy JSON for a role
    GET  /api/v1/tenants           — list configured tenants
    POST /api/v1/tenants           — register a new tenant
    GET  /api/v1/tenants/<id>      — get tenant details + user roster
    GET  /api/v1/audit/<tenant_id> — get audit log for a tenant
    GET  /api/v1/health            — health check

Run locally:
    python api/app.py

With gunicorn:
    gunicorn api.app:app --bind 0.0.0.0:8000 --workers 2
"""

import logging
import os
import sys
from datetime import datetime, timezone

from flask import Flask, jsonify, request, abort
from flask_cors import CORS

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "policies"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "audit"))

from evaluator import PolicyEvaluator, EvaluationContext, Decision
from generator import generate_policy, generate_permission_boundary, generate_trust_policy
from templates import ROLE_TEMPLATES
from logger import AuditLogger

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# In-memory tenant registry — swap for DynamoDB/Postgres in production
_tenants: dict[str, dict] = {}
_audit_loggers: dict[str, AuditLogger] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_or_create_logger(tenant_id: str) -> AuditLogger:
    if tenant_id not in _audit_loggers:
        _audit_loggers[tenant_id] = AuditLogger(tenant_id)
    return _audit_loggers[tenant_id]


def _build_evaluator(tenant_id: str, role: str) -> PolicyEvaluator | None:
    tenant = _tenants.get(tenant_id)
    if not tenant:
        return None

    ev = PolicyEvaluator()
    try:
        policy = generate_policy(tenant_id, role)
        ev.load_identity_policy(policy, source=f"{tenant_id}/{role}")
        boundary = generate_permission_boundary(tenant_id)
        ev.load_permission_boundary(boundary)
    except ValueError:
        return None
    return ev


# ---------------------------------------------------------------------------
# Routes — Policy Evaluation
# ---------------------------------------------------------------------------

@app.route("/api/v1/evaluate", methods=["POST"])
def evaluate():
    """
    Evaluate an IAM access request.

    Body:
    {
        "tenant_id":    "fintech-prod",
        "role":         "developer",
        "principal":    "alice@company.com",
        "action":       "s3:GetObject",
        "resource":     "arn:aws:s3:::tenant-data/report.csv",
        "session_tags": { "tenant_id": "fintech-prod", "dept": "engineering" },
        "resource_tags": { "tenant_id": "fintech-prod" },
        "mfa_present":  true,
        "source_ip":    "10.0.0.5"
    }
    """
    body = request.get_json(silent=True)
    if not body:
        abort(400, description="Request body must be JSON")

    required = ["tenant_id", "role", "action", "resource"]
    missing = [f for f in required if not body.get(f)]
    if missing:
        abort(400, description=f"Missing required fields: {missing}")

    tenant_id = body["tenant_id"]
    role = body["role"]
    principal = body.get("principal", f"{tenant_id}/{role}")

    if role not in ROLE_TEMPLATES:
        abort(400, description=f"Unknown role {role!r}. Valid: {list(ROLE_TEMPLATES.keys())}")

    ev = _build_evaluator(tenant_id, role)
    if ev is None:
        # Tenant not registered — build evaluator from role template directly
        ev = PolicyEvaluator()
        policy = generate_policy(tenant_id, role)
        ev.load_identity_policy(policy, source=f"{tenant_id}/{role}")
        boundary = generate_permission_boundary(tenant_id)
        ev.load_permission_boundary(boundary)

    ctx = EvaluationContext(
        principal=principal,
        action=body["action"],
        resource=body["resource"],
        session_tags=body.get("session_tags", {}),
        resource_tags=body.get("resource_tags", {}),
        mfa_present=body.get("mfa_present", False),
        source_ip=body.get("source_ip"),
    )

    result = ev.evaluate(ctx)

    # Log the decision
    audit = _get_or_create_logger(tenant_id)
    audit.log_decision(
        principal=principal,
        action=body["action"],
        resource=body["resource"],
        decision=result.decision.value,
        reason=result.reason,
        session_tags=body.get("session_tags", {}),
        source_ip=body.get("source_ip", ""),
        request_id=request.headers.get("X-Request-ID", ""),
    )

    response = {
        "decision": result.decision.value,
        "reason": result.reason,
        "policy_source": result.policy_source,
        "tenant_id": tenant_id,
        "role": role,
        "principal": principal,
        "action": body["action"],
        "resource": body["resource"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if result.matched_statement:
        response["matched_statement_sid"] = result.matched_statement.get("Sid", "")

    status = 200 if result.decision == Decision.ALLOW else 403
    return jsonify(response), status


# ---------------------------------------------------------------------------
# Routes — Policy Generation
# ---------------------------------------------------------------------------

@app.route("/api/v1/policies/generate", methods=["POST"])
def generate_policies():
    """
    Generate IAM policy documents for a tenant+role.

    Body: { "tenant_id": "fintech-prod", "role": "developer", "sso": "cognito" }
    Returns: identity policy, permission boundary, and trust policy JSON.
    """
    body = request.get_json(silent=True) or {}
    tenant_id = body.get("tenant_id")
    role = body.get("role")
    sso = body.get("sso", "cognito")

    if not tenant_id or not role:
        abort(400, description="'tenant_id' and 'role' are required")
    if role not in ROLE_TEMPLATES:
        abort(400, description=f"Unknown role. Valid: {list(ROLE_TEMPLATES.keys())}")
    if sso not in ("cognito", "auth0"):
        abort(400, description="'sso' must be 'cognito' or 'auth0'")

    try:
        identity_policy = generate_policy(tenant_id, role)
        boundary = generate_permission_boundary(tenant_id)
        trust_policy = generate_trust_policy(tenant_id, sso)
    except ValueError as e:
        abort(400, description=str(e))

    return jsonify({
        "tenant_id": tenant_id,
        "role": role,
        "sso_provider": sso,
        "identity_policy": identity_policy,
        "permission_boundary": boundary,
        "trust_policy": trust_policy,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/v1/policies/roles", methods=["GET"])
def list_roles():
    """List all available role tiers."""
    return jsonify({
        "roles": [
            {
                "name": name,
                "description": tmpl["description"],
                "action_group_count": len(tmpl["action_groups"]),
            }
            for name, tmpl in ROLE_TEMPLATES.items()
        ]
    })


# ---------------------------------------------------------------------------
# Routes — Tenant Management
# ---------------------------------------------------------------------------

@app.route("/api/v1/tenants", methods=["GET"])
def list_tenants():
    return jsonify({
        "tenants": list(_tenants.values()),
        "total": len(_tenants),
    })


@app.route("/api/v1/tenants", methods=["POST"])
def create_tenant():
    """
    Register a new tenant.
    Body: { "tenant_id": "healthco-prod", "name": "HealthCo", "sso": "auth0" }
    """
    body = request.get_json(silent=True) or {}
    tenant_id = body.get("tenant_id", "").strip()
    if not tenant_id:
        abort(400, description="'tenant_id' is required")
    if tenant_id in _tenants:
        abort(409, description=f"Tenant {tenant_id!r} already exists")

    tenant = {
        "tenant_id": tenant_id,
        "name": body.get("name", tenant_id),
        "sso_provider": body.get("sso", "cognito"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "roles": list(ROLE_TEMPLATES.keys()),
        "status": "active",
    }
    _tenants[tenant_id] = tenant
    logger.info("Tenant registered: %s", tenant_id)
    return jsonify(tenant), 201


@app.route("/api/v1/tenants/<tenant_id>", methods=["GET"])
def get_tenant(tenant_id: str):
    tenant = _tenants.get(tenant_id)
    if not tenant:
        abort(404, description=f"Tenant {tenant_id!r} not found")
    return jsonify(tenant)


# ---------------------------------------------------------------------------
# Routes — Audit Log
# ---------------------------------------------------------------------------

@app.route("/api/v1/audit/<tenant_id>", methods=["GET"])
def get_audit_log(tenant_id: str):
    """Return the last N audit log entries for a tenant."""
    import json
    from pathlib import Path

    log_path = Path(f"audit_logs/{tenant_id}_access.log")
    if not log_path.exists():
        return jsonify({"entries": [], "total": 0, "tenant_id": tenant_id})

    limit = min(200, int(request.args.get("limit", 50)))
    decision_filter = request.args.get("decision")

    entries = []
    try:
        lines = log_path.read_text().strip().splitlines()
        for line in reversed(lines):
            try:
                entry = json.loads(line)
                if decision_filter and entry.get("decision") != decision_filter.upper():
                    continue
                entries.append(entry)
                if len(entries) >= limit:
                    break
            except json.JSONDecodeError:
                continue
    except OSError:
        pass

    return jsonify({
        "tenant_id": tenant_id,
        "entries": entries,
        "total": len(entries),
    })


# ---------------------------------------------------------------------------
# Health & errors
# ---------------------------------------------------------------------------

@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "roles_available": len(ROLE_TEMPLATES),
        "tenants_registered": len(_tenants),
    })


@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad Request", "message": str(e.description)}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not Found", "message": str(e.description)}), 404

@app.errorhandler(409)
def conflict(e):
    return jsonify({"error": "Conflict", "message": str(e.description)}), 409

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal Server Error"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    debug = os.environ.get("FLASK_ENV") == "development"
    logger.info("Starting IAM Framework API on port %d", port)
    app.run(host="0.0.0.0", port=port, debug=debug)
