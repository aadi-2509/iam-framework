# IAM Cloud Security Framework

[![CI](https://github.com/aadi-2509/iam-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/aadi-2509/iam-framework/actions)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A practical RBAC/ABAC access control framework for multi-tenant SaaS on AWS. Generates IAM policy documents, evaluates access decisions locally without AWS API calls, enforces tenant isolation through attribute-based conditions, and logs every access decision to CloudTrail and Athena.

**Built by:** Aaditya Modi — M.S. Cybersecurity, Arizona State University

---

## What it does

- Generates IAM identity policies, permission boundaries, and trust policies for 4 role tiers
- Enforces tenant isolation using ABAC — one policy works for all tenants, boundary enforced by tag matching
- Evaluates access decisions locally with a Python implementation of IAM policy evaluation logic
- Supports MFA enforcement on sensitive actions, permission boundaries, and SCP simulation
- REST API for evaluating access requests, generating policies, and managing tenants
- Structured audit logging to local file, CloudWatch Logs, and S3 for Athena querying

---

## The problem this solves

In a multi-tenant SaaS on AWS, the naive approach is one IAM role per tenant per tier:

```
tenant-a-admin, tenant-a-developer, tenant-a-analyst
tenant-b-admin, tenant-b-developer, tenant-b-analyst
tenant-c-admin, tenant-c-developer, tenant-c-analyst
```

At 50 tenants with 4 tiers each that is 200 roles. This framework uses ABAC so you need
only 4 roles total. Tenant isolation is enforced by a tag condition at evaluation time:

```json
"Condition": {
  "StringEquals": { "aws:PrincipalTag/tenant_id": "${aws:ResourceTag/tenant_id}" }
}
```

---

## Role tiers

| Role | What they can do |
|------|-----------------|
| admin | Full access within tenant boundary. MFA required for IAM and destructive actions. |
| developer | Read/write to compute and storage. No IAM management. |
| analyst | Read-only access to data stores. Can query via Athena. |
| readonly | Minimal read-only access for auditors. |

---

## Project structure

```
iam-framework/
|-- src/
|   |-- policies/
|   |   |-- evaluator.py     # IAM policy evaluation engine (allow/deny/boundary/SCP)
|   |   |-- generator.py     # Generates IAM JSON from role templates
|   |   +-- templates.py     # Role definitions and permission boundary
|   +-- audit/
|       +-- logger.py        # Audit logger (file + CloudWatch + S3/Athena)
|-- api/
|   +-- app.py               # Flask REST API
|-- tests/
|   |-- test_evaluator.py    # 40+ allow/deny scenario tests
|   +-- test_api.py          # REST API integration tests
|-- infra/
|   +-- iam_roles.tf         # Terraform: IAM roles with boundaries + Cognito
|-- docs/
|   +-- policy_design.md     # Design decisions and rationale
|-- .github/workflows/
|   +-- ci.yml               # GitHub Actions CI
|-- .env.example
|-- requirements.txt
|-- CHANGELOG.md
+-- README.md
```

---

## Prerequisites

- Python 3.10 or higher — https://python.org/downloads
- Git — https://git-scm.com
- No AWS account needed for local testing

---

## Quickstart (no AWS required)

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/iam-framework.git
cd iam-framework
```

### 2. Create and activate a virtual environment

Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

macOS / Linux:
```bash
python -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the test suite

```bash
pytest tests/ -v
```

Expected — all green, 40+ tests passing.

### 5. Generate IAM policies

Creates real IAM policy JSON files you could upload to AWS:

```bash
python src/policies/generator.py --tenant fintech-prod --role developer --output out/
```

Output:
```
Generated policies in out/
  Identity policy: fintech-prod_developer_policy.json
  Boundary:        fintech-prod_boundary.json
  Trust policy:    fintech-prod_developer_trust.json
```

Generate for all roles:
```bash
python src/policies/generator.py --tenant fintech-prod --role admin --output out/
python src/policies/generator.py --tenant fintech-prod --role analyst --output out/
python src/policies/generator.py --tenant fintech-prod --role readonly --output out/
```

You can also generate for different SSO providers:
```bash
python src/policies/generator.py --tenant healthco --role developer --sso auth0 --output out/
```

### 6. Evaluate access requests from the command line

Test whether a principal would be allowed or denied:

```bash
# Developer reading their own tenant data -- should ALLOW
python src/policies/evaluator.py \
  --principal "bob" \
  --action "s3:GetObject" \
  --resource "arn:aws:s3:::fintech-data/report.csv" \
  --tags "tenant_id=fintech-prod"
```

```
Decision:  ALLOW
Reason:    Allowed by identity policy
Source:    fintech-prod/developer
```

```bash
# Developer trying IAM actions -- should DENY
python src/policies/evaluator.py \
  --principal "bob" \
  --action "iam:CreateUser" \
  --resource "*" \
  --tags "tenant_id=fintech-prod"
```

```
Decision:  DENY
Reason:    No matching allow statement (implicit deny)
```

```bash
# Tenant A user accessing Tenant B resources -- should DENY (tenant isolation)
python src/policies/evaluator.py \
  --principal "alice" \
  --action "s3:GetObject" \
  --resource "arn:aws:s3:::healthco-data/patients.csv" \
  --tags "tenant_id=fintech-prod"
```

```
Decision:  DENY
Reason:    No matching allow statement (implicit deny)
```

### 7. Start the REST API

```bash
python api/app.py
```

API is running at http://localhost:8000. Open a new terminal for the commands below.

---

## REST API usage

### Health check
```bash
curl http://localhost:8000/api/v1/health
```

### Register a tenant
```bash
curl -X POST http://localhost:8000/api/v1/tenants \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "fintech-prod", "name": "FinTech Corp", "sso": "cognito"}'
```

### Evaluate an access request
```bash
curl -X POST http://localhost:8000/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "fintech-prod",
    "role": "developer",
    "principal": "bob@fintech.com",
    "action": "s3:GetObject",
    "resource": "arn:aws:s3:::fintech-data/q3.csv",
    "session_tags": {"tenant_id": "fintech-prod", "dept": "engineering"},
    "mfa_present": false,
    "source_ip": "10.0.0.5"
  }'
```

Returns HTTP 200 with decision ALLOW, or HTTP 403 with decision DENY and the reason.

### Generate policies via API
```bash
curl -X POST http://localhost:8000/api/v1/policies/generate \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "fintech-prod", "role": "admin", "sso": "cognito"}'
```

Returns the full identity policy, permission boundary, and trust policy JSON.

### List all available roles
```bash
curl http://localhost:8000/api/v1/policies/roles
```

### View audit log for a tenant
```bash
curl http://localhost:8000/api/v1/audit/fintech-prod
```

Returns every access decision (allow and deny) for that tenant in chronological order.

### List all tenants
```bash
curl http://localhost:8000/api/v1/tenants
```

---

## Policy evaluation order

The evaluator follows AWS IAM evaluation logic:

```
1. Explicit DENY in any policy?      --> Always DENY, stop.
2. SCP blocks it?                    --> DENY
3. Permission boundary blocks it?    --> DENY
4. Explicit ALLOW in identity policy?--> ALLOW
5. No match?                         --> DENY (implicit deny)
```

---

## Querying audit logs with Athena

After deploying with Terraform and CloudTrail logs land in S3:

```sql
-- All denied requests in the last 7 days
SELECT timestamp, principal, action, resource, reason
FROM audit_logs
WHERE tenant_id = 'fintech-prod'
  AND decision = 'DENY'
  AND from_iso8601_timestamp(timestamp) > current_timestamp - interval '7' day
ORDER BY timestamp DESC;

-- Cross-tenant access attempts
SELECT timestamp, principal, action, resource
FROM audit_logs
WHERE session_tags LIKE '%tenant-a%'
  AND resource LIKE '%tenant-b%';
```

---

## AWS deployment (optional)

Requires AWS CLI and Terraform 1.4+.

```bash
# Generate all policies for your tenant first
python src/policies/generator.py --tenant your-tenant --role admin --output out/
python src/policies/generator.py --tenant your-tenant --role developer --output out/
python src/policies/generator.py --tenant your-tenant --role analyst --output out/
python src/policies/generator.py --tenant your-tenant --role readonly --output out/

# Deploy roles
cd infra/
terraform init
terraform apply -var="tenant_id=your-tenant"
```

---

## Environment variables

| Variable | Description | Required for |
|----------|-------------|--------------|
| AWS_DEFAULT_REGION | AWS region | AWS deployment |
| CW_LOG_GROUP | CloudWatch log group for audit | Audit logging |
| S3_AUDIT_BUCKET | S3 bucket for Athena queries | Audit logging |
| AUDIT_LOG_DIR | Local audit log directory | Local logging |
| PORT | API port (default 8000) | API |
| FLASK_ENV | development enables debug | API |

---

## License

MIT
