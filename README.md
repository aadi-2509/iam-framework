# IAM Cloud Security Framework

A practical RBAC/ABAC access control framework I built to simulate and audit IAM policies in a multi-tenant SaaS environment. The goal was to understand how to design IAM at scale — where you have multiple customer tenants sharing the same AWS account but needing strict isolation.

This isn't a library you'd drop into production as-is, but it's been useful for experimenting with policy design and for demoing IAM concepts.

---

## What it covers

- Role-based access control (RBAC) with predefined roles per tenant type
- Attribute-based conditions (ABAC) using resource tags and session context
- SSO integration simulation with Cognito and Auth0
- MFA enforcement for sensitive action categories
- Tenant boundary enforcement — tenant A cannot touch tenant B's resources
- Centralized audit logging to CloudTrail + Athena for forensic-quality trail
- Policy evaluation simulator — input a principal + action + resource, get allow/deny + reason

---

## Architecture overview

```
User login (SSO)
     │
     ▼
Cognito User Pool / Auth0
     │
     ▼
AssumeRole (with session tags: dept, tenant_id, env)
     │
     ▼
IAM Role + SCPs + Permission Boundaries
     │
     ├── Resource access (S3, RDS, Lambda, etc.)
     │        └── ABAC conditions on resource tags
     └── Audit trail → CloudTrail → S3 → Athena
```

---

## Tenant model

Each tenant gets:
- An isolated IAM role per user tier (admin / developer / analyst / readonly)
- Resource tags enforcing tenant boundaries (`tenant_id`, `env`)
- A permission boundary that caps max permissions regardless of inline policies
- Session tags injected at login via SSO (department, cost center, env)

```
Tenant A (FinTech)
  ├── role/tenant-a-admin
  ├── role/tenant-a-developer
  ├── role/tenant-a-analyst
  └── role/tenant-a-readonly

Tenant B (HealthCo)
  ├── role/tenant-b-admin
  ...
```

---

## Project structure

```
iam-framework/
├── src/
│   ├── auth/
│   │   ├── cognito_session.py     # Cognito token exchange + role assumption
│   │   └── auth0_session.py       # Auth0 OIDC flow + role assumption
│   ├── policies/
│   │   ├── generator.py           # Generate IAM policy JSON from role definitions
│   │   ├── evaluator.py           # Local policy evaluation engine
│   │   └── templates.py           # Role policy templates per tier
│   ├── tenants/
│   │   └── manager.py             # Tenant CRUD, role assignment
│   └── audit/
│       └── logger.py              # Structured audit log writer
├── infra/
│   ├── iam_roles.tf               # Terraform: all IAM roles + boundaries
│   ├── cognito.tf                 # User pools + identity pools
│   └── athena.tf                  # Athena table for CloudTrail logs
├── tests/
│   ├── test_evaluator.py
│   ├── test_generator.py
│   └── test_tenant_isolation.py
├── docs/
│   └── policy_design.md
├── requirements.txt
├── .env.example
└── README.md
```

---

## Quick start

```bash
git clone https://github.com/yourusername/iam-framework.git
cd iam-framework
pip install -r requirements.txt

# Generate policies for a tenant
python src/policies/generator.py --tenant fintech --role developer --output ./out/

# Simulate an access request locally
python src/policies/evaluator.py \
  --principal "tenant-a-developer" \
  --action "s3:GetObject" \
  --resource "arn:aws:s3:::tenant-a-data/reports/*" \
  --tags "tenant_id=tenant-a,env=prod"

# Run tests
pytest tests/ -v
```

---

## Policy design decisions

**Why ABAC over pure RBAC?**
Roles alone don't scale well past ~20 distinct permission sets. ABAC lets you write fewer policies by adding conditions based on tags — `tenant_id` must match on both the principal's session and the resource. This means you can have one "developer" policy used across all tenants, with the tenant boundary enforced at evaluation time.

**Permission boundaries**
Every role has a permission boundary that acts as a hard ceiling. Even if someone manages to attach a wildcard policy to a role, the boundary prevents it from taking effect. This is the defense-in-depth layer that most IAM setups skip.

**Least privilege by default**
Roles start with an explicit deny-all and actions are added individually. It's more annoying to set up but much easier to audit — you can look at any role and know exactly what it can do.

---

## Querying audit logs with Athena

After CloudTrail logs land in S3, the Athena table (created by `infra/athena.tf`) lets you query them like SQL:

```sql
-- Find all IAM changes in the last 7 days
SELECT eventtime, useridentity.username, eventname, requestparameters
FROM cloudtrail_logs
WHERE eventsource = 'iam.amazonaws.com'
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '7' day
ORDER BY eventtime DESC;

-- Find all cross-tenant access attempts
SELECT eventtime, useridentity.username, requestparameters
FROM cloudtrail_logs
WHERE requestparameters LIKE '%tenant-b%'
  AND useridentity.username LIKE '%tenant-a%';
```

---

## Running tests

```bash
pytest tests/ -v --tb=short
```

The evaluator tests cover ~40 allow/deny scenarios without needing AWS credentials.

---

## License

MIT
