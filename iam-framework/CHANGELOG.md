# Changelog

## [1.0.0] — 2025-10-20

### Added
- Local IAM policy evaluation engine covering explicit deny, SCP, permission boundary, and implicit deny
- Policy generator CLI — generates identity policy, boundary, and trust policy JSON from role templates
- 4 role tiers: admin, developer, analyst, readonly with ABAC conditions
- Permission boundary enforcing hard limits on all roles
- REST API — evaluate access requests, generate policies, manage tenants
- Structured audit logger — file + CloudWatch + S3/Athena output
- 40+ unit tests covering allow/deny scenarios, ABAC conditions, MFA enforcement, SCP blocking
- Terraform: IAM roles with boundaries, Cognito user pools, Athena table
- GitHub Actions CI across Python 3.10/3.11/3.12
- Policy design documentation

### Supported condition operators
- StringEquals, StringEqualsIgnoreCase, StringLike, StringNotEquals
- Bool (MFA checks)
- IpAddress

---

## [0.2.0] — 2025-09-28

### Added
- Permission boundary support in evaluator
- SCP evaluation layer
- MFA condition enforcement in admin role templates
- Audit logger with CloudWatch integration

### Changed
- EvaluationContext now includes resource_tags and mfa_present fields
- Generator outputs separate trust policy file

---

## [0.1.0] — 2025-09-10

### Added
- Initial RBAC/ABAC policy evaluation engine
- Developer and readonly role templates
- Basic audit logging to local file
- CLI for policy generation and evaluation
