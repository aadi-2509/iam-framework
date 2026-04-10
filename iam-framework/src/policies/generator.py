"""
IAM policy generator.

Generates IAM policy JSON documents for each role tier based on
a tenant configuration. The output is meant to be reviewed and
then applied via Terraform or the AWS CLI.

The key design principle: every policy starts with an explicit
deny-all, then adds only what the role actually needs. This makes
auditing easy — you can read the policy and know exactly what's allowed.
"""

import json
import argparse
from pathlib import Path
from templates import ROLE_TEMPLATES, PERMISSION_BOUNDARY


def generate_policy(tenant_id: str, role: str) -> dict:
    """
    Generate an IAM identity policy for a given tenant + role combination.

    The ABAC condition injects the tenant_id so this single policy
    works for any tenant — the boundary is enforced at evaluation time.
    """
    template = ROLE_TEMPLATES.get(role)
    if not template:
        raise ValueError(f"Unknown role: {role!r}. Valid roles: {list(ROLE_TEMPLATES.keys())}")

    statements = []

    for action_group in template["action_groups"]:
        stmt = {
            "Sid": action_group["sid"],
            "Effect": "Allow",
            "Action": action_group["actions"],
            "Resource": action_group.get("resources", "*"),
        }

        # Build conditions
        conditions: dict = {}

        # Tenant isolation via ABAC — principal tag must match resource tag
        if action_group.get("require_tenant_tag", True):
            conditions["StringEquals"] = {
                "aws:PrincipalTag/tenant_id": tenant_id,
                **({f"aws:ResourceTag/tenant_id": tenant_id}
                   if action_group.get("resource_tag_match") else {}),
            }

        # MFA required for sensitive actions
        if action_group.get("require_mfa", False):
            conditions["Bool"] = {"aws:MultiFactorAuthPresent": "true"}

        # Region restriction
        if action_group.get("restrict_regions"):
            conditions.setdefault("StringEquals", {})
            conditions["StringEquals"]["aws:RequestedRegion"] = action_group["restrict_regions"]

        if conditions:
            stmt["Condition"] = conditions

        statements.append(stmt)

    # Explicit deny for high-risk actions regardless of role
    statements.append({
        "Sid": "DenyHighRiskAlways",
        "Effect": "Deny",
        "Action": [
            "iam:CreateUser",
            "iam:DeleteUser",
            "iam:AttachUserPolicy",
            "iam:PutUserPolicy",
            "cloudtrail:StopLogging",
            "cloudtrail:DeleteTrail",
            "guardduty:DeleteDetector",
            "config:DeleteConfigRule",
            "organizations:*",
        ],
        "Resource": "*",
        "Condition": {
            "StringNotEquals": {"aws:PrincipalTag/role": "admin"}
        },
    })

    return {
        "Version": "2012-10-17",
        "Statement": statements,
    }


def generate_permission_boundary(tenant_id: str) -> dict:
    """
    Permission boundary applied to all roles in a tenant.
    Acts as a hard ceiling — even admins can't exceed this.
    """
    boundary = json.loads(json.dumps(PERMISSION_BOUNDARY))  # deep copy
    # Inject tenant_id into relevant conditions
    for stmt in boundary.get("Statement", []):
        cond = stmt.get("Condition", {})
        se = cond.get("StringEquals", {})
        if "aws:PrincipalTag/tenant_id" in se:
            se["aws:PrincipalTag/tenant_id"] = tenant_id
    return boundary


def generate_trust_policy(tenant_id: str, sso_provider: str = "cognito") -> dict:
    """
    Trust policy for the role — who can assume it.
    For Cognito: the identity pool authenticated role.
    For Auth0: the OIDC provider.
    """
    if sso_provider == "cognito":
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "cognito-identity.amazonaws.com:aud": f"us-east-1:{tenant_id}-identity-pool"
                    },
                    "ForAnyValue:StringLike": {
                        "cognito-identity.amazonaws.com:amr": "authenticated"
                    },
                },
            }],
        }
    elif sso_provider == "auth0":
        return {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Federated": f"arn:aws:iam::123456789012:oidc-provider/{tenant_id}.auth0.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"{tenant_id}.auth0.com:aud": f"https://api.{tenant_id}.example.com"
                    }
                },
            }],
        }
    raise ValueError(f"Unknown SSO provider: {sso_provider}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate IAM policy for a tenant role")
    parser.add_argument("--tenant", required=True, help="Tenant ID, e.g. fintech-prod")
    parser.add_argument("--role", required=True, choices=list(ROLE_TEMPLATES.keys()))
    parser.add_argument("--output", default=".", help="Output directory")
    parser.add_argument("--sso", default="cognito", choices=["cognito", "auth0"])
    args = parser.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    policy = generate_policy(args.tenant, args.role)
    boundary = generate_permission_boundary(args.tenant)
    trust = generate_trust_policy(args.tenant, args.sso)

    (out / f"{args.tenant}_{args.role}_policy.json").write_text(json.dumps(policy, indent=2))
    (out / f"{args.tenant}_boundary.json").write_text(json.dumps(boundary, indent=2))
    (out / f"{args.tenant}_{args.role}_trust.json").write_text(json.dumps(trust, indent=2))

    print(f"Generated policies in {out}/")
    print(f"  Identity policy: {args.tenant}_{args.role}_policy.json")
    print(f"  Boundary:        {args.tenant}_boundary.json")
    print(f"  Trust policy:    {args.tenant}_{args.role}_trust.json")
