"""
Local IAM policy evaluation engine.

This is a simplified reimplementation of AWS IAM policy evaluation logic.
It's not a perfect replica of how AWS evaluates policies — there are edge cases
around resource-based policies, SCPs, and VPC endpoint policies that this doesn't
cover. But for testing RBAC/ABAC rules locally (no AWS calls needed), it works well.

Evaluation order follows AWS docs:
  1. Explicit deny in any policy → DENY
  2. SCP deny or no SCP allow → DENY
  3. Permission boundary deny or no boundary allow → DENY
  4. Session policy deny or no session allow → DENY
  5. Identity policy allow → ALLOW
  6. Otherwise → implicit DENY

References:
  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
"""

import fnmatch
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass
class EvaluationContext:
    principal: str
    action: str
    resource: str
    session_tags: dict[str, str] = field(default_factory=dict)
    resource_tags: dict[str, str] = field(default_factory=dict)
    mfa_present: bool = False
    source_ip: Optional[str] = None


@dataclass
class EvaluationResult:
    decision: Decision
    reason: str
    matched_statement: Optional[dict] = None
    policy_source: Optional[str] = None


class PolicyEvaluator:
    """
    Evaluates a set of IAM policy documents against a given request context.

    Usage:
        evaluator = PolicyEvaluator()
        evaluator.load_identity_policy(policy_json, source="developer-role")
        evaluator.load_permission_boundary(boundary_json)
        result = evaluator.evaluate(context)
    """

    def __init__(self):
        self._identity_policies: list[tuple[str, list[dict]]] = []
        self._permission_boundary: Optional[list[dict]] = None
        self._scps: list[list[dict]] = []

    def load_identity_policy(self, policy: dict | str, source: str = "identity") -> None:
        if isinstance(policy, str):
            policy = json.loads(policy)
        statements = self._extract_statements(policy)
        self._identity_policies.append((source, statements))

    def load_permission_boundary(self, policy: dict | str) -> None:
        if isinstance(policy, str):
            policy = json.loads(policy)
        self._permission_boundary = self._extract_statements(policy)

    def load_scp(self, policy: dict | str) -> None:
        if isinstance(policy, str):
            policy = json.loads(policy)
        self._scps.append(self._extract_statements(policy))

    def evaluate(self, ctx: EvaluationContext) -> EvaluationResult:
        # Step 1: explicit deny in any identity policy
        for source, stmts in self._identity_policies:
            for stmt in stmts:
                if stmt.get("Effect") != "Deny":
                    continue
                if self._stmt_matches(stmt, ctx):
                    return EvaluationResult(
                        decision=Decision.DENY,
                        reason="Explicit deny in identity policy",
                        matched_statement=stmt,
                        policy_source=source,
                    )

        # Step 2: SCP check
        for scp_stmts in self._scps:
            has_allow = any(
                s.get("Effect") == "Allow" and self._stmt_matches(s, ctx)
                for s in scp_stmts
            )
            has_deny = any(
                s.get("Effect") == "Deny" and self._stmt_matches(s, ctx)
                for s in scp_stmts
            )
            if has_deny or not has_allow:
                return EvaluationResult(
                    decision=Decision.DENY,
                    reason="Denied or not allowed by SCP",
                    policy_source="scp",
                )

        # Step 3: permission boundary
        if self._permission_boundary is not None:
            boundary_allows = any(
                s.get("Effect") == "Allow" and self._stmt_matches(s, ctx)
                for s in self._permission_boundary
            )
            if not boundary_allows:
                return EvaluationResult(
                    decision=Decision.DENY,
                    reason="Action not permitted by permission boundary",
                    policy_source="permission_boundary",
                )

        # Step 4: look for an allow in identity policies
        for source, stmts in self._identity_policies:
            for stmt in stmts:
                if stmt.get("Effect") != "Allow":
                    continue
                if self._stmt_matches(stmt, ctx):
                    return EvaluationResult(
                        decision=Decision.ALLOW,
                        reason="Allowed by identity policy",
                        matched_statement=stmt,
                        policy_source=source,
                    )

        # Step 5: implicit deny
        return EvaluationResult(
            decision=Decision.DENY,
            reason="No matching allow statement (implicit deny)",
        )

    def _stmt_matches(self, stmt: dict, ctx: EvaluationContext) -> bool:
        if not self._action_matches(stmt.get("Action", []), ctx.action):
            return False
        if not self._resource_matches(stmt.get("Resource", []), ctx.resource):
            return False
        if not self._conditions_match(stmt.get("Condition", {}), ctx):
            return False
        return True

    def _action_matches(self, actions, requested: str) -> bool:
        if isinstance(actions, str):
            actions = [actions]
        requested_lower = requested.lower()
        for a in actions:
            pattern = a.lower().replace("*", ".*").replace("?", ".")
            if re.fullmatch(pattern, requested_lower):
                return True
        return False

    def _resource_matches(self, resources, requested: str) -> bool:
        if isinstance(resources, str):
            resources = [resources]
        for r in resources:
            if r == "*" or fnmatch.fnmatch(requested, r):
                return True
        return False

    def _conditions_match(self, conditions: dict, ctx: EvaluationContext) -> bool:
        for operator, key_values in conditions.items():
            for key, expected in key_values.items():
                actual = self._resolve_condition_key(key, ctx)
                if actual is None:
                    return False
                if not self._eval_operator(operator, actual, expected):
                    return False
        return True

    def _resolve_condition_key(self, key: str, ctx: EvaluationContext) -> Optional[str]:
        key_lower = key.lower()
        # Session/principal tags
        if key_lower.startswith("aws:principaltag/"):
            tag_key = key.split("/", 1)[1]
            return ctx.session_tags.get(tag_key)
        if key_lower.startswith("aws:requestedtag/"):
            tag_key = key.split("/", 1)[1]
            return ctx.session_tags.get(tag_key)
        if key_lower.startswith("aws:resourcetag/"):
            tag_key = key.split("/", 1)[1]
            return ctx.resource_tags.get(tag_key)
        if key_lower == "aws:multifactorauthpresent":
            return str(ctx.mfa_present).lower()
        if key_lower == "aws:sourceip":
            return ctx.source_ip
        return None

    def _eval_operator(self, operator: str, actual: str, expected) -> bool:
        op = operator.lower()
        if isinstance(expected, str):
            expected = [expected]

        if op == "stringequals":
            return actual in expected
        if op == "stringequalsignorecase":
            return actual.lower() in [e.lower() for e in expected]
        if op == "stringlike":
            return any(fnmatch.fnmatch(actual, e) for e in expected)
        if op == "stringnotequals":
            return actual not in expected
        if op == "bool":
            return any(actual == str(e).lower() for e in expected)
        if op == "ipaddress":
            # Simplified — just checks equality for now
            return actual in expected
        return False

    @staticmethod
    def _extract_statements(policy: dict) -> list[dict]:
        stmts = policy.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        return stmts


# ---------------------------------------------------------------------------
# CLI wrapper
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IAM policy evaluator")
    parser.add_argument("--principal", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--resource", required=True)
    parser.add_argument("--tags", default="", help="key=val,key=val session tags")
    parser.add_argument("--policy-file", help="Path to identity policy JSON")
    parser.add_argument("--boundary-file", help="Path to boundary JSON")
    args = parser.parse_args()

    tags = {}
    if args.tags:
        for pair in args.tags.split(","):
            k, _, v = pair.partition("=")
            tags[k.strip()] = v.strip()

    ctx = EvaluationContext(
        principal=args.principal,
        action=args.action,
        resource=args.resource,
        session_tags=tags,
    )

    evaluator = PolicyEvaluator()

    if args.policy_file:
        with open(args.policy_file) as f:
            evaluator.load_identity_policy(f.read(), source=args.policy_file)
    else:
        # Default: minimal scoped policy for demo
        evaluator.load_identity_policy({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:PrincipalTag/tenant_id": tags.get("tenant_id", "")}
                },
            }]
        }, source="demo-policy")

    if args.boundary_file:
        with open(args.boundary_file) as f:
            evaluator.load_permission_boundary(f.read())

    result = evaluator.evaluate(ctx)
    print(f"\nDecision:  {result.decision.value}")
    print(f"Reason:    {result.reason}")
    print(f"Source:    {result.policy_source or 'n/a'}")
    if result.matched_statement:
        print(f"Statement: {json.dumps(result.matched_statement, indent=2)}")
