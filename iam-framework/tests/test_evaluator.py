"""
Tests for the IAM policy evaluator.

Run with: pytest tests/test_evaluator.py -v

All tests are local — no AWS credentials needed.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "policies"))

import pytest
from evaluator import PolicyEvaluator, EvaluationContext, Decision


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def ctx(action="s3:GetObject", resource="arn:aws:s3:::bucket/key",
        tags=None, mfa=False, ip=None):
    return EvaluationContext(
        principal="test-user",
        action=action,
        resource=resource,
        session_tags=tags or {},
        mfa_present=mfa,
        source_ip=ip,
    )


def evaluator_with(policy: dict, boundary: dict = None) -> PolicyEvaluator:
    ev = PolicyEvaluator()
    ev.load_identity_policy(policy, source="test-policy")
    if boundary:
        ev.load_permission_boundary(boundary)
    return ev


# ---------------------------------------------------------------------------
# Basic allow / deny
# ---------------------------------------------------------------------------

class TestBasicDecisions:
    def test_explicit_allow(self):
        ev = evaluator_with({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        })
        result = ev.evaluate(ctx())
        assert result.decision == Decision.ALLOW

    def test_implicit_deny_when_no_matching_statement(self):
        ev = evaluator_with({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}],
        })
        result = ev.evaluate(ctx())
        assert result.decision == Decision.DENY
        assert "implicit" in result.reason.lower()

    def test_explicit_deny_overrides_allow(self):
        ev = evaluator_with({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                {"Effect": "Deny",  "Action": "s3:GetObject", "Resource": "*"},
            ],
        })
        result = ev.evaluate(ctx())
        assert result.decision == Decision.DENY
        assert "explicit deny" in result.reason.lower()

    def test_wildcard_action_matches(self):
        ev = evaluator_with({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        })
        result = ev.evaluate(ctx(action="s3:DeleteObject"))
        assert result.decision == Decision.ALLOW

    def test_action_prefix_wildcard(self):
        ev = evaluator_with({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}],
        })
        assert ev.evaluate(ctx(action="s3:GetObject")).decision == Decision.ALLOW
        assert ev.evaluate(ctx(action="s3:PutObject")).decision == Decision.DENY


# ---------------------------------------------------------------------------
# ABAC conditions
# ---------------------------------------------------------------------------

class TestABACConditions:
    POLICY = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {
                "StringEquals": {"aws:PrincipalTag/tenant_id": "tenant-a"}
            },
        }],
    }

    def test_allow_when_tag_matches(self):
        ev = evaluator_with(self.POLICY)
        result = ev.evaluate(ctx(tags={"tenant_id": "tenant-a"}))
        assert result.decision == Decision.ALLOW

    def test_deny_when_tag_missing(self):
        ev = evaluator_with(self.POLICY)
        result = ev.evaluate(ctx(tags={}))
        assert result.decision == Decision.DENY

    def test_deny_when_tag_wrong_value(self):
        ev = evaluator_with(self.POLICY)
        result = ev.evaluate(ctx(tags={"tenant_id": "tenant-b"}))
        assert result.decision == Decision.DENY

    def test_cross_tenant_access_denied(self):
        """Tenant B user cannot access tenant A resources"""
        ev = evaluator_with(self.POLICY)
        result = ev.evaluate(ctx(tags={"tenant_id": "tenant-b"}))
        assert result.decision == Decision.DENY


# ---------------------------------------------------------------------------
# MFA conditions
# ---------------------------------------------------------------------------

class TestMFAConditions:
    POLICY = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:CreateRole",
            "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        }],
    }

    def test_allow_with_mfa(self):
        ev = evaluator_with(self.POLICY)
        assert ev.evaluate(ctx(action="iam:CreateRole", mfa=True)).decision == Decision.ALLOW

    def test_deny_without_mfa(self):
        ev = evaluator_with(self.POLICY)
        assert ev.evaluate(ctx(action="iam:CreateRole", mfa=False)).decision == Decision.DENY


# ---------------------------------------------------------------------------
# Permission boundary
# ---------------------------------------------------------------------------

class TestPermissionBoundary:
    BASE_POLICY = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }

    def test_allow_when_boundary_permits(self):
        boundary = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }
        ev = evaluator_with(self.BASE_POLICY, boundary=boundary)
        assert ev.evaluate(ctx()).decision == Decision.ALLOW

    def test_deny_when_boundary_blocks(self):
        boundary = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}],
        }
        ev = evaluator_with(self.BASE_POLICY, boundary=boundary)
        result = ev.evaluate(ctx())  # s3:GetObject — not in boundary
        assert result.decision == Decision.DENY
        assert "boundary" in result.reason.lower()

    def test_boundary_caps_admin_policy(self):
        """Even a wildcard admin policy can't exceed the boundary."""
        boundary = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        }
        ev = evaluator_with(self.BASE_POLICY, boundary=boundary)
        # IAM actions — not in boundary
        assert ev.evaluate(ctx(action="iam:DeleteUser")).decision == Decision.DENY
        # S3 — in boundary
        assert ev.evaluate(ctx(action="s3:PutObject")).decision == Decision.ALLOW


# ---------------------------------------------------------------------------
# SCP
# ---------------------------------------------------------------------------

class TestSCP:
    def test_deny_when_scp_blocks(self):
        ev = PolicyEvaluator()
        ev.load_identity_policy({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        })
        ev.load_scp({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "ec2:*",  # Only EC2 allowed by SCP
                "Resource": "*",
            }],
        })
        result = ev.evaluate(ctx())
        assert result.decision == Decision.DENY
        assert "scp" in result.reason.lower()
