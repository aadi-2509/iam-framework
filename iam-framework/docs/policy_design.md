# Policy Design Notes

Some decisions I made while building this that weren't obvious at the time.

---

## Why RBAC + ABAC and not just RBAC?

Pure RBAC hits a wall once you need more than ~20 distinct permission sets.
In a multi-tenant SaaS you'd end up with roles like:

```
tenant-a-developer
tenant-b-developer
tenant-c-developer
...
```

Which is fine at 3 tenants, a nightmare at 50. ABAC lets you write one
`developer` policy and enforce the tenant boundary via a condition:

```json
"Condition": {
  "StringEquals": {
    "aws:PrincipalTag/tenant_id": "${aws:ResourceTag/tenant_id}"
  }
}
```

The tag value is injected at login time via the SSO session, so the same
role definition works for every tenant. The boundary enforcement happens
at IAM evaluation time, not in application code.

---

## Permission boundaries vs SCPs

Both cap what a role can do, but they operate at different levels:

- **SCPs** (Service Control Policies) are org-level. They apply to every
  principal in the account, including the root user. But they only work
  if you're using AWS Organizations.

- **Permission boundaries** are per-role. They're more granular and work
  in single-account setups. The downside is you have to explicitly attach
  them to every role — it's easy to forget.

In this framework I use boundaries rather than SCPs because the lab
runs in a single account. If you're deploying this to a multi-account
org, swap to SCPs for the hard restrictions and use boundaries for
the per-tenant limits.

---

## The deny-high-risk-always statement

Every generated policy includes this deny block:

```json
{
  "Sid": "DenyHighRiskAlways",
  "Effect": "Deny",
  "Action": [
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
    "guardduty:DeleteDetector",
    ...
  ],
  "Condition": {
    "StringNotEquals": {"aws:PrincipalTag/role": "admin"}
  }
}
```

The condition means admins *can* do these things (with MFA, since the
admin action group requires it), but everyone else gets an explicit deny
that overrides any other allow. Explicit denies win in IAM evaluation —
there's no way for a developer role to accidentally get these permissions
even if a wildcard policy is attached somewhere.

---

## MFA requirement implementation

Sensitive action groups in `templates.py` have `require_mfa: True`.
This generates a `Bool` condition:

```json
"Condition": {
  "Bool": {"aws:MultiFactorAuthPresent": "true"}
}
```

The catch: this condition checks the *session*, not whether the user
has MFA *enrolled*. A user without MFA enrolled can still satisfy
`aws:MultiFactorAuthPresent = false` and get denied. But if they
somehow authenticate without MFA and the condition requires it,
they'll get denied at the API call — which is the behavior we want.

For stronger enforcement, combine with a `DenyWithoutMFA` statement
that denies all actions when MFA is absent. I've left that out of
the templates to keep them readable, but it's a good addition.

---

## Least privilege process

When adding permissions for a new feature, I follow this order:

1. Start with a deny-all and run the feature — watch CloudTrail for
   `AccessDenied` errors to find what's needed.
2. Add only those specific actions, not the service wildcard.
3. Scope the resource ARN as tightly as possible.
4. Check if the action needs to be in the permission boundary too.
5. Write a test in `tests/test_evaluator.py` that asserts the new
   action is allowed AND that adjacent actions (like Delete when you
   only need Get) are still denied.

It's slower than just using `s3:*` but the audit trail is much cleaner.
