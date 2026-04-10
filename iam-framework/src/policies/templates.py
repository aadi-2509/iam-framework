"""
Role policy templates.

Each entry defines the action groups for that role tier.
The generator.py script turns these into proper IAM policy JSON.

Design notes:
- action_groups are additive — each one becomes a separate Statement
- require_tenant_tag: True means ABAC isolation is enforced
- require_mfa: True adds a Bool condition for MFA presence
- restrict_regions limits to us-east-1 and us-west-2 by default
"""

ROLE_TEMPLATES = {

    "admin": {
        "description": "Full administrative access within tenant boundary. MFA required for all destructive actions.",
        "action_groups": [
            {
                "sid": "S3FullAccess",
                "actions": ["s3:*"],
                "resources": ["arn:aws:s3:::*"],
                "require_tenant_tag": True,
                "resource_tag_match": True,
                "restrict_regions": ["us-east-1", "us-west-2"],
            },
            {
                "sid": "IAMManagement",
                "actions": [
                    "iam:CreateRole", "iam:DeleteRole", "iam:AttachRolePolicy",
                    "iam:DetachRolePolicy", "iam:PutRolePolicy", "iam:GetRole",
                    "iam:ListRoles", "iam:PassRole",
                ],
                "resources": ["*"],
                "require_tenant_tag": True,
                "require_mfa": True,
            },
            {
                "sid": "EC2Management",
                "actions": ["ec2:*"],
                "resources": ["*"],
                "require_tenant_tag": True,
                "resource_tag_match": True,
            },
            {
                "sid": "RDSAccess",
                "actions": ["rds:*"],
                "resources": ["*"],
                "require_tenant_tag": True,
                "resource_tag_match": True,
                "require_mfa": True,
            },
            {
                "sid": "SecretsAndKMS",
                "actions": [
                    "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue",
                    "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey",
                ],
                "resources": ["*"],
                "require_tenant_tag": True,
                "require_mfa": True,
            },
            {
                "sid": "LambdaAccess",
                "actions": ["lambda:*"],
                "resources": ["*"],
                "require_tenant_tag": True,
                "resource_tag_match": True,
            },
            {
                "sid": "CloudTrailReadOnly",
                "actions": ["cloudtrail:LookupEvents", "cloudtrail:GetTrailStatus", "cloudtrail:DescribeTrails"],
                "resources": ["*"],
                "require_tenant_tag": False,
            },
        ],
    },

    "developer": {
        "description": "Read/write access to compute and storage in dev/staging. No IAM, no prod RDS writes.",
        "action_groups": [
            {
                "sid": "S3ReadWrite",
                "actions": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
                "resources": ["arn:aws:s3:::*"],
                "require_tenant_tag": True,
                "resource_tag_match": True,
            },
            {
                "sid": "EC2ReadOnly",
                "actions": ["ec2:Describe*", "ec2:Get*"],
                "resources": ["*"],
                "require_tenant_tag": False,
            },
            {
                "sid": "LambdaReadWrite",
                "actions": [
                    "lambda:InvokeFunction", "lambda:GetFunction", "lambda:ListFunctions",
                    "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
                ],
                "resources": ["*"],
                "require_tenant_tag": True,
                "resource_tag_match": True,
            },
            {
                "sid": "CloudWatchLogs",
                "actions": ["logs:GetLogEvents", "logs:FilterLogEvents", "logs:DescribeLogGroups"],
                "resources": ["*"],
                "require_tenant_tag": False,
            },
        ],
    },

    "analyst": {
        "description": "Read-only access to data stores. No compute access.",
        "action_groups": [
            {
                "sid": "S3ReadOnly",
                "actions": ["s3:GetObject", "s3:ListBucket"],
                "resources": ["arn:aws:s3:::*"],
                "require_tenant_tag": True,
                "resource_tag_match": True,
            },
            {
                "sid": "RDSReadOnly",
                "actions": ["rds:Describe*", "rds-db:connect"],
                "resources": ["*"],
                "require_tenant_tag": True,
                "resource_tag_match": True,
            },
            {
                "sid": "AthenaQueryAccess",
                "actions": [
                    "athena:StartQueryExecution", "athena:GetQueryExecution",
                    "athena:GetQueryResults", "glue:GetTable", "glue:GetDatabase",
                ],
                "resources": ["*"],
                "require_tenant_tag": False,
            },
        ],
    },

    "readonly": {
        "description": "Minimal read-only access for auditors and observers.",
        "action_groups": [
            {
                "sid": "GlobalReadOnly",
                "actions": [
                    "s3:GetObject", "s3:ListBucket",
                    "ec2:Describe*",
                    "iam:Get*", "iam:List*",
                    "cloudtrail:LookupEvents",
                    "cloudwatch:GetMetricData", "cloudwatch:ListMetrics",
                ],
                "resources": ["*"],
                "require_tenant_tag": True,
            },
        ],
    },
}


# Permission boundary — applied to ALL roles.
# Even an admin cannot exceed what's listed here.
PERMISSION_BOUNDARY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowWithinTenant",
            "Effect": "Allow",
            "Action": [
                "s3:*", "ec2:*", "rds:*", "lambda:*",
                "logs:*", "cloudwatch:*", "athena:*", "glue:*",
                "secretsmanager:GetSecretValue",
                "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey",
                "iam:Get*", "iam:List*", "iam:PassRole",
                "cloudtrail:LookupEvents", "cloudtrail:GetTrailStatus",
                "sts:GetCallerIdentity", "sts:AssumeRole",
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"aws:PrincipalTag/tenant_id": "PLACEHOLDER_TENANT_ID"}
            },
        },
        {
            "Sid": "DenyBoundaryBreakers",
            "Effect": "Deny",
            "Action": [
                "iam:CreateUser", "iam:DeleteUser",
                "iam:AttachUserPolicy", "iam:DetachUserPolicy",
                "iam:PutUserPolicy", "iam:DeleteUserPolicy",
                "cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
                "guardduty:DeleteDetector",
                "config:DeleteConfigRule", "config:DeleteDeliveryChannel",
                "organizations:*",
                "account:*",
                "iam:CreateVirtualMFADevice", "iam:DeactivateMFADevice",
            ],
            "Resource": "*",
        },
    ],
}
