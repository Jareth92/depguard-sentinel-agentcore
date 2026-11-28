# DepGuard Sentinel — IAM remediation evidence register

**Classification:** CONFIDENTIAL — contains security configuration details.

## Scope

This record covers one IAM statement in the managed policy `DepGuardSentinelExecutionPolicy` attached to `DepGuardSentinelExecutionRole` in `us-east-1`.

It is not a full permission audit of the role or a complete Well-Architected review.

## Historical evidence — v1

Command used:

```powershell
aws iam get-policy-version `
  --policy-arn arn:aws:iam::634393785889:policy/DepGuardSentinelExecutionPolicy `
  --version-id v1 `
  --query "PolicyVersion.Document.Statement[?Sid=='PublicContainerBearerToken']" `
  --output json `
  --profile depguard-operator `
  --region us-east-1
```

Observed statement:

```json
{
  "Sid": "PublicContainerBearerToken",
  "Effect": "Allow",
  "Action": "sts:GetServiceBearerToken",
  "Resource": "*"
}
```

There was no service-specific condition in this statement.

## Remediated evidence — v2

Command used:

```powershell
aws iam get-policy-version `
  --policy-arn arn:aws:iam::634393785889:policy/DepGuardSentinelExecutionPolicy `
  --version-id v2 `
  --query "PolicyVersion.Document.Statement[?Sid=='PublicContainerBearerToken']" `
  --output json `
  --profile depguard-operator `
  --region us-east-1
```

Observed condition:

```json
"Condition": {
  "StringEquals": {
    "sts:AWSServiceName": "ecr-public.amazonaws.com"
  }
}
```

## Active version and attachment evidence

`get-policy` returned:

- `DefaultVersion`: `v2`
- `AttachmentCount`: `1`
- `Updated`: `2026-11-27T03:26:55+00:00`

`list-attached-role-policies` returned the policy ARN under `DepGuardSentinelExecutionRole`.

## IAM Policy Simulator evidence already observed

The role-based `simulate-principal-policy` command returned:

| Service context | Decision | Missing context |
|---|---|---|
| `ecr-public.amazonaws.com` | `allowed` | `[]` |
| `codeartifact.amazonaws.com` | `implicitDeny` | `[]` |

These were results from `SimulatePrincipalPolicy` against the role's then-current attached policies, with both `sts:AWSServiceName` and `cloudwatch:namespace=bedrock-agentcore` supplied. The CloudWatch context was required because another statement in the role policy contains a `cloudwatch:namespace` condition.

## Scope and limitations

- The evidence validates the selected statement's service restriction in the context of the role simulator output.
- It does not prove that every other permission in the role is least-privileged.
- It does not prove that the workload actually invoked `sts:GetServiceBearerToken` after the update; no CloudTrail usage evidence is recorded here.
- It does not prove every AWS service is denied. The observed negative test is CodeArtifact.
- `Resource: "*"` remains in the statement. The scope reduction comes from the service condition.
- The optional live script in this pack uses `SimulateCustomPolicy` against isolated v1/v2 statement fixtures. It is a distinct experiment from the historical `SimulatePrincipalPolicy` results.
