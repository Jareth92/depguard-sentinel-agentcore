# SEC06-BP03 — Manual Management and Interactive Access Evidence

## 1. Identification

- Workload: DepGuard Sentinel
- Pillar: Security
- Question: SEC06 — Protecting compute
- Best Practice: SEC06-BP03 — Reduce manual management and interactive access
- Region: us-east-1
- Observation date: 2026-11-27
- Assessment type: Manual evidence-based assessment

## 2. Harness tool restrictions

Observed Harness configuration:

- Harness: DepGuardSentinel
- Version: 2
- Allowed tools: @analyze_manifest
- EnvironmentArtifact: null

The Harness exposes only the explicitly configured
analyze_manifest tool.

The local client in depguard/agentcore_client.py validates
tool names against an explicit allowlist and rejects unexpected
tool requests without executing them.

The inline analyzer executes in the local client process
during the tool handoff.

These controls restrict the model's available tool interface.
They do not independently restrict direct administrative
access to the AgentCore Runtime.

## 3. Developer role permissions

Role: DepGuardDeveloperRole

Two customer-managed policies were inspected:

- DepGuardAgentCoreAccess
- DepGuardDeploymentAccess

DepGuardAgentCoreAccess includes scoped AgentCore operations
for resource creation, listing, reading, tagging, invocation,
and updating the DepGuard Harness and Runtime.

DepGuardDeploymentAccess includes operations for:

- CloudFormation stack management.
- The DepGuard Lambda function.
- API Gateway REST APIs.
- DepGuard deployment artifacts in S3.
- Passing the specific DepGuard Lambda execution role.

Neither inspected policy document contains these actions:

- bedrock-agentcore:InvokeAgentRuntimeCommand
- bedrock-agentcore:InvokeAgentRuntimeCommandShell

The role has deployment and resource-management capabilities.
It must not be described as a read-only role.

No direct interactive shell permission was identified in
the two inspected identity-based policy documents.

## 4. Operator identity permissions

IAM principal:

- User: DepGuardOperator
- Groups: None
- Permissions boundary: Not set

Six directly associated policies were displayed in IAM.

The inspected policies included:

### AgentCore inventory policies

The two inline inventory policies include operations for
listing AgentCore resources and reading selected Harness,
Runtime, and execution-role configuration.

The more extensive inventory policy includes:

- ListHarnesses
- ListAgentRuntimes
- ListHarnessEndpoints
- GetHarness
- GetAgentRuntime
- Read selected execution-role policy metadata and documents

No runtime command or interactive shell actions were
present in the supplied policy documents.

### DepGuardAssumeDeployRole

Allows:

- sts:AssumeRole
- Resource: DepGuardDeployRole

### DepGuardInvokeScanApi

Allows execute-api:Invoke only for:

- API: rkizb4qbq6
- Stage: Prod
- Method: POST
- Path: /scan

### SignInLocalDevelopmentAccess

Allows OAuth2 authorization and token creation for
public OAuth2 client resources.

### IAMUserChangePassword

An AWS-managed policy was identified in the user's policy
list. Its policy document was not separately inspected
during this assessment.

No group-derived permissions were identified because
DepGuardOperator does not belong to any IAM group.

## 5. Deployment role and trust relationship

Role: DepGuardDeployRole

The inspected identity-based deployment policy was
DepGuardDeploymentAccess.

Its permissions manage the scoped DepGuard CloudFormation
stack, Lambda function, API Gateway resources, and S3
deployment artifacts.

The policy document does not contain AgentCore runtime
command or interactive shell actions.

The role trust policy contains:

- Principal: DepGuardOperator
- Action: sts:AssumeRole
- Condition: aws:MultiFactorAuthPresent = true

Therefore, the inspected trust relationship requires MFA
for DepGuardOperator to assume this deployment role.

The role provides infrastructure deployment capabilities.
This is distinct from interactive shell access to the
AgentCore Runtime.

## 6. Direct runtime command and shell access

The following AgentCore actions were checked in the
provided identity-based policy documents:

- bedrock-agentcore:InvokeAgentRuntimeCommand
- bedrock-agentcore:InvokeAgentRuntimeCommandShell

Neither action was found in the inspected policies for:

- DepGuardDeveloperRole
- DepGuardDeployRole
- DepGuardOperator's supplied inline and customer-managed
  policy documents

The Harness allowlist and IAM permissions are separate
authorization layers.

A restricted allowedTools configuration does not by itself
prove that direct runtime command or shell operations are
denied to every IAM principal.

## 7. Resource-based policy inspection limitation

Attempts to call GetResourcePolicy using:

- DepGuardOperator
- DepGuardDeveloperRole

returned AccessDeniedException because the respective
identity-based policies did not allow:

bedrock-agentcore:GetResourcePolicy

As a result, the following resource-based policies have
not been inspected:

- AgentCore Runtime resource policy.
- DEFAULT Runtime endpoint resource policy.

AWS evaluates identity-based and resource-based policies
for supported AgentCore runtime operations.

Consequently, this assessment cannot establish the
effective authorization result for direct runtime command
or interactive shell access.

AccessDenied during policy inspection is not evidence
that a resource-based policy is absent.

## 8. Assessment

Provisional status: PARTIALLY IMPLEMENTED.

Positive evidence:

- The Harness exposes only analyze_manifest.
- The local client enforces an explicit tool allowlist.
- Unexpected tool requests fail closed.
- No direct runtime command or shell action was identified
  in the inspected identity-based policy documents.
- DepGuardOperator has no group-derived permissions.
- DepGuardOperator has no permissions boundary.
- DepGuardDeployRole trust requires MFA for DepGuardOperator.
- Deployment permissions are separated into a dedicated role
  and scoped to DepGuard resources.

Gaps and limitations:

- Runtime resource-based policy was not inspected.
- DEFAULT endpoint resource-based policy was not inspected.
- Effective authorization for direct command and shell
  operations has not been conclusively established.
- No complete audit of every possible IAM principal in the
  account was performed.
- No emergency-only interactive access procedure was
  demonstrated.
- No complete evidence of logged and reviewed manual
  maintenance sessions was collected.
- Deployment automation and operational runbooks require
  further assessment.

## 9. Recommended follow-up

- Inspect Runtime and DEFAULT endpoint resource-based policies
  when authorized read access is available.
- Keep direct runtime command and shell permissions restricted
  to explicitly authorized operational principals.
- Review deployment-role permissions periodically.
- Document emergency access procedures.
- Log and review any authorized manual runtime access.
- Prefer tested scripts and automated deployment procedures
  for routine maintenance.

## 10. Evidence integrity

Evidence sources:

- AWS AgentCore GetHarness output.
- AWS IAM policy documents supplied from the console.
- DepGuardOperator group and permissions-boundary inspection.
- DepGuardDeployRole trust relationship.
- Local depguard/agentcore_client.py source inspection.
- AWS CLI GetResourcePolicy AccessDenied responses.

This assessment is provisional and does not claim that
all direct runtime shell access has been effectively denied.

No IAM permissions or AWS resources were modified during
this evidence collection.