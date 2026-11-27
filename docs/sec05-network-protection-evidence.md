# SEC05 — Protecting Networks Evidence

## 1. Identification

- Workload: DepGuard Sentinel
- Pillar: Security
- Question: SEC05 — Protecting networks
- Region: us-east-1
- Account: 634393785889
- Observation date: 2026-11-27
- Source: Local AWS Well-Architected Security TOC and workload inspection
- Assessment type: Manual evidence-based assessment

## 2. Scope and methodology

This document consolidates the evidence collected for the four SEC05
best practices in the local Well-Architected review corpus.

The assessment distinguishes:
- AWS-managed infrastructure and controls.
- Customer-managed AWS resources and configuration.
- Local client and Red Team adapter behavior.
- Controls implemented in application code and CI.

The findings are provisional. An absence of evidence in the inspected
scope is not proof that a control does not exist elsewhere.

No network infrastructure was created or modified during this assessment.

## 3. Workload network architecture

The AgentCore Runtime configuration was queried using
`get-agent-runtime`.

Observed configuration:

- Runtime: harness_DepGuardSentinel
- Runtime ID: harness_DepGuardSentinel-xg5UWVFic3
- Status: READY
- Version: 2
- Network mode: PUBLIC

The runtime is not configured with a customer-managed VPC network
configuration in the inspected configuration.

The local invocation client creates a Boto3 session and a
`bedrock-agentcore` data-plane client in:

- `scripts/invoke_harness.py`
- `scripts/redteam_adapter.py`

The local client invokes the Harness through
`invoke_with_inline_tool()` in `depguard/agentcore_client.py`.

The inline `analyze_manifest` tool is imported and executed by the
local Python process when the Harness requests a tool handoff.
It is not executed by that local function inside the AgentCore Runtime.

This distinction is important when attributing network traffic to
the local client versus the managed runtime.

## 4. SEC05-BP01 — Create network layers

### Evidence collected

- AgentCore Runtime reports `networkMode: PUBLIC`.
- No customer-managed VPC network configuration was observed for
  this runtime.
- The workload has a local invocation client and a local inline
  manifest analysis function.
- The reviewed architecture does not show customer-managed private
  network tiers for these components.

### Assessment

Provisional status: PARTIALLY IMPLEMENTED.

The workload uses the networking model provided by the managed
AgentCore service, but the inspected runtime is configured in
PUBLIC mode rather than a customer-managed VPC network topology.

The evidence does not establish a customer-managed architecture
with separate public, private, and inspection network layers.

This finding does not imply that AWS-managed infrastructure lacks
network isolation or service-level protections.

### Limitations

- This inspection did not assess every network control internal
  to the managed AgentCore service.
- No migration to VPC networking was performed.
- No cost or operational justification for a VPC migration has
  been established.

## 5. SEC05-BP02 — Control traffic flow within your network layers

### Evidence collected

#### AWS invocation and authorization

- The local client creates a Boto3 `bedrock-agentcore` client.
- The previously inspected caller policy `DepGuardHarnessInvoke`
  limits invocation permissions to the specified Harness ARN.
- The Harness exposes the `analyze_manifest` tool.
- `depguard/agentcore_client.py` uses an explicit tool allowlist
  and rejects unexpected tool names.

These are identity and tool-authorization controls. They do not,
by themselves, demonstrate network-layer traffic filtering.

#### Local Red Team adapter

File: `scripts/redteam_adapter.py`

- The HTTP server binds to `127.0.0.1`.
- Default port: 8787.
- The adapter does not bind to `0.0.0.0`.
- `POST /redteam/test` invokes `_authorized()`.
- When a token is configured, the adapter expects a Bearer
  authorization header and uses `hmac.compare_digest`.
- When no token is configured, `_authorized()` permits requests.
- `GET /health` does not invoke `_authorized()`.

The environment inspection showed `DEPGUARD_REDTEAM_TOKEN` as
UNSET in the inspected PowerShell session. This observation does
not prove the environment of a previously launched adapter process.

#### Runtime resource policy

Attempts to call `GetResourcePolicy` using both
`DepGuardOperator` and `DepGuardDeveloperRole` returned
`AccessDeniedException`.

The identities lack the required identity-based permission
`bedrock-agentcore:GetResourcePolicy`.

Therefore, the runtime resource policy has NOT been inspected.
AccessDenied is not evidence that no resource policy exists.

### Assessment

Provisional status: PARTIALLY IMPLEMENTED.

The local invocation path and Red Team adapter have identifiable
authorization and interface restrictions. However, the evidence
does not establish comprehensive ingress and egress traffic
controls for the managed runtime.

### Limitations

- Runtime resource policy remains unverified.
- Runtime egress restrictions have not been demonstrated.
- Local adapter controls must not be presented as runtime network
  controls.
- The local token observation is limited to the inspected shell
  session.

## 6. SEC05-BP03 — Implement inspection-based protection

### Evidence collected

The AWS Network Firewall console was inspected in us-east-1.

Observed result:

- Network Firewalls: 0
- Console message: No network firewalls.

No customer-managed AWS Network Firewall was visible in the
inspected account and region at the observation time.

### Assessment

Provisional status: NOT DEMONSTRATED.

The assessment did not identify a customer-managed network
inspection architecture associated with DepGuard.

Because the runtime uses PUBLIC networking, the absence of a
customer-managed Network Firewall does not establish that a
firewall is missing from a VPC through which this runtime's
traffic necessarily passes. No such path was demonstrated.

### Limitations

The inspection did not establish the presence or absence of all
possible mechanisms, including:

- VPC Traffic Mirroring.
- VPC Flow Logs.
- IDS/IPS products.
- Other customer-managed traffic inspection services.
- AWS-managed internal protections for AgentCore.

No firewall or inspection service was created during this review.

## 7. SEC05-BP04 — Automate network protection

### Evidence collected

A repository search examined common infrastructure-as-code
indicators, including Terraform files, CloudFormation templates,
CDK configuration, and infrastructure-related directories.

No matching files or directories were found by the search patterns.

The repository contains:

`.github/workflows/ci.yml`

The workflow:

- Runs on pushes and pull requests targeting `main`.
- Supports manual execution through `workflow_dispatch`.
- Uses `permissions: contents: read`.
- Uses `actions/checkout@v7` with `persist-credentials: false`.
- Sets up Python 3.13.
- Installs `requirements.txt`.
- Runs `compileall`.
- Runs the Python unittest suite.

The workflow does not contain steps to:

- Deploy network infrastructure.
- Validate VPC, subnet, routing, or firewall rules.
- Scan network infrastructure templates.
- Detect network configuration drift.
- Automatically enforce network protection policies.

### Assessment

Provisional status: NOT DEMONSTRATED.

DepGuard has automated application compilation and unit testing
through GitHub Actions, but the inspected workflow does not
automate network protection.

The existence of CI is not equivalent to automated network
security enforcement.

### Limitations

The repository search used specific filename and directory
patterns. It is not proof that no infrastructure definition
exists in every possible format or external deployment system.

## 8. Consolidated assessment

| Best Practice | Provisional assessment |
|---|---|
| SEC05-BP01 — Create network layers | PARTIALLY IMPLEMENTED |
| SEC05-BP02 — Control traffic flow within your network layers | PARTIALLY IMPLEMENTED |
| SEC05-BP03 — Implement inspection-based protection | NOT DEMONSTRATED |
| SEC05-BP04 — Automate network protection | NOT DEMONSTRATED |

These are evidence-based working assessments, not official AWS
Well-Architected scores or certifications.

## 9. Main findings

1. The AgentCore Runtime is configured with PUBLIC networking.
2. The local client and inline tool execution must be distinguished
   from the managed runtime when assessing network traffic.
3. Local invocation and tool authorization controls exist, but they
   do not demonstrate comprehensive runtime traffic filtering.
4. The runtime resource policy remains unverified due to IAM
   permission limitations.
5. No AWS Network Firewall was visible in the inspected region.
6. The repository has a CI workflow, but no network protection
   deployment or validation pipeline was identified.

## 10. Recommended follow-up

- Evaluate whether the PUBLIC networking model satisfies the
  workload's actual requirements.
- Review AgentCore-supported network controls and their ownership
  boundaries.
- Inspect runtime resource policy when authorized read access
  becomes available.
- Determine whether additional ingress and egress restrictions
  are required.
- Consider infrastructure-as-code and network policy validation
  only if a customer-managed network architecture is justified.
- Avoid deploying paid network services without a demonstrated
  requirement and cost assessment.

## 11. Evidence integrity

This document records observations from the AWS console,
AWS CLI output, repository source inspection, and workflow
inspection.

It does not claim that the complete AWS-managed AgentCore
networking implementation was independently audited.

No AWS resource was created, modified, or deleted as part
of this evidence collection.
## 12. Clarification of PUBLIC network mode

AWS documentation describes PUBLIC network mode as the default
configuration in which the AgentCore Runtime endpoint is accessible
over the public internet.

In this mode, network traffic to and from the hosted agent uses
public IP addresses. Therefore, PUBLIC is not merely the absence
of a customer-managed VPC topology; it also represents an
internet-facing network configuration.

Public accessibility does not imply anonymous invocation.
AgentCore supports authentication mechanisms such as IAM SigV4
and OAuth.

The workload's invocation path uses IAM SigV4 authentication.
This authentication control should be distinguished from
network-level isolation and traffic inspection.

AWS Security Hub control BedrockAgentCore.1 has High severity
and checks whether the runtime uses VPC network mode. A runtime
configured with PUBLIC mode fails this control when the
control is applicable.

This is the definition of the Security Hub control, not evidence
that an actual Security Hub finding exists in this account.

References:
- https://aws.amazon.com/blogs/networking-and-content-delivery/network-connectivity-patterns-for-agents-deployed-on-amazon-bedrock-agentcore-runtime/
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html
- https://docs.aws.amazon.com/securityhub/latest/userguide/bedrockagentcore-controls.html
