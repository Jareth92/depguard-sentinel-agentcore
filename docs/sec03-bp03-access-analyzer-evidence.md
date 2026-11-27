# SEC03-BP03 — External Access Analysis Evidence

## 1. Identification

- Workload: DepGuard Sentinel
- Pillar: Security
- Question: SEC03 — Permissions management
- Best Practice: SEC03-BP03 — Analyze public and cross-account access
- Service: AWS IAM Access Analyzer
- Region: us-east-1
- Observation date: 2026-11-27

## 2. Initial condition

The IAM Access Analyzer configuration page showed zero analyzers
for the current AWS account in us-east-1.

The absence of an analyzer meant that external resource access
findings were not being collected through this capability in
the inspected region.

## 3. Implemented configuration

An external-access analyzer was created with:

- Name: depguard-external-access-us-east-1
- Type: External access
- Zone of trust: Current account
- Account: 634393785889
- Region: us-east-1
- State: ACTIVE

No internal-access or unused-access analyzer was enabled.

## 4. Observed results

The AWS console reported:

- Last analysis: approximately 12 hours before observation.
- Active findings: 0.
- Resource findings table: No results to display.

Interpretation:

At the time of observation, the analyzer reported no active
external-access findings for the supported resources it evaluates
within the configured regional scope.

## 5. Limitations

This result does not establish that the entire AWS account or
workload is free of public or cross-account exposure.

Specifically:

- The analyzer is configured for us-east-1 only.
- Analysis is limited to supported resource types and policy forms.
- The result does not constitute a complete IAM identity-policy audit.
- No internal-access or unused-access analysis was enabled.
- Coverage of every DepGuard AgentCore resource has not been
  independently demonstrated.
- Zero findings does not prove the absence of all possible exposure.
- No automated notification or remediation workflow was validated.

## 6. Preliminary assessment

Provisional status: Partially Implemented.

Reason:

External-access monitoring is now enabled for the current account
in us-east-1, and the analyzer reports zero active findings.
However, workload coverage, regional scope, and operational
monitoring requirements have not been fully assessed.

This is a manual evidence record, not an official finding generated
by the AWS Well-Architected Review skill.

## 7. Evidence source

AWS Console:
IAM Access Analyzer > Analyzer:
depguard-external-access-us-east-1

Observed properties:
- State: Active
- Zone of trust: Current account
- Active findings: 0
- Last analysis: approximately 12 hours before observation

The console observation was recorded during the review.
A machine-readable export and screenshot have not yet been archived.
