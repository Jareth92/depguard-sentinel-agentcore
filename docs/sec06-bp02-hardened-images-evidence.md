# SEC06-BP02 — Provision Compute from Hardened Images Evidence

## 1. Identification

- Workload: DepGuard Sentinel
- Pillar: Security
- Question: SEC06 — Protecting compute
- Best Practice: SEC06-BP02 — Provision compute from hardened images
- Region: us-east-1
- Observation date: 2026-11-27
- Assessment type: Manual evidence-based assessment
- Assessment status: PARTIALLY IMPLEMENTED

## 2. AgentCore Runtime Artifact

Observed runtime:
- Runtime name: harness_DepGuardSentinel
- Runtime ID: harness_DepGuardSentinel-xg5UWVFic3
- Platform version: V2
- Status: READY
- Runtime version: 2
- Network mode: PUBLIC

Runtime container URI:
public.ecr.aws/i0n3d3i5/harness-us-east-1:latest

Harness environment:
- EnvironmentArtifact: null

Assessment:
The AgentCore Runtime reports a container artifact hosted
in a public Amazon ECR registry.

The Harness configuration does not report a customer-specified
custom EnvironmentArtifact.

The inspected configuration does not establish that DepGuard
builds or maintains this runtime container image.

Limitations:
- The container image digest was not independently verified.
- Publisher provenance was not independently verified.
- Image signature verification was not demonstrated.
- The image hardening baseline and build process were not inspected.
- The use of the latest tag does not establish immutable image pinning.

The reported ECR URI must not be interpreted as proof that
the image is customer-built or independently hardened.

## 3. AWS Lambda Compute Configuration

Resource: DepGuardScanFunction

Observed configuration:
- Package type: Zip
- Runtime: Python 3.13
- Architecture: x86_64
- Layers: 0
- Runtime management: Auto

Assessment:
The Lambda function uses the AWS-managed Python runtime
rather than a customer-provided container image.

The runtime update configuration is set to Auto.
This delegates runtime version update management to AWS Lambda.

Limitations:
- No customer-managed hardened container image was identified.
- No Lambda layer is currently configured.
- The deployed package was not independently verified against
  a signed software artifact or hardened image baseline.

## 4. Repository Image Build Configuration

Repository inspection previously examined common container
build and configuration files.

No customer-managed configuration was identified for:
- Dockerfile
- Containerfile
- docker-compose
- Dev Container configuration
- Container image hardening recipes
- Customer-managed container image build pipeline

No evidence was identified of a customer-managed container
image being built and deployed for the AgentCore Runtime.

Assessment:
A reproducible customer-managed hardened image build
process was not demonstrated.

Limitation:
The absence of these files in the inspected repository does
not establish the absence of AWS-managed internal image
hardening or external build processes.

## 5. Trusted Registries and Dependency Sources

Observed evidence:
- The AgentCore Runtime reports a public ECR image URI.
- requirements.txt pins boto3 to version 1.44.7.
- Dependabot monitors pip and GitHub Actions dependencies.
- GitHub Actions integrates pip-audit 2.10.1.
- The CI dependency audit completed successfully.

Assessment:
Some application dependency controls are implemented.

However, the reviewed evidence does not establish:
- A customer-managed private container registry.
- An approved private package repository integrated into builds.
- Container image signature verification.
- Container image provenance verification.
- A scheduled customer-managed image rebuild process.

## 6. Image and Dependency Scanning

Implemented:
- pip-audit dependency scanning in GitHub Actions.
- CodeQL source code analysis.
- Dependabot dependency monitoring.

These controls provide application source and dependency
analysis but do not demonstrate container image scanning.

No Amazon ECR image scanning pipeline or scheduled image
rescan process was demonstrated for a customer-managed image.

Amazon Inspector vulnerability scanning for the deployed Lambda
was not demonstrated. The account's Free plan restricted the
enablement flow during this assessment; no scan result was obtained.

## 7. Controls Not Demonstrated

The following controls remain unverified or outside the
customer-managed implementation:

- Customer-managed hardened image baseline.
- Reproducible image build and hardening recipe.
- Container image digest and publisher provenance verification.
- Image signature verification.
- Customer-managed private registry for approved images.
- Container image vulnerability scanning.
- Scheduled image rebuild and replacement process.
- Lambda dependency separation through Layers.

These findings do not imply that AWS-managed infrastructure
is unprotected. Provider-managed controls were not independently
audited as part of this assessment.

## 8. Final Assessment

Status: PARTIALLY IMPLEMENTED

Implemented supporting controls:
- AWS-managed Lambda Python runtime with automatic runtime updates.
  This is provider-managed runtime lifecycle evidence, not proof
  of a customer-managed hardened image.
- Automated application dependency auditing through pip-audit.
- CodeQL source code analysis.
- Dependency monitoring through Dependabot.

The customer-managed hardened image baseline itself remains
NOT DEMONSTRATED.

Remaining gaps:
- Customer-managed image hardening and provenance evidence.
- Container image signature verification.
- Private registry and image scanning evidence.
- Scheduled hardened image rebuild and replacement process.

This is a provisional, evidence-based assessment.
It is not an official AWS Well-Architected score or certification.

## 9. References

- https://docs.aws.amazon.com/wellarchitected/latest/framework/sec06-bp02.html
- https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html
- https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html

