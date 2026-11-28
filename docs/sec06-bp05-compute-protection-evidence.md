# SEC06-BP05 — Automate Compute Protection Evidence

## 1. Identification

- Workload: DepGuard Sentinel
- Pillar: Security
- Question: SEC06 — Infrastructure Protection
- Best Practice: SEC06-BP05 — Automate compute protection
- Assessment date: 2026-11-27
- Region: us-east-1
- Assessment status: PARTIALLY IMPLEMENTED

## 2. Lambda Runtime Management

Resource: DepGuardScanFunction

Observed configuration:
- Package type: Zip
- Runtime: Python 3.13
- Architecture: x86_64
- Runtime update mode: Auto
- Runtime version ARN:
  arn:aws:lambda:us-east-1::runtime:94107394b7943d336b78c01af71e42f453f8186ba74ab877f115e1908ea07783

Evidence source:
- AWS Lambda console, Runtime management configuration.
- AWS CLI get-function metadata.

Assessment:
The function uses automatic Lambda runtime management.
This delegates runtime version update management to AWS Lambda.

Limitation:
Automatic runtime management does not establish automated
vulnerability scanning or remediation of application dependencies.

## 3. Lambda Code Signing

Observed configuration:
- Code signing configuration: None
- SigningJobArn: null
- SigningProfileVersionArn: null

Evidence source:
- AWS Lambda console, Code signing configuration.
- AWS CLI get-function metadata.

Assessment:
No code signing configuration is associated with the function.
Signature enforcement for deployed Lambda packages is therefore
not demonstrated.

Note:
GetFunctionCodeSigningConfig and GetRuntimeManagementConfig
returned AccessDenied for the inspected IAM role.
The console was used to verify the configuration.

## 4. Automated Dependency Vulnerability Scanning

Tool: pip-audit
Version: 2.10.1
Input: requirements.txt

Local execution result:
- No known vulnerabilities found.

CI integration:
- Workflow: .github/workflows/ci.yml
- Step: Audit dependencies for known vulnerabilities
- Command: pip-audit -r requirements.txt
- Tool installation is pinned to pip-audit==2.10.1.

Assessment:
Dependency vulnerability auditing is integrated into GitHub Actions.
A non-zero audit result causes the CI job to fail.

Scope limitation:
pip-audit attempts to resolve and audit the Python dependency tree
declared by requirements.txt, including resolved transitive packages.
It does not establish that the deployed Lambda artifact contains
exactly this dependency set, nor does it scan AWS-managed runtime
components, operating-system libraries, or non-Python components.

## 5. Automated Source Code Analysis

Service: GitHub CodeQL

Observed run:
- Run ID: 46102819388
- Branch: main
- Commit: 283643ff874d88bcd7881e8a0270d70dbbcd50de
- Python analysis: Success
- GitHub Actions analysis: Success
- Code scanning alerts visible at inspection: None

Assessment:
CodeQL default setup completed successfully for Python and
GitHub Actions on the main branch.

Limitation:
This run analyzed main, not the hackathon branch.
A pull request analysis is still required to verify the
hackathon branch with CodeQL.

## 6. CI Execution Evidence

Workflow: DepGuard CI

Observed run:
- Run ID: 46104071908
- Run number: 17
- Branch: hackathon/well-architected-review
- Commit: c2811dbd9e0c81c885e96ce1801e33051213a95d
- Event: push
- Conclusion: success

Successful steps:
- Checkout repository
- Set up Python 3.13
- Install dependencies
- Audit dependencies for known vulnerabilities
- Compile Python sources
- Run unit tests

Local validation:
- Python compileall: PASS
- Unit tests: 143 passed
- git diff --check: PASS

## 7. Controls Not Demonstrated

The following controls remain outside the demonstrated
implementation:

- Amazon Inspector scanning of the deployed Lambda function
  was not enabled.
- Lambda code signing is not configured.
- Automated remediation or patch deployment for vulnerable
  application dependencies is not demonstrated.
- CodeQL analysis of the hackathon branch is pending.
- Runtime management in Auto mode does not replace application
  dependency vulnerability management.

## 8. Final Assessment

Status: PARTIALLY IMPLEMENTED

Implemented and evidenced:
- Automatic Lambda runtime version management.
- Automated Python dependency auditing in CI.
- Successful remote CI execution.
- Successful CodeQL analysis on the main branch.

Remaining gaps:
- Lambda artifact signature enforcement.
- Continuous scanning of the deployed Lambda artifact.
- Automated remediation of application dependency vulnerabilities.
- CodeQL verification of the hackathon branch.

This is a provisional, evidence-based assessment.
It is not an official AWS Well-Architected score or certification.

