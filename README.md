# DepGuard Sentinel

**A read-only dependency-manifest security analysis prototype built around Amazon Bedrock AgentCore Harness V2.**

DepGuard Sentinel explores how an AI agent can analyze an untrusted `package.json` manifest while maintaining a restricted tool boundary and testing resistance to adversarial inputs, including prompt injection and forged approval claims.

> **Status:** Security engineering prototype. It is not a production vulnerability scanner or a replacement for a software composition analysis (SCA) platform.

## Project Goals

- Keep dependency-manifest analysis read-only.
- Restrict agent tool access through an explicit allowlist.
- Treat package metadata and supplied content as untrusted data.
- Reject unauthorized tool requests and malformed direct inputs.
- Validate approval bindings against package and version identity.
- Evaluate the agent and local security components through adversarial test scenarios.
- Preserve structured execution evidence for security evaluation.

## Architecture

```text
Red Team Stress Tester
        |
        v
Local HTTP Adapter (127.0.0.1:8787)
        |
        v
AgentCore Client
        |
        v
Amazon Bedrock AgentCore Harness V2
        |
        | Tool handoff: analyze_manifest
        v
Local allowlisted function execution
        |
        v
Tool result returned to Harness
```
The integration uses an explicit tool allowlist containing `analyze_manifest`. The local client handles the inline tool handoff and returns the function result to the Harness.

T07 and T08 exercise local security components directly; they are not AgentCore model invocations.


## Security Design

- **Tool allowlisting:** The AgentCore client permits only the `analyze_manifest` tool.
- **Fail-closed behavior:** Unknown or unsupported tool requests are rejected.
- **Untrusted input handling:** Package metadata is treated as data, not as instructions.
- **Read-only analysis:** The workflow does not install dependencies, execute package scripts, or intentionally modify the analyzed project.
- **Approval binding:** Package and version identity are validated to detect approval substitution attempts.
- **Input validation:** Local components validate raw arguments and reject malformed or unsupported inputs.

## Security Limitations

- **No CVE intelligence lookup:** The analyzer does not query OSV, NVD, GitHub Security Advisories, or other vulnerability databases. It does not provide verified CVE coverage.
- **Network exposure:** The tested AgentCore runtime uses a `PUBLIC` network configuration. Prompt restrictions do not provide network isolation.
- **Confidentiality testing scope:** The T05 check detects known system-prompt fragments. It is not a universal guarantee against information disclosure.
- **Approval persistence:** T07 uses an in-memory fixture and does not demonstrate a production persistent approval store.
- **Test evidence scope:** Passing the configured scenarios demonstrates that their evaluator checks passed; it does not prove that the system is resistant to every possible attack.

## Test Results

**Evidence snapshot: November 21, 2026.**

| Test group | Result | Execution scope |
|---|---:|---|
| Automated Python tests | 125 passed | Local unit and component tests |
| T01–T06 and T09 | 7 scenarios passed | AgentCore-backed Red Team tests |
| T07 and T08 | 2 scenarios passed | Local component-level tests |
| Consolidated Red Team checks | 40/40 passed | Master evidence report |

The nine Red Team scenarios do not represent nine model invocations. T07 and T08 exercise local security components rather than the AgentCore model.

### Evidence Files

The following reports contain the recorded test results:

- `artifacts/redteam-master-20261121.json` — consolidated Red Team results.
- `artifacts/redteam-t01-evidence-20261121.json`
- `artifacts/redteam-t02-evidence-20261121.json`
- `artifacts/redteam-t03-evidence-20261121.json`
- `artifacts/redteam-t04-evidence-20261121.json`
- `artifacts/redteam-t05-evidence-20261121.json`
- `artifacts/redteam-t06-evidence-v2-20261121.json`
- `artifacts/redteam-t07-component-20261121.json`
- `artifacts/redteam-t08-component-20261121.json`
- `artifacts/redteam-t09-evidence-20261121.json`
- `artifacts/unit-tests-20261121.txt` — automated Python test output.

## Requirements

- Python 3.13 (tested).
- AWS CLI configured with an authorized AWS identity.
- An existing Amazon Bedrock AgentCore Harness V2.
- Access to the AWS region where the Harness is deployed.
- Python dependency: `boto3==1.44.7`

## Installation (Windows PowerShell)

Clone the repository:

```powershell
git clone https://github.com/Jareth92/depguard-sentinel-agentcore.git
cd depguard-sentinel-agentcore
```

Create a Python virtual environment:

```powershell
py -3.13 -m venv .venv
```

Install the project dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The commands above use the virtual environment directly and do not require PowerShell activation.

## AWS Configuration

Configure the AWS profile, region, and Harness ARN for your environment:

```powershell
$env:AWS_PROFILE = "<AWS_PROFILE>"
$env:AWS_REGION = "us-east-1"
$env:DEPGUARD_HARNESS_ARN = "arn:aws:bedrock-agentcore:us-east-1:<AWS_ACCOUNT_ID>:harness/<HARNESS_ID>"
```

Verify the configured AWS identity:

```powershell
aws sts get-caller-identity --profile $env:AWS_PROFILE
```

Use your own AWS account and Harness identifiers. Never commit credentials or environment-specific configuration files.

## Running Automated Tests

Run the unit and component test suite from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Invoking the AgentCore Harness

Invoke the configured Harness directly:

```powershell
.\.venv\Scripts\python.exe .\scripts\invoke_harness.py --harness-arn $env:DEPGUARD_HARNESS_ARN --region $env:AWS_REGION --profile $env:AWS_PROFILE
```

To validate the settings without contacting AWS, add the --dry-run option.

## Running the Red Team Adapter

Start the local HTTP adapter:

```powershell
.\.venv\Scripts\python.exe .\scripts\redteam_adapter.py --port 8787 --region $env:AWS_REGION --profile $env:AWS_PROFILE --harness-arn $env:DEPGUARD_HARNESS_ARN
```

The adapter binds to 127.0.0.1 on port 8787 by default.

Available endpoints:

- GET http://127.0.0.1:8787/health — health check.
- POST http://127.0.0.1:8787/redteam/test — Red Team scenario execution.

Keep the adapter restricted to the local machine. Do not expose it to public networks. When DEPGUARD_REDTEAM_TOKEN is unset, local requests are unauthenticated.

## Running Red Team Scenarios

With the adapter running in a separate terminal, execute the Red Team scenarios:

```powershell
.\.venv\Scripts\python.exe .\scripts\stress_test.py --mode hardened --hardened-url "http://127.0.0.1:8787/redteam/test" --output "artifacts/redteam-results.json"
```

To execute a single scenario, use the `--scenario` option with an ID from T01 to T09.

Use `--dry-run` to list the scenarios without making network requests.

The default mode is `both` and requires both Hardened and Naive endpoints. Use `--mode hardened` when testing only the Hardened adapter.

## Repository Structure

```text
depguard-sentinel-agentcore/
|-- depguard/
|   |-- agentcore_client.py
|   |-- analyze_manifest.py
|   |-- approval_binding.py
|   |-- approval_handler.py
|   |-- confidentiality.py
|   |-- lambda_validator.py
|   `-- raw_argument_validator.py
|-- scripts/
|   |-- invoke_harness.py
|   |-- redteam_adapter.py
|   `-- stress_test.py
|-- tests/
|   `-- test_*.py
|-- docs/
|   |-- inline_function_integration.md
|   `-- red_team_checklist.md
|-- artifacts/
|   `-- Red Team and unit test evidence
|-- create-harness.example.json
|-- requirements.txt
|-- .gitignore
`-- README.md
```

The real local `create-harness.json` is excluded from version control.

