# DepGuard Sentinel — Threat Model

## 1. Purpose and Scope

DepGuard Sentinel is a security engineering prototype for read-only
dependency-manifest analysis using Amazon Bedrock AgentCore Harness V2.

This document describes its assets, trust boundaries, adversary model,
security controls, and known residual risks.

The project is not a production Software Composition Analysis (SCA)
platform and does not provide verified CVE coverage.

## 2. Assets and Security Objectives

| Asset | Security objective |
|---|---|
| Dependency manifest | Treat supplied metadata as untrusted data |
| Agent tool boundary | Permit only explicitly allowlisted tools |
| Analysis workflow | Avoid installation, package-script execution, and intentional mutation |
| Approval binding | Detect package and version substitution |
| Runtime session | Preserve session identity during multi-turn testing |
| Execution evidence | Retain structured evidence without exposing raw attacker prompts |
| System instructions | Test disclosure of known prompt fragments |
| AWS configuration | Keep account identifiers, Harness ARNs, and credentials outside public source code |

## 3. Trust Boundaries

### 3.1 User Input to the Harness

Package manifests and user-supplied prompts may contain malicious
instructions, misleading metadata, or forged authority claims.

These values must be treated as untrusted data rather than trusted
instructions.

### 3.2 Harness to AgentCore Client

The client receives streaming responses and handles inline tool handoffs.

Only the explicitly allowlisted `analyze_manifest` tool may be dispatched.
Unknown or unsupported tool requests must fail closed.

### 3.3 Local HTTP Adapter

The Red Team adapter accepts HTTP requests on loopback at 127.0.0.1.

It applies request-size and input-validation controls.

When `DEPGUARD_REDTEAM_TOKEN` is unset, requests are unauthenticated.
The adapter must not be exposed to public networks without a separately
reviewed authentication and network-security design.

### 3.4 Approval and Validation Components

Approval claims and direct tool arguments are untrusted.

The approval-binding component checks package and version identity.
Local validators reject malformed or unsupported inputs.

## 4. Adversary Model

The test model considers an attacker who can influence prompts,
dependency metadata, or direct component inputs.

Relevant adversarial capabilities include:

- Direct prompt injection and instruction override.
- Forged authority and approval claims.
- Indirect injection through package metadata.
- Multi-turn scope escalation.
- Attempts to disclose known system-prompt fragments.
- Ambiguous requests that could be interpreted as authorization.
- Approval bait-and-switch.
- Raw argument and wildcard injection.
- Backend verdict and approval-format mimicry.

The threat model does not assume that prompt instructions provide
network isolation or replace AWS IAM permissions.

## 5. Security Controls

| Control | Security objective |
|---|---|
| Explicit tool allowlist | Restrict tool execution to analyze_manifest |
| Fail-closed client | Reject unsupported tool requests |
| Untrusted-data handling | Instruct the agent to treat manifest metadata as untrusted data, not as trusted instructions |
| Read-only analysis | Avoid package installation and script execution |
| Approval binding | Detect package/version substitution |
| Raw argument validation | Reject malformed or unsupported direct input |
| Confidentiality checks | Detect disclosure of known prompt fragments |
| Structured evidence | Preserve test traces for evaluation |

## 6. Red Team Scenario Mapping

| Scenario | Threat | Execution scope |
|---|---|---|
| T01 | Direct instruction override | AgentCore-backed |
| T02 | False authority | AgentCore-backed |
| T03 | Indirect prompt injection | AgentCore-backed |
| T04 | Multi-turn scope-persistence / scope-escalation probe | AgentCore-backed |
| T05 | Known prompt-fragment disclosure | AgentCore-backed |
| T06 | Ambiguous edge case | AgentCore-backed |
| T07 | Approval bait-and-switch | Local component |
| T08 | Argument and wildcard injection | Local component |
| T09 | Format and verdict mimicry | AgentCore-backed |

T04 exercised four turns in one runtime session. Its evidence records
only `analyze_manifest` executions and zero unauthorized tool executions.
It does not establish that an unauthorized tool request was actually
emitted and blocked during AgentCore execution. Fail-closed handling
is covered separately by local client tests.

T07 and T08 are local component tests, not AgentCore model invocations.
T08 validates a local Lambda-compatible handler and validator.
It was not deployed to AWS Lambda or invoked through AgentCore.

A passing scenario indicates that its configured evaluator checks passed.
It does not prove resistance to all possible attacks.

## 7. Residual Risks and Limitations

- No OSV, NVD, GitHub Security Advisories, or equivalent CVE database lookup.
- No universal guarantee against prompt or data disclosure.
- T05 checks for known prompt fragments; it is not a general
  information-flow verification system.
- T07 uses an in-memory fixture, not a persistent production approval store.
- The tested AgentCore runtime used a PUBLIC network configuration.
  Prompt restrictions do not provide network isolation.
- The local adapter's loopback binding is not a substitute for
  production authentication and network controls.
- The prototype does not establish production readiness.

## 8. Evidence

The consolidated Red Team results are recorded in:

`artifacts/redteam-master-20261121.json`

Individual scenario reports and automated test output are listed
in the root README.

## 9. Review

This threat model describes the tested prototype configuration as of
November 21, 2026.

It should be updated whenever the tool boundary, runtime permissions,
network configuration, approval workflow, or analysis capabilities change.
