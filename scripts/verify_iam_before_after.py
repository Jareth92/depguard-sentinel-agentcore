#!/usr/bin/env python3
"""Compare the isolated DepGuard bearer-token statement before and after.

This script intentionally uses IAM SimulateCustomPolicy, not
SimulatePrincipalPolicy. The two fixture files contain ONLY the
PublicContainerBearerToken statement, not the complete managed policy and not
all permissions attached to DepGuardSentinelExecutionRole.

The script is read-only: it calls the IAM policy simulator and does not create,
update, attach, detach, or delete AWS resources.

Required AWS permission: iam:SimulateCustomPolicy.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ACTION = "sts:GetServiceBearerToken"
EXPECTED = {
    "ecr-public.amazonaws.com": {
        "v1": "allowed",
        "v2": "allowed",
    },
    "codeartifact.amazonaws.com": {
        "v1": "allowed",
        "v2": "implicitDeny",
    },
}

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = PROJECT_ROOT / "iam" / "policy-fixtures"


def load_policy(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Policy fixture not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("Statement"), list):
        raise RuntimeError(f"Unexpected IAM policy shape in {path}")
    return value


def simulate(iam_client: Any, policy: dict[str, Any], service_name: str) -> tuple[str, list[str]]:
    response = iam_client.simulate_custom_policy(
        PolicyInputList=[json.dumps(policy, separators=(",", ":"))],
        ActionNames=[ACTION],
        ResourceArns=["*"],
        ContextEntries=[
            {
                "ContextKeyName": "sts:AWSServiceName",
                "ContextKeyValues": [service_name],
                "ContextKeyType": "string",
            }
        ],
    )
    results = response.get("EvaluationResults", [])
    if len(results) != 1:
        raise RuntimeError(
            f"Expected exactly one IAM evaluation result; received {len(results)}"
        )
    result = results[0]
    return str(result.get("EvalDecision", "UNKNOWN")), list(
        result.get("MissingContextValues", [])
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Simulate the isolated DepGuard IAM bearer-token statement v1 vs v2."
    )
    parser.add_argument(
        "--profile",
        default=os.environ.get("AWS_PROFILE", "depguard-operator"),
        help="AWS shared-config profile (default: AWS_PROFILE or depguard-operator)",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region for the IAM client (default: us-east-1)",
    )
    args = parser.parse_args()

    try:
        import boto3  # Imported lazily so the offline unit tests do not need boto3.
    except ImportError:
        print(
            "ERROR: boto3 is not installed in this Python environment. "
            "Use the project's virtual environment and install its requirements.",
            file=sys.stderr,
        )
        return 2

    try:
        v1 = load_policy(FIXTURE_DIR / "DepGuardSentinelExecutionPolicy.v1.fixture.json")
        v2 = load_policy(FIXTURE_DIR / "DepGuardSentinelExecutionPolicy.v2.fixture.json")
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        iam = session.client("iam")
    except Exception as exc:  # credential/profile/client setup errors
        print(f"ERROR: Could not initialize AWS IAM client: {exc}", file=sys.stderr)
        return 2

    print("DepGuard Sentinel — IAM policy statement simulation")
    print(f"Profile: {args.profile}")
    print(f"Region:  {args.region}")
    print(f"Action:  {ACTION}")
    print("Mode:    SimulateCustomPolicy (isolated statement fixtures; read-only)")
    print("WARNING: This does NOT simulate the complete execution role policy.\n")

    rows: list[dict[str, str | list[str]]] = []
    failed = False
    for service_name in EXPECTED:
        for version, policy in (("v1", v1), ("v2", v2)):
            try:
                decision, missing = simulate(iam, policy, service_name)
            except Exception as exc:
                print(
                    f"ERROR while simulating {version} for {service_name}: {exc}",
                    file=sys.stderr,
                )
                print(
                    "Required permission: iam:SimulateCustomPolicy. "
                    "No permission changes were attempted by this script.",
                    file=sys.stderr,
                )
                return 3
            expected = EXPECTED[service_name][version]
            passed = decision == expected and not missing
            failed = failed or not passed
            rows.append(
                {
                    "version": version,
                    "service": service_name,
                    "decision": decision,
                    "expected": expected,
                    "missing_context": missing,
                    "pass": "PASS" if passed else "FAIL",
                }
            )

    print("| Version | sts:AWSServiceName | Decision | Expected | Missing context | Result |")
    print("|---|---|---|---|---|---|")
    for row in rows:
        print(
            f"| {row['version']} | {row['service']} | {row['decision']} | "
            f"{row['expected']} | {row['missing_context']} | {row['pass']} |"
        )

    print("\nInterpretation:")
    print("- v1 has no sts:AWSServiceName condition, so both test services are allowed by this statement.")
    print("- v2 allows ecr-public.amazonaws.com and implicitly denies codeartifact.amazonaws.com.")
    print("- This is an isolated statement comparison, not proof of every effective permission on the IAM role.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
