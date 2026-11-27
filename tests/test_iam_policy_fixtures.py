"""Offline regression tests for the isolated bearer-token policy fixtures.

These tests validate the fixture documents and the intended StringEquals
condition. They are NOT an implementation of the full AWS IAM policy engine;
use scripts/verify_iam_before_after.py for a live IAM policy simulation.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

FIXTURE_DIR = (
    Path(__file__).resolve().parents[1] / "iam" / "policy-fixtures"
)
V1_PATH = FIXTURE_DIR / "DepGuardSentinelExecutionPolicy.v1.fixture.json"
V2_PATH = FIXTURE_DIR / "DepGuardSentinelExecutionPolicy.v2.fixture.json"


def load_fixture(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def get_target_statement(policy: dict[str, Any]) -> dict[str, Any]:
    matches = [
        statement
        for statement in policy["Statement"]
        if statement.get("Sid") == "PublicContainerBearerToken"
    ]
    if len(matches) != 1:
        raise AssertionError(
            "Expected exactly one PublicContainerBearerToken statement"
        )
    return matches[0]


def fixture_statement_allows_service(
    statement: dict[str, Any], service_name: str
) -> bool:
    """Evaluate only the simple fields/condition used by this fixture."""
    if statement.get("Effect") != "Allow":
        return False
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    if "sts:GetServiceBearerToken" not in actions:
        return False
    resources = statement.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]
    if "*" not in resources:
        return False

    condition = statement.get("Condition")
    if condition is None:
        return True
    expected = condition.get("StringEquals", {}).get("sts:AWSServiceName")
    if expected is None:
        return False
    if isinstance(expected, list):
        return service_name in expected
    return service_name == expected


class IAMPolicyFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.v1 = load_fixture(V1_PATH)
        cls.v2 = load_fixture(V2_PATH)
        cls.v1_statement = get_target_statement(cls.v1)
        cls.v2_statement = get_target_statement(cls.v2)

    def test_fixture_files_are_valid_iam_policy_documents(self) -> None:
        for policy in (self.v1, self.v2):
            self.assertEqual(policy["Version"], "2012-10-17")
            self.assertIsInstance(policy["Statement"], list)
            self.assertEqual(len(policy["Statement"]), 1)

    def test_v1_statement_has_no_service_condition(self) -> None:
        self.assertNotIn("Condition", self.v1_statement)

    def test_v2_statement_restricts_service_to_ecr_public(self) -> None:
        self.assertEqual(
            self.v2_statement.get("Condition"),
            {
                "StringEquals": {
                    "sts:AWSServiceName": "ecr-public.amazonaws.com"
                }
            },
        )

    def test_action_effect_and_resource_are_unchanged(self) -> None:
        for statement in (self.v1_statement, self.v2_statement):
            self.assertEqual(statement["Effect"], "Allow")
            self.assertEqual(statement["Action"], "sts:GetServiceBearerToken")
            self.assertEqual(statement["Resource"], "*")

    def test_v1_fixture_allows_both_comparison_services(self) -> None:
        self.assertTrue(
            fixture_statement_allows_service(
                self.v1_statement, "ecr-public.amazonaws.com"
            )
        )
        self.assertTrue(
            fixture_statement_allows_service(
                self.v1_statement, "codeartifact.amazonaws.com"
            )
        )

    def test_v2_fixture_allows_ecr_public(self) -> None:
        self.assertTrue(
            fixture_statement_allows_service(
                self.v2_statement, "ecr-public.amazonaws.com"
            )
        )

    def test_v2_fixture_does_not_allow_codeartifact(self) -> None:
        self.assertFalse(
            fixture_statement_allows_service(
                self.v2_statement, "codeartifact.amazonaws.com"
            )
        )


if __name__ == "__main__":
    unittest.main()
