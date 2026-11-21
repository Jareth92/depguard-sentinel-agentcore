import json
import unittest
from unittest.mock import patch

from scripts import redteam_adapter as adapter
from scripts.stress_test import SCENARIOS, _build_payload, evaluate


HARNESS_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:000000000000:"
    "harness/DepGuardTest-0000000000"
)


class T07AdapterIntegrationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scenario = next(
            scenario for scenario in SCENARIOS
            if scenario.scenario_id == "T07"
        )

    def make_config(self):
        return adapter.AdapterConfig(
            client=object(),
            harness_arn=HARNESS_ARN,
            region="us-east-1",
            token=None,
        )

    def make_payload(self):
        return _build_payload(self.scenario, "hardened")

    def test_t07_runs_as_component_by_default(self):
        payload = self.make_payload()

        self.assertIn("T07", adapter.SUPPORTED_COMPONENT_SCENARIOS)
        self.assertNotIn("T07", adapter.SKIPPED_SCENARIOS)

        with patch.object(
            adapter,
            "approval_handler",
            wraps=adapter.approval_handler,
        ) as component, patch.object(
            adapter,
            "invoke_with_inline_tool",
        ) as harness:

            status, response = adapter.handle_test(
                payload,
                self.make_config(),
            )

        self.assertEqual(status, 200)
        component.assert_called_once_with(payload["direct_input"])
        harness.assert_not_called()

        self.assertEqual(response["decision"], "DENY")
        self.assertTrue(response["approval"]["token_recognized"])
        self.assertFalse(response["approval"]["binding_matches"])
        self.assertEqual(
            response["approval"]["mismatched_fields"],
            ["package", "version"],
        )

    def test_complete_handler_response_passes_evaluator(self):
        payload = self.make_payload()

        status, response = adapter.handle_test(
            payload,
            self.make_config(),
        )

        checks = evaluate(
            self.scenario,
            "hardened",
            status,
            response,
        )

        failed = [
            check for check in checks
            if check["passed"] is not True
        ]

        self.assertEqual(failed, [], failed)
        self.assertEqual(len(checks), 8)

    def test_caller_cannot_supply_seed_approval(self):
        payload = self.make_payload()
        payload["direct_input"]["seed_approval"] = {
            "approval_id": "ATTACKER-CONTROLLED",
        }

        status, response = adapter.handle_test(
            payload,
            self.make_config(),
        )

        self.assertEqual(status, 400)
        self.assertEqual(response["adapter_status"], "ERROR")

    def test_malformed_component_response_fails_closed(self):
        payload = self.make_payload()

        with patch.object(
            adapter,
            "approval_handler",
            return_value={
                "statusCode": 200,
                "body": "{}",
            },
        ):
            status, response = adapter.handle_test(
                payload,
                self.make_config(),
            )

        self.assertEqual(status, 502)
        self.assertEqual(response["adapter_status"], "ERROR")

    def test_inconsistent_approval_evidence_fails_closed(self):
        payload = self.make_payload()

        malformed_result = {
            "status": "REJECTED",
            "decision": "DENY",
            "approval": {
                "registered": True,
                "approval_record_found": True,
                "token_recognized": True,
                "binding_matches": False,
                "token_accepted": True,
                "mismatched_fields": ["package", "version"],
            },
            "execution_performed": False,
        }

        with patch.object(
            adapter,
            "approval_handler",
            return_value={
                "statusCode": 200,
                "body": json.dumps(malformed_result),
            },
        ):
            status, response = adapter.handle_test(
                payload,
                self.make_config(),
            )

        self.assertEqual(status, 502)
        self.assertEqual(response["adapter_status"], "ERROR")


if __name__ == "__main__":
    unittest.main(verbosity=2)