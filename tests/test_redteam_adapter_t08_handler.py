import json
import unittest
from unittest.mock import patch

from scripts import redteam_adapter as adapter
from scripts.stress_test import SCENARIOS, _build_payload, evaluate


HARNESS_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:000000000000:"
    "harness/DepGuardTest-0000000000"
)


class T08HandlerIntegrationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scenario = next(
            scenario for scenario in SCENARIOS
            if scenario.scenario_id == "T08"
        )

    def run_handler(self, payload):
        config = adapter.AdapterConfig(
            client=object(),
            harness_arn=HARNESS_ARN,
            region="us-east-1",
            token=None,
        )

        # Temporarily remove T08 from SKIP for this local test only.
        remaining_skips = {
            key: value
            for key, value in adapter.SKIPPED_SCENARIOS.items()
            if key != "T08"
        }

        with patch.dict(
            adapter.SKIPPED_SCENARIOS,
            remaining_skips,
            clear=True,
        ):
            return adapter.handle_test(payload, config)

    def test_malicious_fixture_rejected_through_handler(self):
        payload = _build_payload(self.scenario, "hardened")

        status, response = self.run_handler(payload)

        self.assertEqual(status, 200)
        self.assertTrue(response["validation"]["input_rejected"])
        self.assertTrue(response["validation"]["raw_arguments_rejected"])
        self.assertTrue(response["validation"]["manifest_rejected"])

        self.assertEqual(
            response["evidence"]["t08"]["raw_arguments"]["status"],
            "REJECTED",
        )

        self.assertFalse(
            response["evidence"]["t08"]["execution_performed"]
        )

    def test_valid_fixture_accepted_through_handler(self):
        payload = _build_payload(self.scenario, "hardened")

        payload["direct_input"] = {
            "raw_arguments": ["lodash", "@types/node"]
        }

        payload["package_json"] = json.dumps({
            "name": "redteam-fixture",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.21",
                "@types/node": "^22.0.0",
            },
        })

        status, response = self.run_handler(payload)

        self.assertEqual(status, 200)
        self.assertFalse(response["validation"]["input_rejected"])
        self.assertEqual(response["decision"], "ANALYZE_ONLY")

        self.assertEqual(
            response["evidence"]["t08"]["raw_arguments"]["status"],
            "OK",
        )

        self.assertFalse(
            response["evidence"]["t08"]["execution_performed"]
        )

    def test_missing_direct_input_rejected(self):
        payload = _build_payload(self.scenario, "hardened")
        payload.pop("direct_input", None)

        status, response = self.run_handler(payload)

        self.assertEqual(status, 200)
        self.assertTrue(response["validation"]["input_rejected"])
        self.assertFalse(
            response["validation"]["direct_input_schema_valid"]
        )
    def test_t08_runs_as_component_by_default(self):
        self.assertIn("T08", adapter.SUPPORTED_COMPONENT_SCENARIOS)
        self.assertNotIn("T08", adapter.SUPPORTED_AGENT_SCENARIOS)
        self.assertNotIn("T08", adapter.SKIPPED_SCENARIOS)

        payload = _build_payload(self.scenario, "hardened")

        config = adapter.AdapterConfig(
            client=object(),
            harness_arn=HARNESS_ARN,
            region="us-east-1",
            token=None,
        )

        with patch.object(
            adapter,
            "lambda_handler",
            wraps=adapter.lambda_handler,
        ) as component:
            status, response = adapter.handle_test(payload, config)

        component.assert_called_once()
        self.assertEqual(status, 200)
        self.assertTrue(response["validation"]["input_rejected"])
        self.assertEqual(response["decision"], "DENY")

    def test_malicious_fixture_passes_t08_evaluator(self):
        payload = _build_payload(self.scenario, "hardened")

        status, response = self.run_handler(payload)

        checks = evaluate(
            self.scenario,
            "hardened",
            status,
            response,
        )

        failed_checks = [
            check for check in checks
            if check["passed"] is not True
        ]

        self.assertEqual(failed_checks, [], failed_checks)
        self.assertEqual(len(checks), 5)

    def test_malformed_component_response_fails_closed(self):
        payload = _build_payload(self.scenario, "hardened")

        with patch.object(
            adapter,
            "lambda_handler",
            return_value={
                "statusCode": 200,
                "body": "{}",
            },
        ):
            status, response = self.run_handler(payload)

        self.assertEqual(status, 502)
        self.assertEqual(response["adapter_status"], "ERROR")


if __name__ == "__main__":
    unittest.main(verbosity=2)