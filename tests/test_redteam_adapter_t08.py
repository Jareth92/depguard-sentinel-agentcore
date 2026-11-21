import json
import unittest

from scripts import redteam_adapter as adapter
from scripts.stress_test import SCENARIOS, _build_payload


class T08AdapterValidationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scenario = next(
            scenario for scenario in SCENARIOS
            if scenario.scenario_id == "T08"
        )

    def test_t08_fixture_rejected_by_both_validators(self):
        payload = _build_payload(self.scenario, "hardened")

        status, response = adapter._handle_t08_component_validation(payload)

        self.assertEqual(status, 200)
        self.assertTrue(response["validation"]["input_rejected"])
        self.assertTrue(response["validation"]["raw_arguments_rejected"])
        self.assertTrue(response["validation"]["manifest_rejected"])

        evidence = response["evidence"]["t08"]

        self.assertEqual(evidence["raw_arguments"]["status"], "REJECTED")
        self.assertEqual(evidence["raw_arguments"]["summary"]["rejected_count"], 3)
        self.assertEqual(evidence["manifest"]["status"], "REJECTED")
        self.assertFalse(evidence["execution_performed"])

    def test_valid_arguments_and_manifest_are_accepted(self):
        payload = {
            "direct_input": {
                "raw_arguments": ["lodash", "@types/node"]
            },
            "package_json": json.dumps({
                "name": "redteam-fixture",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "4.17.21",
                    "@types/node": "^22.0.0"
                }
            })
        }

        status, response = adapter._handle_t08_component_validation(payload)

        self.assertEqual(status, 200)
        self.assertFalse(response["validation"]["input_rejected"])
        self.assertFalse(response["validation"]["raw_arguments_rejected"])
        self.assertFalse(response["validation"]["manifest_rejected"])
        self.assertEqual(response["decision"], "ANALYZE_ONLY")

        evidence = response["evidence"]["t08"]

        self.assertEqual(evidence["raw_arguments"]["status"], "OK")
        self.assertEqual(evidence["raw_arguments"]["summary"]["accepted_count"], 2)
        self.assertEqual(evidence["manifest"]["status"], "OK")
        self.assertFalse(evidence["execution_performed"])

    def test_extra_direct_input_property_is_rejected(self):
        payload = {
            "direct_input": {
                "raw_arguments": ["lodash"],
                "unexpected": "extra"
            },
            "package_json": json.dumps({
                "dependencies": {"lodash": "4.17.21"}
            })
        }

        status, response = adapter._handle_t08_component_validation(payload)

        self.assertEqual(status, 200)
        self.assertTrue(response["validation"]["input_rejected"])
        self.assertFalse(response["validation"]["direct_input_schema_valid"])
        self.assertTrue(response["validation"]["raw_arguments_rejected"])

    def test_non_string_argument_is_rejected(self):
        payload = {
            "direct_input": {
                "raw_arguments": ["lodash", None]
            },
            "package_json": json.dumps({
                "dependencies": {"lodash": "4.17.21"}
            })
        }

        status, response = adapter._handle_t08_component_validation(payload)

        self.assertEqual(status, 200)
        self.assertTrue(response["validation"]["input_rejected"])

        summary = response["evidence"]["t08"]["raw_arguments"]["summary"]

        self.assertEqual(summary["accepted_count"], 1)
        self.assertEqual(summary["rejected_count"], 1)

    def test_attacker_controlled_values_are_not_returned(self):
        malicious_value = "arn:aws:s3:::*"

        payload = {
            "direct_input": {
                "raw_arguments": [malicious_value]
            },
            "package_json": json.dumps({
                "dependencies": {malicious_value: "latest"}
            })
        }

        status, response = adapter._handle_t08_component_validation(payload)

        self.assertEqual(status, 200)
        self.assertNotIn(malicious_value, json.dumps(response))
        self.assertTrue(response["validation"]["input_rejected"])


if __name__ == "__main__":
    unittest.main(verbosity=2)