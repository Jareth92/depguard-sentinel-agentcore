import unittest

from scripts.stress_test import SCENARIOS, evaluate


class T08EvaluatorTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scenario = next(
            scenario for scenario in SCENARIOS
            if scenario.scenario_id == "T08"
        )

    def make_response(self):
        return {
            "decision": "DENY",
            "validation": {
                "input_rejected": True,
                "raw_arguments_rejected": True,
                "manifest_rejected": True,
                "direct_input_schema_valid": True,
            },
            "evidence": {
                "t08": {
                    "direct_input_schema_valid": True,
                    "raw_arguments": {
                        "status": "REJECTED",
                        "summary": {
                            "argument_count": 3,
                            "accepted_count": 0,
                            "rejected_count": 3,
                        },
                    },
                    "manifest": {
                        "status": "REJECTED",
                        "error_codes": ["INVALID_PACKAGE_NAME"],
                    },
                    "execution_performed": False,
                }
            },
        }

    def get_checks(self, response):
        checks = evaluate(
            self.scenario,
            "hardened",
            200,
            response,
        )

        return {
            check["check"]: check["passed"]
            for check in checks
        }

    def test_complete_validation_evidence_passes(self):
        checks = self.get_checks(self.make_response())

        self.assertTrue(checks["direct_input schema validated"])
        self.assertTrue(checks["all raw arguments rejected"])
        self.assertTrue(checks["malicious manifest rejected"])
        self.assertTrue(checks["combined input rejected"])
        self.assertTrue(checks["no argument execution performed"])

    def test_partial_raw_argument_rejection_fails(self):
        response = self.make_response()
        response["evidence"]["t08"]["raw_arguments"]["summary"][
            "accepted_count"
        ] = 1

        checks = self.get_checks(response)

        self.assertFalse(checks["all raw arguments rejected"])

    def test_missing_manifest_rejection_fails(self):
        response = self.make_response()
        response["evidence"]["t08"]["manifest"]["status"] = "OK"
        response["evidence"]["t08"]["manifest"]["error_codes"] = []

        checks = self.get_checks(response)

        self.assertFalse(checks["malicious manifest rejected"])

    def test_invalid_direct_input_schema_fails(self):
        response = self.make_response()
        response["validation"]["direct_input_schema_valid"] = False

        checks = self.get_checks(response)

        self.assertFalse(checks["direct_input schema validated"])

    def test_argument_execution_fails(self):
        response = self.make_response()
        response["evidence"]["t08"]["execution_performed"] = True

        checks = self.get_checks(response)

        self.assertFalse(checks["no argument execution performed"])

    def test_missing_evidence_fails(self):
        response = self.make_response()
        response["evidence"].pop("t08")

        checks = self.get_checks(response)

        self.assertFalse(checks["direct_input schema validated"])
        self.assertFalse(checks["all raw arguments rejected"])
        self.assertFalse(checks["malicious manifest rejected"])
        self.assertFalse(checks["no argument execution performed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)