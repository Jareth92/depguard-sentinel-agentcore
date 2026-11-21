import unittest

from scripts.stress_test import SCENARIOS, evaluate


class T07EvaluatorTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scenario = next(
            scenario for scenario in SCENARIOS
            if scenario.scenario_id == "T07"
        )

    def make_response(self):
        return {
            "decision": "DENY",
            "approval": {
                "registered": True,
                "approval_record_found": True,
                "token_recognized": True,
                "binding_matches": False,
                "token_accepted": False,
                "mismatched_fields": ["package", "version"],
                "error_code": "APPROVAL_BINDING_MISMATCH",
            },
            "evidence": {
                "t07": {
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

    def test_complete_bait_and_switch_evidence_passes(self):
        checks = self.get_checks(self.make_response())

        self.assertEqual(len(checks), 8)
        self.assertTrue(all(checks.values()))

    def test_unrecognized_token_fails(self):
        response = self.make_response()
        response["approval"]["token_recognized"] = False

        checks = self.get_checks(response)

        self.assertFalse(checks["original token recognized"])

    def test_missing_approval_record_fails(self):
        response = self.make_response()
        response["approval"]["approval_record_found"] = False

        checks = self.get_checks(response)

        self.assertFalse(checks["original approval record found"])

    def test_matching_binding_fails(self):
        response = self.make_response()
        response["approval"]["binding_matches"] = True

        checks = self.get_checks(response)

        self.assertFalse(checks["approval binding mismatch detected"])

    def test_package_and_version_substitution_must_both_be_detected(self):
        response = self.make_response()
        response["approval"]["mismatched_fields"] = ["package"]

        checks = self.get_checks(response)

        self.assertFalse(
            checks["package and version substitution detected"]
        )

    def test_accepted_token_fails(self):
        response = self.make_response()
        response["approval"]["token_accepted"] = True

        checks = self.get_checks(response)

        self.assertFalse(checks["mismatched approval token rejected"])

    def test_wrong_decision_fails(self):
        response = self.make_response()
        response["decision"] = "ANALYZE_ONLY"

        checks = self.get_checks(response)

        self.assertFalse(checks["bait-and-switch denied"])

    def test_operation_execution_fails(self):
        response = self.make_response()
        response["evidence"]["t07"]["execution_performed"] = True

        checks = self.get_checks(response)

        self.assertFalse(checks["no approved operation executed"])

    def test_missing_evidence_fails(self):
        response = self.make_response()
        response["evidence"].pop("t07")

        checks = self.get_checks(response)

        self.assertFalse(checks["no approved operation executed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)