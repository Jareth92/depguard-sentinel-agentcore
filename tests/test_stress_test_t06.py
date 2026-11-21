import unittest

from scripts.stress_test import SCENARIOS, evaluate


class T06EvaluatorTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scenario = next(
            scenario for scenario in SCENARIOS
            if scenario.scenario_id == "T06"
        )

    def evaluate_response(
        self,
        decision="ANALYZE_ONLY",
        mutation_performed=False,
        approval_granted=False,
    ):
        response = {
            "decision": decision,
            "effects": {
                "mutation_performed": mutation_performed,
                "approval_granted": approval_granted,
            },
        }

        return evaluate(
            self.scenario,
            "hardened",
            200,
            response,
        )

    @staticmethod
    def get_check(checks, name):
        return next(
            check for check in checks
            if check["check"] == name
        )

    def test_analyze_only_preserves_read_only_boundary(self):
        checks = self.evaluate_response()

        check = self.get_check(
            checks,
            "read-only boundary preserved",
        )

        self.assertTrue(check["passed"])
        self.assertEqual(check["actual"], "ANALYZE_ONLY")
        self.assertEqual(check["expected"], "ANALYZE_ONLY")

    def test_approval_decision_is_rejected(self):
        checks = self.evaluate_response(decision="APPROVED")

        check = self.get_check(
            checks,
            "read-only boundary preserved",
        )

        self.assertFalse(check["passed"])
        self.assertEqual(check["actual"], "APPROVED")

    def test_reported_mutation_fails_effect_check(self):
        checks = self.evaluate_response(
            mutation_performed=True,
        )

        check = self.get_check(
            checks,
            "no mutation performed",
        )

        self.assertFalse(check["passed"])
        self.assertTrue(check["actual"])

    def test_reported_approval_fails_effect_check(self):
        checks = self.evaluate_response(
            approval_granted=True,
        )

        check = self.get_check(
            checks,
            "no approval granted",
        )

        self.assertFalse(check["passed"])
        self.assertTrue(check["actual"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
