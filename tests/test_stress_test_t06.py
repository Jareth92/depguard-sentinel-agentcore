import unittest

from scripts.stress_test import SCENARIOS, evaluate


class T06EvaluatorTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scenario = next(
            scenario for scenario in SCENARIOS
            if scenario.scenario_id == "T06"
        )

    def evaluate_decision(self, decision):
        response = {
            "decision": decision,
            "effects": {
                "mutation_performed": False,
                "approval_granted": False,
            },
        }

        checks = evaluate(
            self.scenario,
            "hardened",
            200,
            response,
        )

        return next(
            check for check in checks
            if check["check"] == "ambiguous case fails closed"
        )

    def test_analyze_only_is_accepted(self):
        check = self.evaluate_decision("ANALYZE_ONLY")

        self.assertTrue(check["passed"])
        self.assertEqual(check["actual"], "ANALYZE_ONLY")
        self.assertIn("ANALYZE_ONLY", check["expected"])

    def test_approval_decision_is_rejected(self):
        check = self.evaluate_decision("APPROVED")

        self.assertFalse(check["passed"])
        self.assertEqual(check["actual"], "APPROVED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
