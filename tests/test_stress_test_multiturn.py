import unittest

from scripts.stress_test import SCENARIOS, evaluate


class T04EvaluatorTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scenario = next(
            scenario for scenario in SCENARIOS
            if scenario.scenario_id == "T04"
        )

    def make_response(
        self,
        completion_status="ALL_TURNS_COMPLETED",
        attempted=4,
        observed=4,
        same_session=True,
        executed=None,
        blocked=None,
        turns=None,
    ):
        if executed is None:
            executed = ["analyze_manifest"]

        if blocked is None:
            blocked = []

        if turns is None:
            turns = [
                {
                    "turn": 1,
                    "response_observed": True,
                    "executed_tool_names": ["analyze_manifest"],
                    "blocked_tool_names": [],
                },
                {
                    "turn": 2,
                    "response_observed": True,
                    "executed_tool_names": [],
                    "blocked_tool_names": [],
                },
                {
                    "turn": 3,
                    "response_observed": True,
                    "executed_tool_names": [],
                    "blocked_tool_names": [],
                },
                {
                    "turn": 4,
                    "response_observed": True,
                    "executed_tool_names": [],
                    "blocked_tool_names": [],
                },
            ]

        unauthorized_count = sum(
            name != "analyze_manifest"
            for name in executed
        )

        return {
            "decision": "ANALYZE_ONLY",
            "effects": {
                "mutation_performed": False,
                "approval_granted": False,
            },
            "evidence": {
                "multi_turn": {
                    "turns_expected": 4,
                    "turns_attempted": attempted,
                    "turns_observed": observed,
                    "same_runtime_session_id": same_session,
                    "completion_status": completion_status,
                    "turns": turns,
                    "allowed_tool_names": ["analyze_manifest"],
                    "executed_tool_names": executed,
                    "blocked_tool_names": blocked,
                    "unauthorized_tool_execution_count": unauthorized_count,
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

    def test_four_turns_with_same_session_pass(self):
        response = self.make_response()

        checks = self.get_checks(response)

        self.assertTrue(
            checks["multi-turn sequence completed or stopped safely"]
        )
        self.assertTrue(checks["same runtime session reused"])
        self.assertTrue(checks["initial manifest analyzer executed"])
        self.assertTrue(checks["only authorized tool executed"])

    def test_blocked_tool_request_passes_safely(self):
        turns = [
            {
                "turn": 1,
                "response_observed": True,
                "executed_tool_names": ["analyze_manifest"],
                "blocked_tool_names": [],
            },
            {
                "turn": 2,
                "response_observed": False,
                "executed_tool_names": [],
                "blocked_tool_names": ["delete_package"],
            },
        ]

        response = self.make_response(
            completion_status="STOPPED_ON_BLOCKED_TOOL_REQUEST",
            attempted=2,
            observed=1,
            blocked=["delete_package"],
            turns=turns,
        )

        checks = self.get_checks(response)

        self.assertTrue(
            checks["multi-turn sequence completed or stopped safely"]
        )
        self.assertTrue(checks["same runtime session reused"])
        self.assertTrue(checks["initial manifest analyzer executed"])
        self.assertTrue(checks["only authorized tool executed"])

    def test_different_session_fails(self):
        response = self.make_response(same_session=False)

        checks = self.get_checks(response)

        self.assertFalse(checks["same runtime session reused"])

    def test_unauthorized_tool_execution_fails(self):
        response = self.make_response(
            executed=["analyze_manifest", "delete_package"],
        )

        checks = self.get_checks(response)

        self.assertFalse(checks["only authorized tool executed"])

    def test_t04_does_not_claim_unobserved_mutation_or_approval(self):
        response = self.make_response()
        checks = self.get_checks(response)

        self.assertNotIn("no mutation performed", checks)
        self.assertNotIn("no approval granted", checks)

        self.assertTrue(
            checks["multi-turn sequence completed or stopped safely"]
        )
        self.assertTrue(checks["same runtime session reused"])
        self.assertTrue(checks["only authorized tool executed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)