import json
import unittest
from unittest.mock import patch

from scripts.stress_test import SCENARIOS, run_case


class StressTestEvidenceTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scenario = next(
            scenario for scenario in SCENARIOS
            if scenario.scenario_id == "T01"
        )

    def test_preserves_safe_execution_trace(self):
        attacker_marker = "DO_NOT_PERSIST_RAW_TOOL_ARGUMENTS"

        response = {
            "decision": "ANALYZE_ONLY",
            "trust_state": "TAINTED",
            "effects": {
                "mutation_performed": False,
                "approval_granted": False,
            },
            "evidence": {
                "source": "DepGuard Sentinel local adapter",
                "scope": "read-only analyze_manifest",
                "mutation_and_approval_basis": "Read-only allowlist",
                "tool_requests": [
                    {
                        "tool_name": "analyze_manifest",
                        "tool_use_id_present": True,
                        "input_bytes": 120,
                    }
                ],
                "tool_results": [
                    {
                        "tool_name": "analyze_manifest",
                        "status": "OK",
                        "decision": "ANALYZE_ONLY",
                        "trust_state": "TAINTED",
                        "dependency_count": 1,
                        "suspicious_content_detected": False,
                        "finding_codes": [],
                        "validation_error_codes": [],
                    }
                ],
                "blocked_tool_names": ["delete_package"],
                "final_stop_reason": "end_turn",

                # This must never enter the report.
                "raw_tool_arguments": attacker_marker,
            },
        }

        with patch(
            "scripts.stress_test._post_json",
            return_value=(200, response, 12.5),
        ):
            result = run_case(
                self.scenario,
                "hardened",
                "http://127.0.0.1:8787/redteam/test",
                30,
                None,
            )

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["decision"], "ANALYZE_ONLY")

        evidence = result["evidence"]

        self.assertEqual(
            evidence["tool_requests"],
            response["evidence"]["tool_requests"],
        )
        self.assertEqual(
            evidence["tool_results"],
            response["evidence"]["tool_results"],
        )
        self.assertEqual(
            evidence["blocked_tool_names"],
            ["delete_package"],
        )
        self.assertEqual(
            evidence["final_stop_reason"],
            "end_turn",
        )

        serialized = json.dumps(result)

        self.assertNotIn(attacker_marker, serialized)
        self.assertNotIn("raw_tool_arguments", evidence)

    def test_preserves_scenario_specific_evidence(self):
        specialized = {
            "multi_turn": {"turns_expected": 4},
            "confidentiality": {
                "response_inspected": True,
                "known_prompt_fragment_detected": False,
            },
            "t07": {"execution_performed": False},
            "t08": {"manifest_rejected": True},
        }

        response = {
            "decision": "ANALYZE_ONLY",
            "trust_state": "TAINTED",
            "effects": {
                "mutation_performed": False,
                "approval_granted": False,
            },
            "evidence": specialized,
        }

        with patch(
            "scripts.stress_test._post_json",
            return_value=(200, response, 10.0),
        ):
            result = run_case(
                self.scenario,
                "hardened",
                "http://127.0.0.1:8787/redteam/test",
                30,
                None,
            )

        self.assertEqual(result["status"], "PASS")

        for key, value in specialized.items():
            with self.subTest(evidence_field=key):
                self.assertEqual(result["evidence"][key], value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
