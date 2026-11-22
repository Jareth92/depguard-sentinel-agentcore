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

    def test_preserves_verified_final_response(self):
        final_response = (
            "The manifest was analyzed in read-only mode. "
            "No approval or mutation was performed."
        )

        response = {
            "decision": "ANALYZE_ONLY",
            "trust_state": "TAINTED",
            "effects": {
                "mutation_performed": False,
                "approval_granted": False,
            },
            "evidence": {
                "final_response": final_response,
                "final_response_capture": {
                    "stored": True,
                    "response_bytes": len(final_response.encode("utf-8")),
                    "reason": "no_known_exact_fragment_detected",
                },
                "known_prompt_fragment_scan": {
                    "response_inspected": True,
                    "known_prompt_fragment_detected": False,
                },
            },
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
        self.assertEqual(
            result["evidence"]["final_response"],
            final_response,
        )

    def test_never_preserves_t05_final_response(self):
        t05 = next(
            scenario for scenario in SCENARIOS
            if scenario.scenario_id == "T05"
        )

        potentially_sensitive_text = (
            "A simulated response that must never enter the T05 report."
        )

        response = {
            "decision": "ANALYZE_ONLY",
            "trust_state": "TAINTED",
            "effects": {
                "mutation_performed": False,
                "approval_granted": False,
            },
            "evidence": {
                "final_response": potentially_sensitive_text,
                "final_response_capture": {
                    "stored": True,
                    "response_bytes": len(
                        potentially_sensitive_text.encode("utf-8")
                    ),
                    "reason": "no_known_exact_fragment_detected",
                },
                "known_prompt_fragment_scan": {
                    "response_inspected": True,
                    "known_prompt_fragment_detected": False,
                },
                "confidentiality": {
                    "response_inspected": True,
                    "known_prompt_fragment_detected": False,
                    "matched_signature_ids": [],
                    "matched_signature_count": 0,
                    "detection_method": (
                        "exact_known_prompt_fragment_match"
                    ),
                },
            },
        }

        with patch(
            "scripts.stress_test._post_json",
            return_value=(200, response, 10.0),
        ):
            result = run_case(
                t05,
                "hardened",
                "http://127.0.0.1:8787/redteam/test",
                30,
                None,
            )

        self.assertEqual(result["status"], "PASS")
        self.assertNotIn(
            "final_response",
            result["evidence"],
        )

        self.assertNotIn(
            potentially_sensitive_text,
            json.dumps(result),
        )

    def test_does_not_preserve_response_outside_capture_scope(self):
        t09 = next(
            scenario for scenario in SCENARIOS
            if scenario.scenario_id == "T09"
        )

        response = {
            "decision": "ANALYZE_ONLY",
            "trust_state": "TAINTED",
            "effects": {
                "mutation_performed": False,
                "approval_granted": False,
            },
            "evidence": {
                "final_response": "T09 response fixture.",
                "final_response_capture": {
                    "stored": True,
                    "response_bytes": len(
                        "T09 response fixture.".encode("utf-8")
                    ),
                    "reason": "no_known_exact_fragment_detected",
                },
                "known_prompt_fragment_scan": {
                    "response_inspected": True,
                    "known_prompt_fragment_detected": False,
                },
            },
        }

        with patch(
            "scripts.stress_test._post_json",
            return_value=(200, response, 10.0),
        ):
            result = run_case(
                t09,
                "hardened",
                "http://127.0.0.1:8787/redteam/test",
                30,
                None,
            )

        self.assertNotIn(
            "final_response",
            result["evidence"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
