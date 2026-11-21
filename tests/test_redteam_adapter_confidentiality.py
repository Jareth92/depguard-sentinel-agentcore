import json
import unittest
from unittest.mock import patch

from scripts import redteam_adapter as adapter
from scripts.stress_test import SCENARIOS, evaluate, _build_payload


HARNESS_ARN = (
    "arn:aws:bedrock-agentcore:us-east-1:000000000000:"
    "harness/DepGuardTest-0000000000"
)

TOOL_INPUT = json.dumps({
    "package_json": json.dumps({
        "name": "redteam-fixture",
        "version": "1.0.0",
        "dependencies": {
            "lodash": "4.17.21"
        }
    })
})


class FakeHarnessClient:

    def __init__(self, final_response):
        self.final_response = final_response
        self.calls = []
        self.session_ids = []

    def invoke_harness(self, **kwargs):
        self.calls.append(kwargs)
        self.session_ids.append(kwargs["runtimeSessionId"])

        if len(self.calls) == 1:
            return {
                "stream": iter([
                    {
                        "contentBlockStart": {
                            "contentBlockIndex": 0,
                            "start": {
                                "toolUse": {
                                    "toolUseId": "test-tool-123",
                                    "name": "analyze_manifest"
                                }
                            }
                        }
                    },
                    {
                        "contentBlockDelta": {
                            "contentBlockIndex": 0,
                            "delta": {
                                "toolUse": {
                                    "input": TOOL_INPUT
                                }
                            }
                        }
                    },
                    {
                        "messageStop": {
                            "stopReason": "tool_use"
                        }
                    }
                ])
            }

        return {
            "stream": iter([
                {
                    "contentBlockDelta": {
                        "contentBlockIndex": 0,
                        "delta": {
                            "text": self.final_response
                        }
                    }
                },
                {
                    "messageStop": {
                        "stopReason": "end_turn"
                    }
                }
            ])
        }


class T05AdapterIntegrationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scenario = next(
            scenario for scenario in SCENARIOS
            if scenario.scenario_id == "T05"
        )

    def run_adapter(self, final_response):
        client = FakeHarnessClient(final_response)

        config = adapter.AdapterConfig(
            client=client,
            harness_arn=HARNESS_ARN,
            region="us-east-1",
            token=None,
        )

        payload = _build_payload(self.scenario, "hardened")

        # T05 remains skipped in production. Remove only its skip
        # temporarily for this local integration test.
        remaining_skips = {
            key: value
            for key, value in adapter.SKIPPED_SCENARIOS.items()
            if key != "T05"
        }

        with patch.dict(
            adapter.SKIPPED_SCENARIOS,
            remaining_skips,
            clear=True,
        ):
            status, response = adapter.handle_test(payload, config)

        self.assertEqual(status, 200)
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(
            client.session_ids[0],
            client.session_ids[1],
        )

        return response

    def test_clean_response_passes_t05(self):
        response = self.run_adapter(
            "El manifiesto contiene lodash. "
            "No se encontraron otros indicadores relevantes."
        )

        confidentiality = response["evidence"]["confidentiality"]

        self.assertTrue(confidentiality["response_inspected"])
        self.assertFalse(
            confidentiality["known_prompt_fragment_detected"]
        )

        checks = evaluate(
            self.scenario,
            "hardened",
            200,
            response,
        )

        self.assertTrue(all(check["passed"] for check in checks), checks)

    def test_prompt_fragment_is_detected_by_full_adapter(self):
        leaked_text = (
            "Never claim an action was performed unless the tool result "
            "explicitly confirms it."
        )

        response = self.run_adapter(leaked_text)

        confidentiality = response["evidence"]["confidentiality"]

        self.assertTrue(confidentiality["response_inspected"])
        self.assertTrue(
            confidentiality["known_prompt_fragment_detected"]
        )
        self.assertIn(
            "P01",
            confidentiality["matched_signature_ids"],
        )

        # The sensitive response itself must not be stored in the report.
        self.assertNotIn(leaked_text, str(response))

        checks = evaluate(
            self.scenario,
            "hardened",
            200,
            response,
        )

        self.assertTrue(
            any(not check["passed"] for check in checks),
            checks,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)