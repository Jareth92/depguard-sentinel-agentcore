import json
import unittest
from unittest.mock import patch

from scripts import redteam_adapter as adapter
from scripts.stress_test import SCENARIOS, _build_payload


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


def tool_use_response(name, tool_id, tool_input="{}"):
    return {
        "stream": iter([
            {
                "contentBlockStart": {
                    "contentBlockIndex": 0,
                    "start": {
                        "toolUse": {
                            "toolUseId": tool_id,
                            "name": name,
                        }
                    }
                }
            },
            {
                "contentBlockDelta": {
                    "contentBlockIndex": 0,
                    "delta": {
                        "toolUse": {
                            "input": tool_input
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


def final_response(text):
    return {
        "stream": iter([
            {
                "contentBlockDelta": {
                    "contentBlockIndex": 0,
                    "delta": {
                        "text": text
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


class FakeMultiTurnHarnessClient:

    def __init__(self, block_on_call=None):
        self.calls = []
        self.session_ids = []
        self.block_on_call = block_on_call

    def invoke_harness(self, **kwargs):
        self.calls.append(kwargs)
        self.session_ids.append(kwargs["runtimeSessionId"])

        call_number = len(self.calls)

        # First turn: request the permitted manifest analyzer.
        if call_number == 1:
            return tool_use_response(
                "analyze_manifest",
                "allowed-tool-001",
                TOOL_INPUT,
            )

        # Optional adversarial test: request an unauthorized tool.
        if call_number == self.block_on_call:
            return tool_use_response(
                "delete_package",
                "unauthorized-tool-001",
            )

        return final_response(
            "No puedo realizar instalaciones, eliminaciones ni "
            "modificaciones externas. El análisis es de solo lectura."
        )


class T04MultiTurnAdapterTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.scenario = next(
            scenario for scenario in SCENARIOS
            if scenario.scenario_id == "T04"
        )

    def run_adapter(self, block_on_call=None):
        client = FakeMultiTurnHarnessClient(
            block_on_call=block_on_call
        )

        config = adapter.AdapterConfig(
            client=client,
            harness_arn=HARNESS_ARN,
            region="us-east-1",
            token=None,
        )

        payload = _build_payload(
            self.scenario,
            "hardened",
        )

        # T04 remains skipped in production until the tests pass.
        # Remove only its skip for this local integration test.
        remaining_skips = {
            key: value
            for key, value in adapter.SKIPPED_SCENARIOS.items()
            if key != "T04"
        }

        with patch.dict(
            adapter.SKIPPED_SCENARIOS,
            remaining_skips,
            clear=True,
        ):
            status, response = adapter.handle_test(
                payload,
                config,
            )

        self.assertEqual(status, 200)

        # Verify the actual IDs passed to the fake Harness client.
        self.assertGreaterEqual(len(client.session_ids), 2)
        self.assertEqual(
            len(set(client.session_ids)),
            1,
            "All Harness API calls must reuse the same session ID.",
        )

        return client, response

    def test_all_four_turns_use_the_same_session(self):
        client, response = self.run_adapter()

        evidence = response["evidence"]["multi_turn"]

        self.assertEqual(len(client.calls), 5)
        self.assertEqual(evidence["turns_expected"], 4)
        self.assertEqual(evidence["turns_attempted"], 4)
        self.assertEqual(evidence["turns_observed"], 4)
        self.assertTrue(evidence["same_runtime_session_id"])
        self.assertEqual(
            evidence["completion_status"],
            "ALL_TURNS_COMPLETED",
        )

        self.assertEqual(
            evidence["executed_tool_names"],
            ["analyze_manifest"],
        )
        self.assertEqual(
            evidence["unauthorized_tool_execution_count"],
            0,
        )

        self.assertTrue(
            all(
                turn["response_observed"] is True
                for turn in evidence["turns"]
            )
        )

    def test_unauthorized_tool_request_is_blocked(self):
        # Calls 1 and 2 complete the initial analyzer handoff.
        # Call 3 is the second conversation turn and requests deletion.
        client, response = self.run_adapter(block_on_call=3)

        evidence = response["evidence"]["multi_turn"]

        self.assertEqual(len(client.calls), 3)
        self.assertEqual(evidence["turns_expected"], 4)
        self.assertEqual(evidence["turns_attempted"], 2)
        self.assertEqual(evidence["turns_observed"], 1)
        self.assertTrue(evidence["same_runtime_session_id"])

        self.assertEqual(
            evidence["completion_status"],
            "STOPPED_ON_BLOCKED_TOOL_REQUEST",
        )

        self.assertIn(
            "delete_package",
            evidence["blocked_tool_names"],
        )

        # Only analyze_manifest was actually executed.
        self.assertEqual(
            evidence["executed_tool_names"],
            ["analyze_manifest"],
        )

        self.assertEqual(
            response["blocked_attempts_count"],
            1,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)