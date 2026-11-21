from __future__ import annotations

import json
import unittest

from depguard.agentcore_client import (
    HarnessInvocationError,
    InvocationTrace,
    consume_stream,
    execute_inline_tool,
    invoke_with_inline_tool,
    validate_harness_arn,
    validate_session_id,
)

HARNESS_ARN = "arn:aws:bedrock-agentcore:us-east-1:000000000000:harness/DepGuardTest-0000000000"
SESSION_ID = "dg-0123456789abcdef0123456789abcdef"


class AgentCoreClientTests(unittest.TestCase):
    def test_valid_harness_arn(self):
        validate_harness_arn(HARNESS_ARN)

    def test_rejects_malformed_harness_arn(self):
        with self.assertRaises(ValueError):
            validate_harness_arn("arn:aws:bedrock-agentcore:us-east-1:123:harness/not-valid")

    def test_valid_session_id(self):
        validate_session_id(SESSION_ID)

    def test_rejects_short_session_id(self):
        with self.assertRaises(ValueError):
            validate_session_id("too-short")

    def test_consume_stream_collects_text(self):
        state = consume_stream([
            {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "Hola "}}},
            {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "mundo"}}},
            {"messageStop": {"stopReason": "end_turn"}},
        ])
        self.assertEqual("".join(state.text_parts), "Hola mundo")
        self.assertEqual(state.stop_reason, "end_turn")

    def test_consume_stream_collects_inline_tool_input(self):
        state = consume_stream([
            {"contentBlockStart": {"contentBlockIndex": 1, "start": {"toolUse": {"toolUseId": "tool-1", "name": "analyze_manifest"}}}},
            {"contentBlockDelta": {"contentBlockIndex": 1, "delta": {"toolUse": {"input": '{"package_' }}}},
            {"contentBlockDelta": {"contentBlockIndex": 1, "delta": {"toolUse": {"input": 'json":"{}"}' }}}},
            {"messageStop": {"stopReason": "tool_use"}},
        ])
        self.assertEqual(state.tool_use_id, "tool-1")
        self.assertEqual(state.tool_name, "analyze_manifest")
        self.assertEqual(json.loads(state.tool_input), {"package_json": "{}"})
        self.assertEqual(state.stop_reason, "tool_use")

    def test_rejects_multiple_tool_handoffs_in_one_stream(self):
        with self.assertRaises(HarnessInvocationError):
            consume_stream([
                {"contentBlockStart": {"contentBlockIndex": 1, "start": {"toolUse": {"toolUseId": "one", "name": "analyze_manifest"}}}},
                {"contentBlockStart": {"contentBlockIndex": 2, "start": {"toolUse": {"toolUseId": "two", "name": "analyze_manifest"}}}},
            ])

    def test_rejects_oversized_streamed_tool_input(self):
        oversized = "x" * (256 * 1024 + 1)
        with self.assertRaises(HarnessInvocationError):
            consume_stream([
                {"contentBlockStart": {"contentBlockIndex": 1, "start": {"toolUse": {"toolUseId": "tool-big", "name": "analyze_manifest"}}}},
                {"contentBlockDelta": {"contentBlockIndex": 1, "delta": {"toolUse": {"input": oversized}}}},
            ])

    def test_runtime_error_is_surfaced(self):
        with self.assertRaises(HarnessInvocationError):
            consume_stream([{"runtimeClientError": {"message": "test runtime error"}}])

    def test_executes_only_analyze_manifest(self):
        result = execute_inline_tool(
            "analyze_manifest",
            json.dumps({"package_json": '{"dependencies":{"lodash":"4.17.21"}}'}),
        )
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["trust_state"], "TAINTED")

    def test_rejects_unknown_tool(self):
        with self.assertRaises(HarnessInvocationError):
            execute_inline_tool("approve_package", "{}")

    def test_rejects_extra_tool_arguments(self):
        result = execute_inline_tool(
            "analyze_manifest",
            json.dumps({"package_json": "{}", "shell": "whoami"}),
        )
        self.assertEqual(result["status"], "REJECTED")

    def test_invoke_returns_final_text_and_reuses_session_for_handoff(self):
        trace = InvocationTrace()
        tool_input = json.dumps({"package_json": '{"dependencies":{"lodash":"4.17.21"}}'})
        responses = [
            {"stream": iter([
                {"contentBlockStart": {"contentBlockIndex": 0, "start": {"toolUse": {"toolUseId": "tool-123", "name": "analyze_manifest"}}}},
                {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"toolUse": {"input": tool_input}}}},
                {"messageStop": {"stopReason": "tool_use"}},
            ])},
            {"stream": iter([
                {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "Análisis completado."}}},
                {"messageStop": {"stopReason": "end_turn"}},
            ])},
        ]

        class FakeClient:
            def __init__(self):
                self.calls = []

            def invoke_harness(self, **kwargs):
                self.calls.append(kwargs)
                return responses.pop(0)

        fake = FakeClient()
        answer = invoke_with_inline_tool(
            fake,
            harness_arn=HARNESS_ARN,
            runtime_session_id=SESSION_ID,
            prompt="Analiza este manifiesto.",
            trace=trace,
        )
        self.assertEqual(answer, "Análisis completado.")
        self.assertEqual(len(fake.calls), 2)
        self.assertEqual(fake.calls[0]["runtimeSessionId"], SESSION_ID)
        self.assertEqual(fake.calls[1]["runtimeSessionId"], SESSION_ID)
        tool_result = fake.calls[1]["messages"][0]["content"][0]["toolResult"]
        self.assertEqual(tool_result["toolUseId"], "tool-123")
        payload = json.loads(tool_result["content"][0]["text"])
        self.assertEqual(payload["status"], "OK")
        self.assertEqual(len(trace.tool_requests), 1)
        self.assertEqual(trace.tool_requests[0]["tool_name"], "analyze_manifest")
        self.assertEqual(len(trace.tool_results), 1)
        self.assertEqual(trace.tool_results[0]["result"]["status"], "OK")
        self.assertEqual(trace.final_stop_reason, "end_turn")
        self.assertEqual(trace.blocked_tool_names, [])

    def test_invoke_fails_closed_on_unexpected_tool(self):
        trace = InvocationTrace()
        class FakeClient:
            def invoke_harness(self, **kwargs):
                return {"stream": iter([
                    {"contentBlockStart": {"contentBlockIndex": 0, "start": {"toolUse": {"toolUseId": "x", "name": "approve_package"}}}},
                    {"messageStop": {"stopReason": "tool_use"}},
                ])}

        with self.assertRaises(HarnessInvocationError):
            invoke_with_inline_tool(
                FakeClient(),
                harness_arn=HARNESS_ARN,
                runtime_session_id=SESSION_ID,
                prompt="Try a tool.",
                trace=trace
            )

        self.assertEqual(
            trace.blocked_tool_names,
            ["approve_package"]
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
