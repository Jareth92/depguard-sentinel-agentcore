"""Minimal, fail-closed client loop for DepGuard Sentinel's inline function.

The Harness stores the pending tool handoff in its runtime session. This module
executes only the explicitly approved local function ``analyze_manifest`` and
returns its structured result using the matching toolUseId and the SAME
runtimeSessionId. It does not execute shell commands or perform mutations.

Python 3.10+. boto3 is required only when invoking the real AWS Harness.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .analyze_manifest import analyze_manifest

_ALLOWED_TOOL_NAME = "analyze_manifest"
_MAX_TOOL_INPUT_BYTES = 256 * 1024
_HARNESS_ARN_RE = re.compile(
    r"^arn:aws:bedrock-agentcore:[a-z0-9-]+:[0-9]{12}:harness/"
    r"[A-Za-z][A-Za-z0-9_]{0,39}-[A-Za-z0-9]{10}$"
)
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{32,99}$")


class HarnessInvocationError(RuntimeError):
    """Raised for an incomplete or unsafe Harness invocation."""


@dataclass
class StreamState:
    text_parts: list[str] = field(default_factory=list)
    stop_reason: str | None = None
    tool_use_id: str | None = None
    tool_name: str | None = None
    tool_block_index: int | None = None
    tool_input_parts: list[str] = field(default_factory=list)
    runtime_error: str | None = None

    @property
    def tool_input(self) -> str:
        return "".join(self.tool_input_parts)

@dataclass
class InvocationTrace:
    """Structured evidence collected during one Harness invocation."""

    tool_requests: list[dict[str, Any]] = field(default_factory=list)
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    blocked_tool_names: list[str] = field(default_factory=list)
    final_stop_reason: str | None = None


def validate_harness_arn(harness_arn: str) -> None:
    if not isinstance(harness_arn, str) or not _HARNESS_ARN_RE.fullmatch(harness_arn):
        raise ValueError("HARNESS_ARN no tiene el formato esperado para un Harness AgentCore.")


def validate_session_id(session_id: str) -> None:
    if not isinstance(session_id, str) or not _SESSION_ID_RE.fullmatch(session_id):
        raise ValueError("runtimeSessionId debe tener entre 33 y 100 caracteres válidos.")


def _append_tool_input(state: StreamState, fragment: str) -> None:
    current_size = sum(len(part.encode("utf-8")) for part in state.tool_input_parts)
    if current_size + len(fragment.encode("utf-8")) > _MAX_TOOL_INPUT_BYTES:
        raise HarnessInvocationError("La entrada de la herramienta excede el límite local de tamaño.")
    state.tool_input_parts.append(fragment)


def consume_stream(events: Iterable[dict[str, Any]]) -> StreamState:
    """Consume one InvokeHarness stream and extracts text or one inline handoff."""
    state = StreamState()
    for event in events:
        if "runtimeClientError" in event:
            error = event.get("runtimeClientError") or {}
            # Avoid echoing arbitrary runtime detail into logs or tool responses.
            state.runtime_error = str(error.get("message", "Runtime client error"))[:300]
            continue
        if "validationException" in event:
            state.runtime_error = "Harness rejected the invocation input (validation error)."
            continue
        if "internalServerException" in event:
            state.runtime_error = "AgentCore returned an internal server error."
            continue

        start_event = event.get("contentBlockStart")
        if isinstance(start_event, dict):
            start = start_event.get("start", {})
            tool_use = start.get("toolUse") if isinstance(start, dict) else None
            if isinstance(tool_use, dict):
                block_index = start_event.get("contentBlockIndex")
                if state.tool_use_id is not None:
                    raise HarnessInvocationError("Se recibió más de un toolUse en un mismo handoff; se detuvo por seguridad.")
                state.tool_use_id = tool_use.get("toolUseId")
                state.tool_name = tool_use.get("name")
                state.tool_block_index = block_index
                initial_input = tool_use.get("input")
                if isinstance(initial_input, str) and initial_input:
                    _append_tool_input(state, initial_input)

        delta_event = event.get("contentBlockDelta")
        if isinstance(delta_event, dict):
            delta = delta_event.get("delta", {})
            block_index = delta_event.get("contentBlockIndex")
            if isinstance(delta, dict) and isinstance(delta.get("text"), str):
                state.text_parts.append(delta["text"])
            if (
                isinstance(delta, dict)
                and "toolUse" in delta
                and block_index == state.tool_block_index
            ):
                tool_delta = delta.get("toolUse") or {}
                input_part = tool_delta.get("input")
                if isinstance(input_part, str):
                    _append_tool_input(state, input_part)

        message_stop = event.get("messageStop")
        if isinstance(message_stop, dict):
            state.stop_reason = message_stop.get("stopReason")

    if state.runtime_error:
        raise HarnessInvocationError(state.runtime_error)
    return state


def execute_inline_tool(tool_name: str, raw_input: str) -> dict[str, Any]:
    """Execute the sole permitted inline tool and return a safe JSON object."""
    if tool_name != _ALLOWED_TOOL_NAME:
        raise HarnessInvocationError(f"Herramienta no permitida: {tool_name!r}.")
    if not isinstance(raw_input, str):
        raise HarnessInvocationError("La entrada de la herramienta debe ser JSON de texto.")
    if len(raw_input.encode("utf-8")) > _MAX_TOOL_INPUT_BYTES:
        return {
            "status": "REJECTED",
            "decision": "DENY",
            "trust_state": "TAINTED",
            "validation": {
                "input_rejected": True,
                "errors": [{"code": "TOOL_INPUT_TOO_LARGE", "message": "Tool input exceeds the configured size limit."}],
            },
        }
    try:
        arguments = json.loads(raw_input)
    except json.JSONDecodeError:
        return {
            "status": "REJECTED",
            "decision": "DENY",
            "trust_state": "TAINTED",
            "validation": {
                "input_rejected": True,
                "errors": [{"code": "INVALID_TOOL_ARGUMENTS", "message": "Tool arguments must be valid JSON."}],
            },
        }
    if not isinstance(arguments, dict) or set(arguments) != {"package_json"}:
        return {
            "status": "REJECTED",
            "decision": "DENY",
            "trust_state": "TAINTED",
            "validation": {
                "input_rejected": True,
                "errors": [{"code": "INVALID_TOOL_ARGUMENTS", "message": "Expected exactly one argument: package_json."}],
            },
        }
    return analyze_manifest(arguments["package_json"])


def invoke_with_inline_tool(
    client: Any,
    *,
    harness_arn: str,
    runtime_session_id: str,
    prompt: str,
    max_handoffs: int = 3,
    trace: InvocationTrace | None = None,
) -> str:
    """Invoke Harness, resolve analyze_manifest handoffs, and return final text.

    ``client`` is a boto3 bedrock-agentcore data-plane client or a test double.
    The same runtime session ID is used for the first request and every result.
    """
    validate_harness_arn(harness_arn)
    validate_session_id(runtime_session_id)
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("El prompt no puede estar vacío.")
    if not 1 <= max_handoffs <= 10:
        raise ValueError("max_handoffs debe estar entre 1 y 10.")

    messages: list[dict[str, Any]] = [
        {"role": "user", "content": [{"text": prompt}]}
    ]
    final_text: list[str] = []

    for handoff_count in range(max_handoffs + 1):
        response = client.invoke_harness(
            harnessArn=harness_arn,
            runtimeSessionId=runtime_session_id,
            messages=messages,
        )
        stream = response.get("stream")
        if stream is None:
            raise HarnessInvocationError("La respuesta de InvokeHarness no contiene un stream.")

        state = consume_stream(stream)

        if state.stop_reason == "tool_use":
            # Discard intermediate assistant text from tool handoff turns.
            # Only the final assistant response is intended for the caller.
            pass

        elif state.stop_reason in {"end_turn", "stop_sequence"}:
            if trace is not None:
                trace.final_stop_reason = state.stop_reason

            final_text.extend(state.text_parts)
            return "".join(final_text).strip()

        else:
            raise HarnessInvocationError(
                f"Harness terminó con un stopReason no satisfactorio: "
                f"{state.stop_reason!r}."
            )

        if trace is not None:
            trace.tool_requests.append({
                "tool_name": state.tool_name,
                "tool_use_id": state.tool_use_id,
                "input_bytes": len(state.tool_input.encode("utf-8")),
            })

        if handoff_count >= max_handoffs:
            raise HarnessInvocationError("Se alcanzó el máximo local de handoffs inline.")
        if not state.tool_use_id or not state.tool_name:
            raise HarnessInvocationError("El handoff no contiene toolUseId/nombre de herramienta.")
        if state.tool_name != _ALLOWED_TOOL_NAME:
            if trace is not None:
                trace.blocked_tool_names.append(state.tool_name)
            # Fail closed: do not send a result for an unexpected tool and do not execute it.
            raise HarnessInvocationError(f"La herramienta solicitada no está permitida: {state.tool_name!r}.")

        try:
            tool_result = execute_inline_tool(state.tool_name, state.tool_input)
        except HarnessInvocationError:
            raise
        except Exception:
            # Never pass stack traces or internal exceptions to the model.
            tool_result = {
                "status": "ERROR",
                "decision": "DENY",
                "trust_state": "TAINTED",
                "validation": {
                    "input_rejected": True,
                    "errors": [{"code": "TOOL_EXECUTION_ERROR", "message": "The local analysis tool could not complete safely."}],
                },
            }

        if trace is not None:
            trace.tool_results.append({
                "tool_name": state.tool_name,
                "tool_use_id": state.tool_use_id,
                "result": tool_result,
            })

        # The harness correlates this result to its stored pending toolUse. Reuse
        # the same runtimeSessionId and send only the matching toolResult message.
        messages = [{
            "role": "user",
            "content": [{
                "toolResult": {
                    "toolUseId": state.tool_use_id,
                    "content": [{"text": json.dumps(tool_result, ensure_ascii=False, separators=(",", ":"))}],
                    "status": "success",
                }
            }],
        }]

        if trace is not None:
            trace.final_stop_reason = state.stop_reason

    raise HarnessInvocationError("El ciclo de invocación terminó inesperadamente.")
