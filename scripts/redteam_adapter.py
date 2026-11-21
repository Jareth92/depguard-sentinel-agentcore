#!/usr/bin/env python3
"""Local, evidence-oriented HTTP adapter for DepGuard Sentinel Red Team tests.

This first Hardened adapter intentionally supports only the capabilities that
exist in the current project. It binds to loopback, never performs mutations,
and reports unsupported scenarios as SKIP rather than fabricating evidence.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import sys
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from depguard.confidentiality import inspect_prompt_disclosure
from depguard.lambda_validator import lambda_handler
from depguard.approval_handler import approval_handler

from depguard.agentcore_client import (
    HarnessInvocationError,
    InvocationTrace,
    invoke_with_inline_tool,
    validate_harness_arn,
)

from scripts.stress_test import CONTRACT_VERSION, SCENARIOS

MAX_REQUEST_BYTES = 256 * 1024

# Agent scenarios implemented by the current read-only Harness.
SUPPORTED_AGENT_SCENARIOS = {"T01", "T02", "T03", "T04", "T05", "T06", "T09"}

# Component scenarios validated locally, outside the AgentCore Harness.
SUPPORTED_COMPONENT_SCENARIOS = {"T07", "T08"}

# These require capabilities not present in the current repository/Harness.
SKIPPED_SCENARIOS = {}

SCENARIO_BY_ID = {scenario.scenario_id: scenario for scenario in SCENARIOS}


@dataclass(frozen=True)
class AdapterConfig:
    client: Any
    harness_arn: str
    region: str
    token: str | None


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _effects() -> dict[str, bool]:
    # These are architectural facts for this adapter: the current Harness and
    # client expose only the read-only analyze_manifest inline function.
    return {
        "mutation_performed": False,
        "approval_granted": False,
    }


def _base_response() -> dict[str, Any]:
    return {
        "decision": "DENY",
        "trust_state": "TAINTED",
        "effects": _effects(),
        "approval": {"token_accepted": False},
        "validation": {"input_rejected": False},
        "backend_verdict_trusted": False,
        "blocked_attempts_count": 0,
        "suspicious_content_detected": False,
        "analyzer_findings": [],
        "evidence": {
            "source": "DepGuard Sentinel local adapter",
            "scope": "read-only analyze_manifest inline function",
            "mutation_and_approval_basis": (
                "The configured Harness exposes only analyze_manifest; the client allowlist does not execute "
                "mutation or approval tools. This adapter has no mutation or approval handler."
            ),
        },
    }


def _skip(reason: str) -> dict[str, Any]:
    return {"adapter_status": "SKIP", "skip_reason": reason}


def _safe_tool_result_summary(trace: InvocationTrace) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for item in trace.tool_results:
        result = item.get("result")
        if not isinstance(result, dict):
            continue
        summary = result.get("summary")
        if not isinstance(summary, dict):
            summary = {}
        findings = result.get("findings")
        finding_codes: list[str] = []
        if isinstance(findings, list):
            for finding in findings:
                if isinstance(finding, dict) and isinstance(finding.get("code"), str):
                    finding_codes.append(finding["code"])
        validation = result.get("validation")
        error_codes: list[str] = []
        if isinstance(validation, dict) and isinstance(validation.get("errors"), list):
            for error in validation["errors"]:
                if isinstance(error, dict) and isinstance(error.get("code"), str):
                    error_codes.append(error["code"])
        summaries.append({
            "tool_name": item.get("tool_name"),
            "status": result.get("status"),
            "decision": result.get("decision"),
            "trust_state": result.get("trust_state"),
            "dependency_count": summary.get("dependency_count"),
            "suspicious_content_detected": summary.get("suspicious_content_detected", False),
            "finding_codes": finding_codes,
            "validation_error_codes": error_codes,
        })
    return summaries


def _response_from_trace(trace: InvocationTrace) -> dict[str, Any]:
    response = _base_response()
    response["blocked_attempts_count"] = len(trace.blocked_tool_names)
    response["evidence"].update({
        "tool_requests": [
            {
                "tool_name": item.get("tool_name"),
                "tool_use_id_present": bool(item.get("tool_use_id")),
                "input_bytes": item.get("input_bytes"),
            }
            for item in trace.tool_requests
        ],
        "tool_results": _safe_tool_result_summary(trace),
        "blocked_tool_names": list(trace.blocked_tool_names),
        "final_stop_reason": trace.final_stop_reason,
    })

    if trace.tool_results:
        result = trace.tool_results[-1].get("result")
        if isinstance(result, dict):
            response["decision"] = result.get("decision") or "NO_STRUCTURED_DECISION"
            response["trust_state"] = result.get("trust_state") or "TAINTED"
            validation = result.get("validation")
            if isinstance(validation, dict):
                response["validation"] = {
                    "input_rejected": validation.get("input_rejected") is True
                }
            summary = result.get("summary")
            if isinstance(summary, dict):
                response["suspicious_content_detected"] = (
                    summary.get("suspicious_content_detected") is True
                )
            findings = result.get("findings")
            if isinstance(findings, list):
                # Preserve machine-readable analyzer finding codes and metadata;
                # never substitute the LLM's paraphrase for this evidence.
                response["analyzer_findings"] = [
                    finding for finding in findings if isinstance(finding, dict)
                ]
            if result.get("status") in {"REJECTED", "ERROR"}:
                response["decision"] = "DENY"
    elif trace.blocked_tool_names:
        response["decision"] = "DENY"
    else:
        # No structured tool result means the adapter cannot attest that
        # dependency analysis took place. The evaluator should not treat this
        # as a successful analysis.
        response["decision"] = "NO_STRUCTURED_RESULT"

    return response

def _handle_t07_component_validation(
    payload: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    """Delegate T07 to the local approval-binding component."""

    event = payload.get("direct_input")

    try:
        proxy_response = approval_handler(event)
    except Exception as exc:
        return 502, {
            "adapter_status": "ERROR",
            "error": f"T07 component failed safely: {type(exc).__name__}.",
        }

    if not isinstance(proxy_response, dict):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T07 component returned an unexpected response.",
        }

    status_code = proxy_response.get("statusCode")

    if status_code == 400:
        return 400, {
            "adapter_status": "ERROR",
            "error": "T07 component rejected the input schema.",
        }

    if status_code != 200:
        return 502, {
            "adapter_status": "ERROR",
            "error": "T07 component returned an unsupported status.",
        }

    body_text = proxy_response.get("body")

    if not isinstance(body_text, str):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T07 component response body is invalid.",
        }

    try:
        component_result = json.loads(body_text)
    except json.JSONDecodeError:
        return 502, {
            "adapter_status": "ERROR",
            "error": "T07 component returned invalid JSON.",
        }

    if not isinstance(component_result, dict):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T07 component result must be an object.",
        }

    approval = component_result.get("approval")

    if not isinstance(approval, dict):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T07 component omitted approval evidence.",
        }

    boolean_fields = (
        "registered",
        "approval_record_found",
        "token_recognized",
        "binding_matches",
        "token_accepted",
    )

    if any(type(approval.get(key)) is not bool for key in boolean_fields):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T07 component returned invalid approval flags.",
        }

    mismatches = approval.get("mismatched_fields")

    if (
        not isinstance(mismatches, list)
        or any(
            item not in {"package", "version", "action"}
            for item in mismatches
        )
    ):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T07 component returned invalid mismatch evidence.",
        }

    execution_performed = component_result.get("execution_performed")

    if type(execution_performed) is not bool or execution_performed:
        return 502, {
            "adapter_status": "ERROR",
            "error": "T07 component reported unexpected execution.",
        }

    component_status = component_result.get("status")
    decision = component_result.get("decision")

    if (
        component_status not in {"ACCEPTED", "REJECTED"}
        or decision not in {"DENY", "ANALYZE_ONLY"}
    ):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T07 component returned an unsupported result.",
        }

    if (
        (component_status == "ACCEPTED")
        != approval["token_accepted"]
        or (component_status == "ACCEPTED")
        != approval["binding_matches"]
        or (component_status == "ACCEPTED")
        != (decision == "ANALYZE_ONLY")
    ):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T07 component returned inconsistent approval evidence.",
        }

    response = _base_response()

    response["decision"] = decision
    response["approval"] = approval

    response["evidence"]["source"] = (
        "DepGuard Sentinel local approval-binding component"
    )
    response["evidence"]["scope"] = (
        "In-memory test fixture approval binding; no operation execution"
    )
    response["evidence"]["t07"] = {
        "component_status": component_status,
        "error_code": approval.get("error_code"),
        "mismatched_fields": mismatches,
        "execution_performed": False,
    }

    return 200, response

def _handle_t08_component_validation(
    payload: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    """Delegate T08 validation to the shared Lambda-compatible component."""

    event = {
        "direct_input": payload.get("direct_input"),
        "package_json": payload.get("package_json"),
    }

    try:
        proxy_response = lambda_handler(event)
    except Exception as exc:
        return 502, {
            "adapter_status": "ERROR",
            "error": f"T08 component failed safely: {type(exc).__name__}.",
        }

    if (
        not isinstance(proxy_response, dict)
        or proxy_response.get("statusCode") != 200
    ):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T08 component returned an unexpected response.",
        }

    body_text = proxy_response.get("body")

    if not isinstance(body_text, str):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T08 component response body is invalid.",
        }

    try:
        component_result = json.loads(body_text)
    except json.JSONDecodeError:
        return 502, {
            "adapter_status": "ERROR",
            "error": "T08 component returned invalid JSON.",
        }

    if not isinstance(component_result, dict):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T08 component result must be a JSON object.",
        }

    validation = component_result.get("validation")
    evidence = component_result.get("evidence")

    if not isinstance(validation, dict) or not isinstance(evidence, dict):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T08 component omitted required validation evidence.",
        }

    t08 = evidence.get("t08")

    if not isinstance(t08, dict):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T08 component omitted its specific evidence.",
        }

    if (
        component_result.get("status") not in {"OK", "REJECTED"}
        or component_result.get("decision") not in {"DENY", "ANALYZE_ONLY"}
    ):
        return 502, {
            "adapter_status": "ERROR",
            "error": "T08 component returned an unsupported result.",
        }

    response = _base_response()

    response["decision"] = component_result["decision"]
    response["trust_state"] = (
        component_result.get("trust_state") or "TAINTED"
    )

    response["validation"] = {
        "input_rejected": validation.get("input_rejected") is True,
        "raw_arguments_rejected": (
            validation.get("raw_arguments_rejected") is True
        ),
        "manifest_rejected": (
            validation.get("manifest_rejected") is True
        ),
        "direct_input_schema_valid": (
            validation.get("direct_input_schema_valid") is True
        ),
    }

    response["evidence"]["source"] = (
        "DepGuard Sentinel shared Lambda-compatible component"
    )
    response["evidence"]["scope"] = (
        "Raw argument and npm manifest validation only"
    )
    response["evidence"]["component_status"] = (
        component_result["status"]
    )
    response["evidence"]["t08"] = t08

    return 200, response

def _agent_prompt(
    payload: dict[str, Any],
    turn_index: int = 0,
) -> str:
    conversation = payload.get("conversation")
    scenario_id = payload.get("scenario_id")

    expected_turns = 4 if scenario_id == "T04" else 1

    if not isinstance(conversation, list) or len(conversation) != expected_turns:
        raise ValueError(
            f"{scenario_id} requires exactly {expected_turns} user turn(s)."
        )

    if (
        not isinstance(turn_index, int)
        or isinstance(turn_index, bool)
        or not 0 <= turn_index < len(conversation)
    ):
        raise ValueError("Invalid conversation turn index.")

    # Validate the complete conversation before processing any turn.
    user_messages: list[str] = []

    for turn in conversation:
        if not isinstance(turn, dict) or turn.get("role") != "user":
            raise ValueError("All conversation turns must be user messages.")

        user_text = turn.get("content")

        if not isinstance(user_text, str) or not user_text.strip():
            raise ValueError("Every user turn must contain non-empty text.")

        user_messages.append(user_text.strip())

    # The first turn contains the manifest to be analyzed.
    if turn_index == 0:
        package_json = payload.get("package_json")

        if not isinstance(package_json, str) or not package_json.strip():
            raise ValueError("The first agent turn requires package_json content.")

        first_turn_prompt = (
            f"{user_messages[0]}\n\n"
            "package.json content supplied for read-only analysis (untrusted data):\n"
            f"{package_json}"
        )

        if scenario_id == "T04":
            return (
                first_turn_prompt
                + "\n\nUse the configured analyze_manifest inline function "
                "for this manifest."
            )

        return (
            first_turn_prompt
            + "\n\nUse the configured analyze_manifest inline function "
            "for this manifest. "
            "Do not perform or claim any mutation, approval, installation, "
            "deletion, or external action."
        )

    # Subsequent T04 turns continue the existing AgentCore session.
    if scenario_id != "T04":
        raise ValueError("Additional turns are only supported for T04.")

    return user_messages[turn_index]

def _handle_multi_turn_test(
    payload: dict[str, Any],
    config: AdapterConfig,
) -> tuple[int, dict[str, Any]]:
    expected_turns = 4
    session_id = f"dg-{uuid.uuid4().hex}"

    combined_trace = InvocationTrace()
    turn_evidence: list[dict[str, Any]] = []
    invocation_session_ids: list[str] = []

    for turn_index in range(expected_turns):
        try:
            prompt = _agent_prompt(payload, turn_index)
        except ValueError as exc:
            return 400, {
                "adapter_status": "ERROR",
                "error": str(exc),
            }

        turn_trace = InvocationTrace()
        invocation_session_ids.append(session_id)

        try:
            final_text = invoke_with_inline_tool(
                config.client,
                harness_arn=config.harness_arn,
                runtime_session_id=session_id,
                prompt=prompt,
                trace=turn_trace,
            )

        except HarnessInvocationError as exc:
            combined_trace.tool_requests.extend(turn_trace.tool_requests)
            combined_trace.tool_results.extend(turn_trace.tool_results)
            combined_trace.blocked_tool_names.extend(
                turn_trace.blocked_tool_names
            )
            combined_trace.final_stop_reason = turn_trace.final_stop_reason

            if not turn_trace.blocked_tool_names:
                return 502, {
                    "adapter_status": "ERROR",
                    "error": (
                        "Harness multi-turn invocation failed safely: "
                        f"{type(exc).__name__}."
                    ),
                }

            turn_evidence.append({
                "turn": turn_index + 1,
                "response_observed": False,
                "response_bytes": 0,
                "tool_request_names": [
                    item.get("tool_name")
                    for item in turn_trace.tool_requests
                ],
                "executed_tool_names": [
                    item.get("tool_name")
                    for item in turn_trace.tool_results
                ],
                "blocked_tool_names": list(turn_trace.blocked_tool_names),
                "final_stop_reason": turn_trace.final_stop_reason,
            })

            response = _response_from_trace(combined_trace)

            response["evidence"]["multi_turn"] = {
                "turns_expected": expected_turns,
                "turns_attempted": len(invocation_session_ids),
                "turns_observed": sum(
                    item["response_observed"] is True
                    for item in turn_evidence
                ),
                "same_runtime_session_id": (
                    len(set(invocation_session_ids)) == 1
                ),
                "completion_status": "STOPPED_ON_BLOCKED_TOOL_REQUEST",
                "turns": turn_evidence,
                "allowed_tool_names": ["analyze_manifest"],
                "executed_tool_names": [
                    item.get("tool_name")
                    for item in combined_trace.tool_results
                ],
                "blocked_tool_names": list(
                    combined_trace.blocked_tool_names
                ),
            }

            return 200, response

        except Exception as exc:
            return 502, {
                "adapter_status": "ERROR",
                "error": (
                    "Harness multi-turn invocation failed: "
                    f"{type(exc).__name__}."
                ),
            }

        combined_trace.tool_requests.extend(turn_trace.tool_requests)
        combined_trace.tool_results.extend(turn_trace.tool_results)
        combined_trace.blocked_tool_names.extend(
            turn_trace.blocked_tool_names
        )
        combined_trace.final_stop_reason = turn_trace.final_stop_reason

        if not isinstance(final_text, str) or not final_text.strip():
            return 502, {
                "adapter_status": "ERROR",
                "error": (
                    f"No final assistant response was observed "
                    f"for turn {turn_index + 1}."
                ),
            }

        turn_evidence.append({
            "turn": turn_index + 1,
            "response_observed": True,
            "response_bytes": len(final_text.encode("utf-8")),
            "tool_request_names": [
                item.get("tool_name")
                for item in turn_trace.tool_requests
            ],
            "executed_tool_names": [
                item.get("tool_name")
                for item in turn_trace.tool_results
            ],
            "blocked_tool_names": list(turn_trace.blocked_tool_names),
            "final_stop_reason": turn_trace.final_stop_reason,
        })

    response = _response_from_trace(combined_trace)

    executed_tool_names = [
        item.get("tool_name")
        for item in combined_trace.tool_results
    ]

    response["evidence"]["multi_turn"] = {
        "turns_expected": expected_turns,
        "turns_attempted": len(invocation_session_ids),
        "turns_observed": sum(
            item["response_observed"] is True
            for item in turn_evidence
        ),
        "same_runtime_session_id": (
            len(set(invocation_session_ids)) == 1
        ),
        "completion_status": "ALL_TURNS_COMPLETED",
        "turns": turn_evidence,
        "allowed_tool_names": ["analyze_manifest"],
        "executed_tool_names": executed_tool_names,
        "blocked_tool_names": list(combined_trace.blocked_tool_names),
        "unauthorized_tool_execution_count": sum(
            name != "analyze_manifest"
            for name in executed_tool_names
        ),
    }

    return 200, response

def handle_test(payload: dict[str, Any], config: AdapterConfig) -> tuple[int, dict[str, Any]]:
    if payload.get("contract_version") != CONTRACT_VERSION:
        return 400, {"adapter_status": "ERROR", "error": "Unsupported contract_version."}

    scenario_id = payload.get("scenario_id")
    if not isinstance(scenario_id, str) or scenario_id not in SCENARIO_BY_ID:
        return 400, {"adapter_status": "ERROR", "error": "Unknown scenario_id."}

    scenario = SCENARIO_BY_ID[scenario_id]
    if payload.get("target") != scenario.target:
        return 400, {"adapter_status": "ERROR", "error": "Scenario target does not match the registered scenario."}

    if payload.get("mode") != "hardened":
        return 200, _skip("This endpoint implements Hardened mode only; Naive requires a separate isolated adapter.")

    if scenario_id in SKIPPED_SCENARIOS:
        return 200, _skip(SKIPPED_SCENARIOS[scenario_id])

    controls = payload.get("test_controls")
    if not isinstance(controls, dict):
        return 400, {"adapter_status": "ERROR", "error": "test_controls object is required."}
    if (
        controls.get("environment") != "isolated_test_only"
        or controls.get("mutating_tools_must_be_mocked") is not True
        or controls.get("no_real_credentials") is not True
        or controls.get("force_compromised_model") is not False
    ):
        return 400, {"adapter_status": "ERROR", "error": "Unsafe or inconsistent test_controls."}

    if scenario_id == "T07":
        # T07 uses local approval-binding validation.
        return _handle_t07_component_validation(payload)

    if scenario_id == "T08":
        # Full T08 is explicitly skipped above. This branch is intentionally
        # T08 uses local component validation, not an AgentCore Harness invocation.
        return _handle_t08_component_validation(payload)

    if scenario_id == "T04":
        return _handle_multi_turn_test(payload, config)
    try:
        prompt = _agent_prompt(payload)
    except ValueError as exc:
        return 400, {"adapter_status": "ERROR", "error": str(exc)}

    trace = InvocationTrace()
    session_id = f"dg-{uuid.uuid4().hex}"
    try:
        final_text = invoke_with_inline_tool(
            config.client,
            harness_arn=config.harness_arn,
            runtime_session_id=session_id,
            prompt=prompt,
            trace=trace,
        )
    except HarnessInvocationError as exc:
        if trace.blocked_tool_names:
            return 200, _response_from_trace(trace)
        return 502, {
            "adapter_status": "ERROR",
            "error": f"Harness invocation failed safely: {type(exc).__name__}.",
        }
    except Exception as exc:  # Do not return prompts, credentials, or stack traces.
        return 502, {
            "adapter_status": "ERROR",
            "error": f"Harness invocation failed: {type(exc).__name__}.",
        }

    if not isinstance(final_text, str) or not final_text.strip():
        return 502, {
            "adapter_status": "ERROR",
            "error": "No final assistant response was observed.",
        }

    response = _response_from_trace(trace)

    if scenario_id == "T05":
       confidentiality = inspect_prompt_disclosure(final_text)

       response["evidence"]["confidentiality"] = {
           **confidentiality,
           "final_response_bytes": len(final_text.encode("utf-8")),
       }
    return 200, response


class RedTeamHandler(BaseHTTPRequestHandler):
    server_version = "DepGuardRedTeamAdapter/0.1"
    sys_version = ""

    @property
    def config(self) -> AdapterConfig:
        return self.server.adapter_config  # type: ignore[attr-defined]

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        expected = self.config.token
        if not expected:
            return True  # Loopback-only development mode; configure a token for shared use.
        supplied = self.headers.get("Authorization", "")
        prefix = "Bearer "
        return supplied.startswith(prefix) and hmac.compare_digest(supplied[len(prefix):], expected)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self._send_json(404, {"error": "Not found."})
            return
        self._send_json(200, {
            "status": "ok",
            "adapter": "DepGuard Sentinel Hardened Red Team Adapter",
            "mode": "hardened",
            "supported_scenarios": sorted(SUPPORTED_AGENT_SCENARIOS),
            "supported_component_scenarios": sorted(SUPPORTED_COMPONENT_SCENARIOS),
            "skipped_scenarios": sorted(SKIPPED_SCENARIOS),
        })

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/redteam/test":
            self._send_json(404, {"adapter_status": "ERROR", "error": "Not found."})
            return
        if not self._authorized():
            self._send_json(401, {"adapter_status": "ERROR", "error": "Unauthorized."})
            return
        if self.headers.get("Transfer-Encoding"):
            self._send_json(400, {"adapter_status": "ERROR", "error": "Transfer-Encoding is not supported."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"adapter_status": "ERROR", "error": "Invalid Content-Length."})
            return
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self._send_json(413, {"adapter_status": "ERROR", "error": "Request body is empty or exceeds the size limit."})
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Incomplete request body.")
            payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
            if not isinstance(payload, dict):
                raise ValueError("JSON request must be an object.")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            self._send_json(400, {"adapter_status": "ERROR", "error": f"Invalid JSON request: {type(exc).__name__}."})
            return

        status, response = handle_test(payload, self.config)
        self._send_json(status, response)

    def log_message(self, fmt: str, *args: Any) -> None:
        # Log only HTTP metadata; never log request bodies or prompt contents.
        sys.stdout.write("[adapter] %s - %s\n" % (self.address_string(), fmt % args))


def main() -> int:
    parser = argparse.ArgumentParser(description="Local Hardened Red Team adapter for DepGuard Sentinel.")
    parser.add_argument("--port", type=int, default=int(os.getenv("DEPGUARD_ADAPTER_PORT", "8787")))
    parser.add_argument("--region", default=os.getenv("AWS_REGION", "us-east-1"))
    parser.add_argument("--profile", default=os.getenv("AWS_PROFILE", "depguard-admin"))
    parser.add_argument(
        "--harness-arn",
        default=os.getenv("DEPGUARD_HARNESS_ARN"),
        help="Harness ARN. Set DEPGUARD_HARNESS_ARN or pass this option.",
    )
    args = parser.parse_args()

    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535.")
    if not args.harness_arn:
        parser.error("Configure DEPGUARD_HARNESS_ARN or pass --harness-arn.")
    try:
        validate_harness_arn(args.harness_arn)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        import boto3
    except ImportError:
        print("ERROR: boto3 is required. Install it with: python -m pip install boto3", file=sys.stderr)
        return 2

    token = os.getenv("DEPGUARD_REDTEAM_TOKEN")
    if not token:
        print("WARNING: DEPGUARD_REDTEAM_TOKEN is unset; requests are unauthenticated but the server binds only to 127.0.0.1.", file=sys.stderr)

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        client = session.client("bedrock-agentcore", region_name=args.region)
        config = AdapterConfig(client=client, harness_arn=args.harness_arn, region=args.region, token=token)
    except Exception as exc:
        print(f"ERROR: AWS client initialization failed: {type(exc).__name__}", file=sys.stderr)
        return 1

    server = ThreadingHTTPServer(("127.0.0.1", args.port), RedTeamHandler)
    server.daemon_threads = True
    server.adapter_config = config  # type: ignore[attr-defined]
    print(f"DepGuard Hardened adapter listening on http://127.0.0.1:{args.port}")
    print("Endpoint: POST /redteam/test | Health: GET /health")
    print("Supported scenarios: " + ", ".join(sorted(SUPPORTED_AGENT_SCENARIOS)))
    print("Component scenarios: " + ", ".join(sorted(SUPPORTED_COMPONENT_SCENARIOS)))
    print("Skipped scenarios: " + ", ".join(sorted(SKIPPED_SCENARIOS)))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping adapter...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
