"""Lambda-compatible entry point for deterministic T08 validation.

This handler validates raw package identifiers and npm manifests.
It never executes arguments or invokes external services.
"""
from __future__ import annotations

import json
from typing import Any

from .analyze_manifest import analyze_manifest
from .raw_argument_validator import validate_raw_arguments


_ALLOWED_EVENT_KEYS = {"direct_input", "package_json"}
_ALLOWED_DIRECT_INPUT_KEYS = {"raw_arguments"}


def _error_codes(validation: Any) -> list[str]:
    if not isinstance(validation, dict):
        return []

    errors = validation.get("errors")

    if not isinstance(errors, list):
        return []

    return [
        item["code"]
        for item in errors
        if isinstance(item, dict)
        and isinstance(item.get("code"), str)
    ]


def _proxy_response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "content-type": "application/json"
        },
        "body": json.dumps(
            body,
            ensure_ascii=True,
            separators=(",", ":"),
        ),
    }


def lambda_handler(
    event: Any,
    context: Any = None,
) -> dict[str, Any]:
    """Validate a direct Lambda event without performing side effects."""

    if not isinstance(event, dict):
        return _proxy_response(400, {
            "status": "REJECTED",
            "error": "EVENT_MUST_BE_OBJECT",
        })

    if set(event.keys()) != _ALLOWED_EVENT_KEYS:
        return _proxy_response(400, {
            "status": "REJECTED",
            "error": "INVALID_EVENT_SCHEMA",
        })

    direct_input = event.get("direct_input")

    schema_valid = (
        isinstance(direct_input, dict)
        and set(direct_input.keys()) == _ALLOWED_DIRECT_INPUT_KEYS
    )

    raw_arguments = (
        direct_input.get("raw_arguments")
        if isinstance(direct_input, dict)
        else None
    )

    raw_result = validate_raw_arguments(raw_arguments)
    manifest_result = analyze_manifest(event.get("package_json"))

    raw_validation = raw_result.get("validation")
    if not isinstance(raw_validation, dict):
        raw_validation = {}

    manifest_validation = manifest_result.get("validation")
    if not isinstance(manifest_validation, dict):
        manifest_validation = {}

    raw_rejected = (
        not schema_valid
        or raw_result.get("status") != "OK"
        or raw_validation.get("input_rejected") is not False
    )

    manifest_rejected = (
        manifest_result.get("status") != "OK"
        or manifest_validation.get("input_rejected") is not False
    )

    input_rejected = raw_rejected or manifest_rejected

    manifest_summary = manifest_result.get("summary")
    if not isinstance(manifest_summary, dict):
        manifest_summary = {}

    result = {
        "status": "REJECTED" if input_rejected else "OK",
        "decision": "DENY" if input_rejected else "ANALYZE_ONLY",
        "trust_state": "TAINTED",
        "validation": {
            "input_rejected": input_rejected,
            "raw_arguments_rejected": raw_rejected,
            "manifest_rejected": manifest_rejected,
            "direct_input_schema_valid": schema_valid,
        },
        "evidence": {
            "t08": {
                "direct_input_schema_valid": schema_valid,
                "raw_arguments": {
                    "status": raw_result.get("status"),
                    "summary": raw_result.get("summary"),
                    "error_codes": _error_codes(raw_validation),
                },
                "manifest": {
                    "status": manifest_result.get("status"),
                    "error_codes": _error_codes(manifest_validation),
                    "dependency_count": manifest_summary.get(
                        "dependency_count"
                    ),
                },
                "execution_performed": False,
            }
        },
    }

    return _proxy_response(200, result)