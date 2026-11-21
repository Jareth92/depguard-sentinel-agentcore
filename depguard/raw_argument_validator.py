"""Strict validation for untrusted raw package-name arguments.

This module validates identifiers only. It never executes arguments,
constructs shell commands, accesses paths, or invokes external services.
"""
from __future__ import annotations

import json
from typing import Any

from .analyze_manifest import MAX_PACKAGE_NAME_LENGTH, analyze_manifest

MAX_RAW_ARGUMENTS = 64


def validate_raw_arguments(raw_arguments: Any) -> dict[str, Any]:
    """Validate a bounded list of npm package identifiers."""

    errors: list[dict[str, Any]] = []
    accepted_count = 0
    rejected_count = 0

    if not isinstance(raw_arguments, list):
        errors.append({
            "code": "INVALID_RAW_ARGUMENTS_TYPE",
            "message": "raw_arguments must be a JSON array.",
        })

    elif not raw_arguments:
        errors.append({
            "code": "EMPTY_RAW_ARGUMENTS",
            "message": "At least one package identifier is required.",
        })

    elif len(raw_arguments) > MAX_RAW_ARGUMENTS:
        errors.append({
            "code": "TOO_MANY_RAW_ARGUMENTS",
            "message": "The raw argument count exceeds the configured limit.",
        })
        rejected_count = len(raw_arguments)

    else:
        for index, argument in enumerate(raw_arguments):
            if not isinstance(argument, str):
                errors.append({
                    "index": index,
                    "code": "INVALID_RAW_ARGUMENT_TYPE",
                    "message": "Each package identifier must be a string.",
                })
                rejected_count += 1
                continue

            if len(argument) > MAX_PACKAGE_NAME_LENGTH:
                errors.append({
                    "index": index,
                    "code": "RAW_ARGUMENT_TOO_LONG",
                    "message": "The package identifier exceeds the length limit.",
                })
                rejected_count += 1
                continue

            # Reuse the existing npm package-name validator.
            # The supplied identifier is treated strictly as a JSON key.
            manifest = json.dumps(
                {"dependencies": {argument: "1.0.0"}},
                ensure_ascii=True,
                separators=(",", ":"),
            )

            result = analyze_manifest(manifest)

            validation = result.get("validation", {})
            validation_errors = validation.get("errors", [])

            if (
                result.get("status") == "REJECTED"
                or validation.get("input_rejected") is True
            ):
                rejected_count += 1

                codes = [
                    error.get("code")
                    for error in validation_errors
                    if isinstance(error, dict)
                    and isinstance(error.get("code"), str)
                ]

                errors.append({
                    "index": index,
                    "code": codes[0] if codes else "INVALID_PACKAGE_NAME",
                    "message": "The package identifier was rejected.",
                })
            else:
                accepted_count += 1

    return {
        "status": "REJECTED" if errors else "OK",
        "validation": {
            "input_rejected": bool(errors),
            "errors": errors,
        },
        "summary": {
            "argument_count": (
                len(raw_arguments)
                if isinstance(raw_arguments, list)
                else 0
            ),
            "accepted_count": accepted_count,
            "rejected_count": rejected_count,
        },
        "execution_performed": False,
    }