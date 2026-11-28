"""Local pattern-based sensitive data classification.

This module detects candidate sensitive data patterns without returning
or persisting matched values. It is not a complete DLP solution.
"""

from __future__ import annotations

import re
from typing import Any


MAX_SCAN_BYTES = 256 * 1024

_CLASSIFICATION_RANK = {
    "UNCLASSIFIED": 0,
    "CONFIDENTIAL": 1,
    "RESTRICTED": 2,
}

_PATTERNS: tuple[
    tuple[str, str, str, re.Pattern[str]], ...
] = (
    (
        "PRIVATE_KEY_MARKER",
        "CREDENTIAL_MATERIAL",
        "RESTRICTED",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            re.IGNORECASE,
        ),
    ),
    (
        "AWS_ACCESS_KEY_ID_CANDIDATE",
        "CLOUD_CREDENTIAL_IDENTIFIER",
        "RESTRICTED",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "GITHUB_TOKEN_CANDIDATE",
        "ACCESS_TOKEN",
        "RESTRICTED",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "BEARER_TOKEN_CANDIDATE",
        "ACCESS_TOKEN",
        "RESTRICTED",
        re.compile(
            r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}",
            re.IGNORECASE,
        ),
    ),
    (
        "GENERIC_CREDENTIAL_ASSIGNMENT",
        "CREDENTIAL_MATERIAL",
        "RESTRICTED",
        re.compile(
            r"""["']?\b(?:password|passwd|client[_-]?secret|"""
            r"""api[_-]?key|access[_-]?token|refresh[_-]?token|"""
            r"""(?:aws_)?secret[_-]?access[_-]?key)\b["']?"""
            r"""\s*[:=]\s*["']?([A-Za-z0-9._~+/=-]{8,})""",
            re.IGNORECASE,
        ),
    ),
    (
        "EMAIL_ADDRESS_CANDIDATE",
        "PERSONAL_DATA",
        "CONFIDENTIAL",
        re.compile(
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            re.IGNORECASE,
        ),
    ),
)


def classify_sensitive_data(value: object) -> dict[str, Any]:
    """Classify known sensitive-data patterns without disclosing values.

    Detection is heuristic. A match is a candidate, not proof that a
    credential is valid or that an email address identifies a person.
    No-match results remain UNCLASSIFIED, never PUBLIC.
    """

    if not isinstance(value, str):
        return {
            "input_inspected": False,
            "input_rejected": True,
            "classification": "UNCLASSIFIED",
            "sensitive_data_detected": False,
            "findings": [],
            "reason": "INVALID_INPUT_TYPE",
        }

    input_bytes = len(value.encode("utf-8"))

    if input_bytes > MAX_SCAN_BYTES:
        return {
            "input_inspected": False,
            "input_rejected": True,
            "classification": "UNCLASSIFIED",
            "sensitive_data_detected": False,
            "findings": [],
            "reason": "INPUT_EXCEEDS_MAX_BYTES",
        }

    findings: list[dict[str, Any]] = []

    for code, category, classification, pattern in _PATTERNS:
        match_count = sum(1 for _ in pattern.finditer(value))

        if match_count:
            findings.append({
                "code": code,
                "category": category,
                "classification": classification,
                "match_count": match_count,
            })

    highest_classification = max(
        (
            finding["classification"]
            for finding in findings
        ),
        key=lambda item: _CLASSIFICATION_RANK[item],
        default="UNCLASSIFIED",
    )

    return {
        "input_inspected": True,
        "input_rejected": False,
        "classification": highest_classification,
        "sensitive_data_detected": bool(findings),
        "detection_method": "LOCAL_PATTERN_MATCHING",
        "findings": findings,
    }
