"""Read-only, defensive parser for npm package.json manifests.

This module deliberately does not install packages, access the network, invoke
shell commands, read files, or modify external state. The caller supplies the
raw package.json text. Its contents are always treated as untrusted data.

Public API:
    analyze_manifest(package_json: str) -> dict[str, object]

The response is JSON-serializable and includes ``validation.input_rejected``
for direct integration with the DepGuard Sentinel red-team test contract.
Python 3.10+; standard library only.
"""
from __future__ import annotations

import json
import re
from typing import Any

MAX_MANIFEST_BYTES = 256 * 1024
MAX_DEPENDENCIES = 2_000
MAX_PACKAGE_NAME_LENGTH = 214
MAX_SPECIFIER_LENGTH = 256

DEPENDENCY_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)

# npm package names are lowercase. Scoped packages use exactly @scope/name.
# This intentionally rejects paths, ARNs, wildcard package identifiers, and
# shell-like input. It does not reject valid scoped packages.
_UNSCOPED_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$", re.ASCII)
_SCOPED_NAME_RE = re.compile(r"^@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$", re.ASCII)
_EXACT_SEMVER_RE = re.compile(
    r"^[vV]?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",
    re.ASCII,
)
_SEMVER_RANGE_CHARS_RE = re.compile(r"^[vV0-9*xX<>=~^|.,+\-\s]+$", re.ASCII)
_DIST_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$", re.ASCII)
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# These patterns flag suspicious text; they do not make a vulnerability claim.
# Detection is intentionally conservative and produces a review signal only.
_SUSPICIOUS_TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "PROMPT_OVERRIDE_TEXT",
        re.compile(r"\b(ignore|disregard|override)\s+(all\s+)?(previous|prior|system)\s+instructions\b", re.I),
    ),
    ("SYSTEM_NOTE_MARKER", re.compile(r"\[\s*system\s+(note|message|instruction)\s*\]", re.I)),
    ("TOOL_EXECUTION_REQUEST", re.compile(r"\b(run|call|execute)\s+approve_package\s*\(", re.I)),
    ("ALERT_SUPPRESSION_REQUEST", re.compile(r"\b(erase|delete|hide|suppress)\s+(any\s+)?(security\s+)?alert(s)?\b", re.I)),
    ("BACKEND_VERDICT_MIMIC", re.compile(r"\bBACKEND\s+VERDICT\s*:", re.I)),
    ("APPROVAL_CLAIM_MIMIC", re.compile(r"\"approvedBy\"\s*:", re.I)),
)


class _ManifestValidationError(Exception):
    """Internal validation error with a stable machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class _DuplicateJSONKeyError(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKeyError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _reject(code: str, message: str) -> None:
    raise _ManifestValidationError(code, message)


def _validate_package_name(name: Any, *, field_name: str) -> str:
    if not isinstance(name, str):
        _reject("INVALID_PACKAGE_NAME", f"{field_name} must be a string.")
    if not name or len(name) > MAX_PACKAGE_NAME_LENGTH:
        _reject("INVALID_PACKAGE_NAME", f"{field_name} has an invalid length.")
    if _CONTROL_CHARS_RE.search(name) or name != name.strip():
        _reject("INVALID_PACKAGE_NAME", f"{field_name} contains whitespace or control characters.")
    if name.startswith("@"):
        valid = _SCOPED_NAME_RE.fullmatch(name) is not None
    else:
        valid = _UNSCOPED_NAME_RE.fullmatch(name) is not None
    if not valid or name in {".", ".."}:
        _reject("INVALID_PACKAGE_NAME", f"{field_name} is not a valid npm package name.")
    return name


def _classify_specifier(specifier: Any, *, package_name: str) -> tuple[str, bool]:
    """Return (specifier_type, risk_indicator) without resolving/fetching it."""
    if not isinstance(specifier, str):
        _reject(
            "INVALID_PACKAGE_SPECIFIER",
            f"Dependency {package_name!r} must have a string specifier.",
        )
    if not specifier or len(specifier) > MAX_SPECIFIER_LENGTH:
        _reject(
            "INVALID_PACKAGE_SPECIFIER",
            f"Dependency {package_name!r} has an empty or oversized specifier.",
        )
    if _CONTROL_CHARS_RE.search(specifier) or specifier != specifier.strip():
        _reject(
            "INVALID_PACKAGE_SPECIFIER",
            f"Dependency {package_name!r} has whitespace padding or control characters.",
        )

    lowered = specifier.lower()
    external_prefixes = (
        "file:",
        "link:",
        "workspace:",
        "git+",
        "git:",
        "http://",
        "https://",
        "ssh://",
        "github:",
        "gitlab:",
        "bitbucket:",
    )
    if lowered.startswith(external_prefixes):
        # We record the reference as data. This module never fetches or follows it.
        return "NON_REGISTRY_REFERENCE", True

    if lowered.startswith("npm:"):
        alias_target = specifier[4:]
        if not alias_target or "@" not in alias_target:
            _reject(
                "INVALID_PACKAGE_SPECIFIER",
                f"Dependency {package_name!r} has an invalid npm alias specifier.",
            )
        return "NPM_ALIAS", True

    if _EXACT_SEMVER_RE.fullmatch(specifier):
        return "EXACT_VERSION", False

    # npm accepts semver ranges such as ^1.2.3, >=1 <2, 1.x, and *.
    if _SEMVER_RANGE_CHARS_RE.fullmatch(specifier):
        return "SEMVER_RANGE", False

    # Dist-tags (e.g. latest, next, beta) are valid npm specifiers but are
    # mutable references, so surface them as a risk indicator rather than
    # claiming that a specific version is pinned.
    if _DIST_TAG_RE.fullmatch(specifier):
        return "DIST_TAG", True

    _reject(
        "INVALID_PACKAGE_SPECIFIER",
        f"Dependency {package_name!r} has an unsupported specifier format.",
    )
    raise AssertionError("unreachable")


def _iter_string_values(value: Any, path: str = "$", depth: int = 0):
    """Iteratively traverse manifest strings, with a defensive depth bound."""
    stack: list[tuple[Any, str, int]] = [(value, path, depth)]
    while stack:
        current, current_path, current_depth = stack.pop()
        if current_depth > 100:
            # A valid but unusually deep metadata tree is not needed for package
            # inventory. JSON parser itself also enforces a recursion ceiling.
            continue
        if isinstance(current, str):
            yield current_path, current
        elif isinstance(current, dict):
            for key, child in reversed(list(current.items())):
                # Keys are strings in JSON. Only values are scanned for payloads.
                stack.append((child, f"{current_path}.{key}", current_depth + 1))
        elif isinstance(current, list):
            for index in range(len(current) - 1, -1, -1):
                stack.append((current[index], f"{current_path}[{index}]", current_depth + 1))


def _scan_untrusted_text(manifest: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for path, text in _iter_string_values(manifest):
        for code, pattern in _SUSPICIOUS_TEXT_PATTERNS:
            if pattern.search(text):
                marker = (code, path)
                if marker not in seen:
                    seen.add(marker)
                    findings.append({
                        "code": code,
                        "severity": "REVIEW",
                        "field": path,
                        "message": "Suspicious instruction-like or verdict-like text detected in untrusted metadata.",
                    })
    return findings


def _base_result(*, status: str, decision: str, errors: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "decision": decision,
        # Every caller-supplied manifest remains untrusted, even when no known
        # injection marker is detected. Parsing does not confer authority.
        "trust_state": "TAINTED",
        "validation": {
            "input_rejected": bool(errors),
            "errors": errors or [],
        },
        "manifest": {"name": None, "version": None},
        "dependencies": [],
        "summary": {
            "dependency_count": 0,
            "unique_dependency_count": 0,
            "by_section": {section: 0 for section in DEPENDENCY_SECTIONS},
            "suspicious_content_detected": False,
            "non_registry_reference_count": 0,
            "mutable_specifier_count": 0,
        },
        "findings": [],
        "risk_indicators": [],
    }


def analyze_manifest(package_json: str) -> dict[str, Any]:
    """Parse and normalize an untrusted npm ``package.json`` string.

    The function is deterministic, read-only, and network-free. It returns a
    structured rejection instead of raising for untrusted/invalid input.
    It does not perform vulnerability lookups and does not issue approval.
    """
    if not isinstance(package_json, str):
        result = _base_result(
            status="REJECTED",
            decision="DENY",
            errors=[{"code": "INVALID_INPUT_TYPE", "message": "package_json must be a string."}],
        )
        return result

    if not package_json:
        return _base_result(
            status="REJECTED",
            decision="DENY",
            errors=[{"code": "EMPTY_INPUT", "message": "package_json must not be empty."}],
        )

    try:
        encoded = package_json.encode("utf-8", errors="strict")
    except UnicodeError:
        return _base_result(
            status="REJECTED",
            decision="DENY",
            errors=[{"code": "INVALID_UNICODE", "message": "package_json must be valid UTF-8 text."}],
        )

    if len(encoded) > MAX_MANIFEST_BYTES:
        return _base_result(
            status="REJECTED",
            decision="DENY",
            errors=[{
                "code": "MANIFEST_TOO_LARGE",
                "message": f"package_json exceeds the {MAX_MANIFEST_BYTES}-byte limit.",
            }],
        )

    try:
        parsed = json.loads(
            package_json,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_nonstandard_constant,
        )
    except _DuplicateJSONKeyError:
        return _base_result(
            status="REJECTED",
            decision="DENY",
            errors=[{"code": "DUPLICATE_JSON_KEY", "message": "Duplicate JSON object keys are not allowed."}],
        )
    except (json.JSONDecodeError, ValueError, RecursionError):
        return _base_result(
            status="REJECTED",
            decision="DENY",
            errors=[{"code": "INVALID_JSON", "message": "package_json is not valid strict JSON."}],
        )

    if not isinstance(parsed, dict):
        return _base_result(
            status="REJECTED",
            decision="DENY",
            errors=[{"code": "ROOT_NOT_OBJECT", "message": "package_json must contain a JSON object at its root."}],
        )

    try:
        manifest_name = parsed.get("name")
        if manifest_name is not None:
            manifest_name = _validate_package_name(manifest_name, field_name="name")

        manifest_version = parsed.get("version")
        if manifest_version is not None:
            if (
                not isinstance(manifest_version, str)
                or not manifest_version
                or len(manifest_version) > MAX_SPECIFIER_LENGTH
                or _CONTROL_CHARS_RE.search(manifest_version)
                or manifest_version != manifest_version.strip()
            ):
                _reject("INVALID_MANIFEST_VERSION", "The manifest version must be a bounded, non-empty string without control characters.")

        dependencies: list[dict[str, str]] = []
        by_section = {section: 0 for section in DEPENDENCY_SECTIONS}
        for section in DEPENDENCY_SECTIONS:
            entries = parsed.get(section, {})
            if not isinstance(entries, dict):
                _reject("INVALID_DEPENDENCY_SECTION", f"{section} must be a JSON object.")
            for package_name, specifier in entries.items():
                valid_name = _validate_package_name(package_name, field_name=f"{section} dependency name")
                specifier_type, risk = _classify_specifier(specifier, package_name=valid_name)
                dependencies.append({
                    "name": valid_name,
                    "specifier": specifier,
                    "section": section,
                    "specifier_type": specifier_type,
                    "risk_indicator": "NON_PINNED_OR_EXTERNAL_REFERENCE" if risk else "NONE",
                })
                by_section[section] += 1
                if len(dependencies) > MAX_DEPENDENCIES:
                    _reject(
                        "TOO_MANY_DEPENDENCIES",
                        f"The manifest exceeds the {MAX_DEPENDENCIES}-dependency limit.",
                    )

        findings = _scan_untrusted_text(parsed)
        non_registry_count = sum(item["specifier_type"] == "NON_REGISTRY_REFERENCE" for item in dependencies)
        mutable_count = sum(item["specifier_type"] in {"DIST_TAG", "NON_REGISTRY_REFERENCE", "NPM_ALIAS"} for item in dependencies)
        risk_indicators: list[str] = []
        if non_registry_count:
            risk_indicators.append("NON_REGISTRY_DEPENDENCY_REFERENCES_PRESENT")
        if mutable_count:
            risk_indicators.append("NON_PINNED_OR_EXTERNAL_DEPENDENCY_SPECIFIERS_PRESENT")
        if findings:
            risk_indicators.append("INSTRUCTION_LIKE_OR_VERDICT_LIKE_METADATA_PRESENT")

        result = _base_result(status="OK", decision="ANALYZE_ONLY")
        result["manifest"] = {"name": manifest_name, "version": manifest_version}
        result["dependencies"] = dependencies
        result["summary"] = {
            "dependency_count": len(dependencies),
            "unique_dependency_count": len({item["name"] for item in dependencies}),
            "by_section": by_section,
            "suspicious_content_detected": bool(findings),
            "non_registry_reference_count": non_registry_count,
            "mutable_specifier_count": mutable_count,
        }
        result["findings"] = findings
        result["risk_indicators"] = risk_indicators
        return result

    except _ManifestValidationError as exc:
        return _base_result(
            status="REJECTED",
            decision="DENY",
            errors=[{"code": exc.code, "message": exc.message}],
        )
