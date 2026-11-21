import hashlib
import hmac
import re

from dataclasses import dataclass


# Strict identifiers for test-only approval records.
PACKAGE_PATTERN = re.compile(
    r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$"
)

VERSION_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)

APPROVAL_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
)

ACTION_PATTERN = re.compile(
    r"^[a-z][a-z0-9:_-]{0,63}$"
)


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    package: str
    version: str
    action: str
    token_digest: bytes

class ApprovalRegistry:
    """
    In-memory approval registry for isolated security tests.

    This is not a production approval backend.
    It does not grant permissions or execute operations.
    """

    def __init__(self) -> None:
        self._records: dict[str, ApprovalRecord] = {}

    @staticmethod
    def _valid_fields(
        approval_id: object,
        package: object,
        version: object,
        action: object,
        token: object,
    ) -> bool:
        return (
            isinstance(approval_id, str)
            and APPROVAL_ID_PATTERN.fullmatch(approval_id) is not None
            and isinstance(package, str)
            and PACKAGE_PATTERN.fullmatch(package) is not None
            and isinstance(version, str)
            and VERSION_PATTERN.fullmatch(version) is not None
            and isinstance(action, str)
            and ACTION_PATTERN.fullmatch(action) is not None
            and isinstance(token, str)
            and 16 <= len(token) <= 512
        )

    @staticmethod
    def _digest(token: str) -> bytes:
        return hashlib.sha256(token.encode("utf-8")).digest()

    def register_fixture(
        self,
        approval_id: str,
        package: str,
        version: str,
        action: str,
        token: str,
    ) -> bool:
        """Register a temporary approval fixture for testing only."""

        if not self._valid_fields(
            approval_id, package, version, action, token
        ):
            return False

        if approval_id in self._records:
            return False

        self._records[approval_id] = ApprovalRecord(
            approval_id=approval_id,
            package=package,
            version=version,
            action=action,
            token_digest=self._digest(token),
        )

        return True

    def verify(self, attempt: object) -> dict:
        """Verify token identity and exact approval binding."""

        rejected = {
            "token_accepted": False,
            "approval_record_found": False,
            "token_recognized": False,
            "binding_matches": False,
            "mismatched_fields": [],
            "error_code": "INVALID_ATTEMPT",
        }

        if not isinstance(attempt, dict):
            return rejected

        required_fields = {
            "approval_id",
            "package",
            "version",
            "action",
            "token",
        }

        if set(attempt.keys()) != required_fields:
            rejected["error_code"] = "INVALID_ATTEMPT_SCHEMA"
            return rejected

        if not self._valid_fields(
            attempt["approval_id"],
            attempt["package"],
            attempt["version"],
            attempt["action"],
            attempt["token"],
        ):
            rejected["error_code"] = "INVALID_ATTEMPT_FIELDS"
            return rejected

        record = self._records.get(attempt["approval_id"])

        if record is None:
            rejected["mismatched_fields"] = ["approval_id"]
            rejected["error_code"] = "APPROVAL_NOT_FOUND"
            return rejected

        token_matches = hmac.compare_digest(
            record.token_digest,
            self._digest(attempt["token"]),
        )

        mismatches = []

        if attempt["package"] != record.package:
            mismatches.append("package")

        if attempt["version"] != record.version:
            mismatches.append("version")

        if attempt["action"] != record.action:
            mismatches.append("action")

        binding_matches = len(mismatches) == 0

        accepted = token_matches and binding_matches

        return {
            "token_accepted": accepted,
            "approval_record_found": True,
            "token_recognized": token_matches,
            "binding_matches": binding_matches,
            "mismatched_fields": mismatches,
            "error_code": (
                "APPROVAL_ACCEPTED"
                if accepted
                else (
                    "APPROVAL_BINDING_MISMATCH"
                    if token_matches
                    else "TOKEN_MISMATCH"
                )
            ),
        }