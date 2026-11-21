import json

from depguard.approval_binding import ApprovalRegistry


# Trusted, deterministic fixture for isolated T07 testing only.
TEST_ONLY_APPROVAL_FIXTURE = {
    "approval_id": "REDTEAM-FIXTURE-ONLY",
    "package": "lodash",
    "version": "4.17.21",
    "action": "install",
    "token": "REDTEAM-T07-FIXTURE-TOKEN-ONLY",
}


def approval_handler(event: object) -> dict:
    """
    Local test-only approval handler.

    The trusted approval fixture is provisioned internally.
    The caller can only submit an attempted authorization reuse.

    No real approval, persistence, or operation execution occurs.
    """

    if not isinstance(event, dict):
        return {
            "statusCode": 400,
            "body": json.dumps({
                "status": "REJECTED",
                "error_code": "INVALID_EVENT",
            }),
        }

    if set(event.keys()) != {"attempt"}:
        return {
            "statusCode": 400,
            "body": json.dumps({
                "status": "REJECTED",
                "error_code": "INVALID_EVENT_SCHEMA",
            }),
        }

    attempt = event["attempt"]

    if not isinstance(attempt, dict):
        return {
            "statusCode": 400,
            "body": json.dumps({
                "status": "REJECTED",
                "error_code": "INVALID_ATTEMPT_OBJECT",
            }),
        }

    registry = ApprovalRegistry()
    seed = TEST_ONLY_APPROVAL_FIXTURE

    registered = registry.register_fixture(
        approval_id=seed["approval_id"],
        package=seed["package"],
        version=seed["version"],
        action=seed["action"],
        token=seed["token"],
    )

    if not registered:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "status": "REJECTED",
                "error_code": "FIXTURE_REGISTRATION_FAILED",
            }),
        }

    verification = registry.verify(attempt)

    accepted = verification["token_accepted"]

    result = {
        "status": "ACCEPTED" if accepted else "REJECTED",
        "decision": "ANALYZE_ONLY" if accepted else "DENY",
        "approval": {
            "registered": True,
            **verification,
        },
        "execution_performed": False,
    }

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": json.dumps(result),
    }