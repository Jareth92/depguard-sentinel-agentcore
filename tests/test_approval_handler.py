import json
import unittest

from depguard.approval_handler import approval_handler


class ApprovalHandlerTests(unittest.TestCase):

    def setUp(self):
        self.attempt = {
            "approval_id": "REDTEAM-FIXTURE-ONLY",
            "package": "lodash",
            "version": "4.17.21",
            "action": "install",
            "token": "REDTEAM-T07-FIXTURE-TOKEN-ONLY",
        }

    def invoke(self, attempt=None):
        response = approval_handler({
            "attempt": attempt if attempt is not None else self.attempt
        })
        return response["statusCode"], json.loads(response["body"])

    def test_exact_approval_is_accepted_without_execution(self):
        status, result = self.invoke()

        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "ACCEPTED")
        self.assertEqual(result["decision"], "ANALYZE_ONLY")
        self.assertTrue(result["approval"]["token_accepted"])
        self.assertFalse(result["execution_performed"])

    def test_bait_and_switch_is_rejected(self):
        attempt = dict(self.attempt)
        attempt["package"] = "lodasah"
        attempt["version"] = "4.17.1"

        status, result = self.invoke(attempt)

        approval = result["approval"]

        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["decision"], "DENY")
        self.assertTrue(approval["registered"])
        self.assertTrue(approval["approval_record_found"])
        self.assertTrue(approval["token_recognized"])
        self.assertFalse(approval["binding_matches"])
        self.assertFalse(approval["token_accepted"])
        self.assertEqual(
            set(approval["mismatched_fields"]),
            {"package", "version"},
        )
        self.assertFalse(result["execution_performed"])

    def test_wrong_token_is_rejected(self):
        attempt = dict(self.attempt)
        attempt["token"] = "ANOTHER-INVALID-TOKEN"

        status, result = self.invoke(attempt)

        self.assertEqual(status, 200)
        self.assertEqual(result["decision"], "DENY")
        self.assertFalse(result["approval"]["token_recognized"])
        self.assertEqual(
            result["approval"]["error_code"],
            "TOKEN_MISMATCH",
        )

    def test_different_action_is_rejected(self):
        attempt = dict(self.attempt)
        attempt["action"] = "delete"

        status, result = self.invoke(attempt)

        self.assertEqual(status, 200)
        self.assertFalse(result["approval"]["token_accepted"])
        self.assertEqual(
            result["approval"]["mismatched_fields"],
            ["action"],
        )

    def test_extra_attempt_field_is_rejected(self):
        attempt = dict(self.attempt)
        attempt["admin_override"] = True

        status, result = self.invoke(attempt)

        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(
            result["approval"]["error_code"],
            "INVALID_ATTEMPT_SCHEMA",
        )

    def test_caller_cannot_supply_seed_fixture(self):
        response = approval_handler({
            "seed_approval": {
                "approval_id": "ATTACKER-CONTROLLED",
            },
            "attempt": self.attempt,
        })

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(
            body["error_code"],
            "INVALID_EVENT_SCHEMA",
        )

    def test_missing_attempt_is_rejected(self):
        response = approval_handler({})

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(
            body["error_code"],
            "INVALID_EVENT_SCHEMA",
        )

    def test_token_is_not_returned(self):
        status, result = self.invoke({
            **self.attempt,
            "package": "lodasah",
            "version": "4.17.1",
        })

        self.assertEqual(status, 200)
        self.assertNotIn(
            self.attempt["token"],
            json.dumps(result),
        )

    def test_non_object_event_is_rejected(self):
        response = approval_handler("not-an-object")

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(body["error_code"], "INVALID_EVENT")


if __name__ == "__main__":
    unittest.main(verbosity=2)