import unittest

from depguard.approval_binding import ApprovalRegistry


class ApprovalBindingTests(unittest.TestCase):

    def setUp(self):
        self.registry = ApprovalRegistry()

        self.approval_id = "REDTEAM-T07-FIXTURE"
        self.token = "REDTEAM-T07-FIXTURE-TOKEN-ONLY"

        self.assertTrue(
            self.registry.register_fixture(
                approval_id=self.approval_id,
                package="lodash",
                version="4.17.21",
                action="install",
                token=self.token,
            )
        )

    def make_attempt(self, **overrides):
        attempt = {
            "approval_id": self.approval_id,
            "package": "lodash",
            "version": "4.17.21",
            "action": "install",
            "token": self.token,
        }
        attempt.update(overrides)
        return attempt

    def test_exact_approval_is_recognized(self):
        result = self.registry.verify(self.make_attempt())

        self.assertTrue(result["token_accepted"])
        self.assertTrue(result["token_recognized"])
        self.assertTrue(result["binding_matches"])
        self.assertEqual(result["error_code"], "APPROVAL_ACCEPTED")

    def test_bait_and_switch_rejects_package_and_version(self):
        result = self.registry.verify(
            self.make_attempt(
                package="lodasah",
                version="4.17.1",
            )
        )

        self.assertFalse(result["token_accepted"])
        self.assertTrue(result["approval_record_found"])
        self.assertTrue(result["token_recognized"])
        self.assertFalse(result["binding_matches"])

        self.assertEqual(
            set(result["mismatched_fields"]),
            {"package", "version"},
        )

        self.assertEqual(
            result["error_code"],
            "APPROVAL_BINDING_MISMATCH",
        )

    def test_different_package_is_rejected(self):
        result = self.registry.verify(
            self.make_attempt(package="express")
        )

        self.assertFalse(result["token_accepted"])
        self.assertEqual(result["mismatched_fields"], ["package"])

    def test_different_version_is_rejected(self):
        result = self.registry.verify(
            self.make_attempt(version="4.18.0")
        )

        self.assertFalse(result["token_accepted"])
        self.assertEqual(result["mismatched_fields"], ["version"])

    def test_different_action_is_rejected(self):
        result = self.registry.verify(
            self.make_attempt(action="delete")
        )

        self.assertFalse(result["token_accepted"])
        self.assertEqual(result["mismatched_fields"], ["action"])

    def test_wrong_token_is_rejected(self):
        result = self.registry.verify(
            self.make_attempt(token="ANOTHER-INVALID-TOKEN")
        )

        self.assertFalse(result["token_accepted"])
        self.assertFalse(result["token_recognized"])
        self.assertTrue(result["binding_matches"])
        self.assertEqual(result["error_code"], "TOKEN_MISMATCH")

    def test_unknown_approval_id_is_rejected(self):
        result = self.registry.verify(
            self.make_attempt(approval_id="UNKNOWN-APPROVAL")
        )

        self.assertFalse(result["token_accepted"])
        self.assertFalse(result["approval_record_found"])
        self.assertEqual(result["error_code"], "APPROVAL_NOT_FOUND")

    def test_extra_attempt_field_is_rejected(self):
        result = self.registry.verify(
            self.make_attempt(admin_override=True)
        )

        self.assertFalse(result["token_accepted"])
        self.assertEqual(result["error_code"], "INVALID_ATTEMPT_SCHEMA")

    def test_invalid_version_format_is_rejected(self):
        result = self.registry.verify(
            self.make_attempt(version="../4.17.21")
        )

        self.assertFalse(result["token_accepted"])
        self.assertEqual(result["error_code"], "INVALID_ATTEMPT_FIELDS")

    def test_duplicate_approval_id_cannot_be_registered(self):
        accepted = self.registry.register_fixture(
            approval_id=self.approval_id,
            package="express",
            version="5.0.0",
            action="install",
            token=self.token,
        )

        self.assertFalse(accepted)


if __name__ == "__main__":
    unittest.main(verbosity=2)