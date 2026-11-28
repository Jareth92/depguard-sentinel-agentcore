import unittest

from depguard.data_classification import (
    MAX_SCAN_BYTES,
    classify_sensitive_data,
)


class DataClassificationTests(unittest.TestCase):

    def test_email_is_classified_as_confidential(self):
        result = classify_sensitive_data(
            "Contact: analyst@example.com"
        )

        self.assertTrue(result["input_inspected"])
        self.assertTrue(result["sensitive_data_detected"])
        self.assertEqual(result["classification"], "CONFIDENTIAL")
        self.assertEqual(
            result["findings"][0]["code"],
            "EMAIL_ADDRESS_CANDIDATE",
        )

    def test_aws_access_key_candidate_is_restricted(self):
        result = classify_sensitive_data(
            "AKIAIOSFODNN7EXAMPLE"
        )

        self.assertEqual(result["classification"], "RESTRICTED")
        self.assertIn(
            "AWS_ACCESS_KEY_ID_CANDIDATE",
            [item["code"] for item in result["findings"]],
        )

    def test_github_token_candidate_is_restricted(self):
        result = classify_sensitive_data(
            "ghp_abcdefghijklmnopqrstuvwxyz123456"
        )

        self.assertEqual(result["classification"], "RESTRICTED")
        self.assertTrue(result["sensitive_data_detected"])

    def test_bearer_token_candidate_is_restricted(self):
        result = classify_sensitive_data(
            "Authorization: Bearer synthetic-token-value-123456"
        )

        self.assertEqual(result["classification"], "RESTRICTED")

    def test_private_key_marker_is_restricted(self):
        result = classify_sensitive_data(
            "-----BEGIN PRIVATE KEY-----"
        )

        self.assertEqual(result["classification"], "RESTRICTED")
        self.assertIn(
            "PRIVATE_KEY_MARKER",
            [item["code"] for item in result["findings"]],
        )

    def test_generic_api_key_assignment_is_restricted(self):
        synthetic_secret = "synthetic-secret-value-123456"

        result = classify_sensitive_data(
            f'{{"api_key": "{synthetic_secret}"}}'
        )

        self.assertEqual(result["classification"], "RESTRICTED")
        self.assertTrue(result["sensitive_data_detected"])

        # The detected value must never appear in the result.
        self.assertNotIn(synthetic_secret, str(result))

    def test_highest_classification_wins(self):
        result = classify_sensitive_data(
            "Contact analyst@example.com; "
            "api_key=synthetic-secret-value-123456"
        )

        self.assertEqual(result["classification"], "RESTRICTED")

    def test_no_known_pattern_remains_unclassified(self):
        result = classify_sensitive_data(
            "Ordinary application documentation."
        )

        self.assertTrue(result["input_inspected"])
        self.assertFalse(result["sensitive_data_detected"])
        self.assertEqual(result["classification"], "UNCLASSIFIED")
        self.assertEqual(result["findings"], [])

    def test_invalid_input_is_rejected(self):
        result = classify_sensitive_data(None)

        self.assertFalse(result["input_inspected"])
        self.assertTrue(result["input_rejected"])
        self.assertEqual(result["classification"], "UNCLASSIFIED")

    def test_oversized_input_is_rejected(self):
        result = classify_sensitive_data(
            "x" * (MAX_SCAN_BYTES + 1)
        )

        self.assertFalse(result["input_inspected"])
        self.assertTrue(result["input_rejected"])
        self.assertEqual(
            result["reason"],
            "INPUT_EXCEEDS_MAX_BYTES",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
