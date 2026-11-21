import unittest

from depguard.raw_argument_validator import validate_raw_arguments


class RawArgumentValidatorTests(unittest.TestCase):

    def test_accepts_standard_package_name(self):
        result = validate_raw_arguments(["lodash"])

        self.assertEqual(result["status"], "OK")
        self.assertFalse(result["validation"]["input_rejected"])
        self.assertEqual(result["summary"]["accepted_count"], 1)
        self.assertEqual(result["summary"]["rejected_count"], 0)

    def test_accepts_scoped_package_name(self):
        result = validate_raw_arguments(["@types/node"])

        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["summary"]["accepted_count"], 1)

    def test_rejects_wildcard_path_and_arn(self):
        malicious = ["*", "../", "arn:aws:s3:::*"]

        result = validate_raw_arguments(malicious)

        self.assertEqual(result["status"], "REJECTED")
        self.assertTrue(result["validation"]["input_rejected"])
        self.assertEqual(result["summary"]["accepted_count"], 0)
        self.assertEqual(result["summary"]["rejected_count"], 3)
        self.assertEqual(len(result["validation"]["errors"]), 3)

        # Do not disclose attacker-controlled values in error messages.
        for value in malicious:
            self.assertNotIn(value, str(result))

    def test_rejects_non_list_input(self):
        result = validate_raw_arguments("*")

        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(
            result["validation"]["errors"][0]["code"],
            "INVALID_RAW_ARGUMENTS_TYPE",
        )

    def test_rejects_empty_list(self):
        result = validate_raw_arguments([])

        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(
            result["validation"]["errors"][0]["code"],
            "EMPTY_RAW_ARGUMENTS",
        )

    def test_rejects_non_string_argument(self):
        result = validate_raw_arguments(["lodash", None])

        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["summary"]["accepted_count"], 1)
        self.assertEqual(result["summary"]["rejected_count"], 1)

    def test_rejects_too_many_arguments(self):
        result = validate_raw_arguments(["lodash"] * 65)

        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(
            result["validation"]["errors"][0]["code"],
            "TOO_MANY_RAW_ARGUMENTS",
        )

    def test_rejects_oversized_identifier(self):
        result = validate_raw_arguments(["a" * 215])

        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(
            result["validation"]["errors"][0]["code"],
            "RAW_ARGUMENT_TOO_LONG",
        )

    def test_valid_and_invalid_arguments_are_counted(self):
        result = validate_raw_arguments([
            "lodash",
            "@types/node",
            "*",
        ])

        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["summary"]["argument_count"], 3)
        self.assertEqual(result["summary"]["accepted_count"], 2)
        self.assertEqual(result["summary"]["rejected_count"], 1)

    def test_validator_never_executes_arguments(self):
        result = validate_raw_arguments(["lodash", "*"])

        self.assertIs(result["execution_performed"], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)