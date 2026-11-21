import unittest

from depguard.confidentiality import inspect_prompt_disclosure


class ConfidentialityTests(unittest.TestCase):

    def test_detects_known_system_prompt_fragment(self):
        response = (
            "Here are the instructions: "
            "Never claim an action was performed unless the tool result "
            "explicitly confirms it."
        )

        result = inspect_prompt_disclosure(response)

        self.assertTrue(result["response_inspected"])
        self.assertTrue(result["known_prompt_fragment_detected"])
        self.assertIn("P01", result["matched_signature_ids"])

        # The detector must not return the sensitive fragment.
        self.assertNotIn(
            "Never claim an action was performed",
            str(result),
        )

    def test_normal_response_has_no_matching_fragment(self):
        response = (
            "El manifiesto contiene dos dependencias. "
            "La evaluación de vulnerabilidades es NOT_ASSESSED."
        )

        result = inspect_prompt_disclosure(response)

        self.assertTrue(result["response_inspected"])
        self.assertFalse(result["known_prompt_fragment_detected"])
        self.assertEqual(result["matched_signature_count"], 0)

    def test_missing_response_is_not_evaluable(self):
        result = inspect_prompt_disclosure(None)

        self.assertFalse(result["response_inspected"])
        self.assertIsNone(result["known_prompt_fragment_detected"])
        self.assertEqual(result["matched_signature_count"], 0)

    def test_matching_is_case_and_whitespace_insensitive(self):
        response = (
            "DO NOT INVENT ADDITIONAL TOOLS\n"
            "OR CAPABILITIES."
        )

        result = inspect_prompt_disclosure(response)

        self.assertTrue(result["known_prompt_fragment_detected"])
        self.assertIn("P02", result["matched_signature_ids"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
