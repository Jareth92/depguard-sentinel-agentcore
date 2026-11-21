import json
import unittest

from depguard.lambda_validator import lambda_handler


class LambdaValidatorTests(unittest.TestCase):

    def make_event(self, raw_arguments=None, package_json=None):
        if raw_arguments is None:
            raw_arguments = ["lodash", "@types/node"]

        if package_json is None:
            package_json = json.dumps({
                "name": "lambda-test-fixture",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "4.17.21",
                    "@types/node": "^22.0.0",
                },
            })

        return {
            "direct_input": {
                "raw_arguments": raw_arguments,
            },
            "package_json": package_json,
        }

    def decode_body(self, response):
        return json.loads(response["body"])

    def test_accepts_valid_event(self):
        response = lambda_handler(self.make_event())
        body = self.decode_body(response)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["status"], "OK")
        self.assertEqual(body["decision"], "ANALYZE_ONLY")
        self.assertFalse(body["validation"]["input_rejected"])

        self.assertEqual(
            body["evidence"]["t08"]["raw_arguments"]["summary"]["accepted_count"],
            2,
        )

    def test_rejects_malicious_arguments_and_manifest(self):
        malicious = ["*", "../", "arn:aws:s3:::*"]

        package_json = json.dumps({
            "name": "lambda-test-fixture",
            "version": "1.0.0",
            "dependencies": {
                "../escape": "1.0.0",
                "arn:aws:s3:::*": "latest",
                "*": "1.0.0",
            },
        })

        response = lambda_handler(
            self.make_event(malicious, package_json)
        )
        body = self.decode_body(response)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["status"], "REJECTED")
        self.assertTrue(body["validation"]["input_rejected"])
        self.assertTrue(body["validation"]["raw_arguments_rejected"])
        self.assertTrue(body["validation"]["manifest_rejected"])

        self.assertFalse(body["evidence"]["t08"]["execution_performed"])

        # Attacker-controlled values must not be echoed.
        serialized = json.dumps(body)
        for value in malicious:
            self.assertNotIn(value, serialized)

    def test_rejects_non_object_event(self):
        response = lambda_handler(["not", "an", "object"])
        body = self.decode_body(response)

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(body["error"], "EVENT_MUST_BE_OBJECT")

    def test_rejects_extra_event_property(self):
        event = self.make_event()
        event["unexpected"] = "extra"

        response = lambda_handler(event)
        body = self.decode_body(response)

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(body["error"], "INVALID_EVENT_SCHEMA")

    def test_rejects_missing_event_property(self):
        event = {
            "direct_input": {
                "raw_arguments": ["lodash"]
            }
        }

        response = lambda_handler(event)
        body = self.decode_body(response)

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(body["error"], "INVALID_EVENT_SCHEMA")

    def test_rejects_extra_direct_input_property(self):
        event = self.make_event()
        event["direct_input"]["unexpected"] = "extra"

        response = lambda_handler(event)
        body = self.decode_body(response)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(body["status"], "REJECTED")
        self.assertFalse(
            body["validation"]["direct_input_schema_valid"]
        )

    def test_rejects_malformed_manifest(self):
        event = self.make_event(
            raw_arguments=["lodash"],
            package_json="{invalid-json",
        )

        response = lambda_handler(event)
        body = self.decode_body(response)

        self.assertEqual(body["status"], "REJECTED")
        self.assertTrue(body["validation"]["manifest_rejected"])
        self.assertTrue(body["validation"]["input_rejected"])

    def test_rejects_empty_raw_arguments(self):
        event = self.make_event(raw_arguments=[])

        response = lambda_handler(event)
        body = self.decode_body(response)

        self.assertEqual(body["status"], "REJECTED")
        self.assertTrue(body["validation"]["raw_arguments_rejected"])

    def test_handler_returns_lambda_proxy_response_shape(self):
        response = lambda_handler(self.make_event())

        self.assertIn("statusCode", response)
        self.assertIn("headers", response)
        self.assertIn("body", response)
        self.assertEqual(
            response["headers"]["content-type"],
            "application/json",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)