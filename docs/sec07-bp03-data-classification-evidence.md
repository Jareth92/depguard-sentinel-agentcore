# SEC07-BP03 — Automated Data Identification and Classification Evidence

## 1. Identification

- Workload: DepGuard Sentinel
- Pillar: Security
- Question: SEC07 — Data Protection
- Best Practice: SEC07-BP03 — Automate identification and classification
- Assessment date: 2026-11-27
- Region: us-east-1
- Assessment status: PARTIALLY IMPLEMENTED

## 2. Local Sensitive Data Classifier

Component: `depguard/data_classification.py`

Detection method: Local deterministic pattern matching.

Maximum input size: 256 KiB.

The classifier identifies candidate patterns associated with:

| Detection code | Data category | Classification |
|---|---|---|
| PRIVATE_KEY_MARKER | CREDENTIAL_MATERIAL | RESTRICTED |
| AWS_ACCESS_KEY_ID_CANDIDATE | CLOUD_CREDENTIAL_IDENTIFIER | RESTRICTED |
| GITHUB_TOKEN_CANDIDATE | ACCESS_TOKEN | RESTRICTED |
| BEARER_TOKEN_CANDIDATE | ACCESS_TOKEN | RESTRICTED |
| GENERIC_CREDENTIAL_ASSIGNMENT | CREDENTIAL_MATERIAL | RESTRICTED |
| EMAIL_ADDRESS_CANDIDATE | PERSONAL_DATA | CONFIDENTIAL |

The highest detected classification determines the overall result.

No-match inputs are classified as `UNCLASSIFIED`, not `PUBLIC`.

The classifier returns detection codes, categories, classification levels,
and match counts. It does not return the matched values.

Invalid input types and inputs exceeding the maximum size are rejected.

## 3. Red Team Adapter Integration

Component: `scripts/redteam_adapter.py`

The adapter invokes `classify_sensitive_data()` on the final assistant
response before deciding whether it can be captured.

The existing known system-prompt fragment inspection remains active.

For scenarios within `FINAL_RESPONSE_CAPTURE_SCENARIOS`, capture requires:

- No known system-prompt fragment detected.
- Response size within the existing 8 KiB limit.
- Successful data classification inspection.
- No sensitive-data candidate detected.

Capture is denied when sensitive data is detected or classification
cannot be completed.

T05 remains explicitly excluded from final-response persistence.

Evidence:
- `tests/test_redteam_adapter_confidentiality.py`
- `test_t06_does_not_store_sensitive_data_candidates`

The integration tests use a local FakeHarnessClient; they do not represent
a live AgentCore invocation.

## 4. Independent Report-Side Validation

Component: `scripts/stress_test.py`

Before preserving final assistant text in a report, the runner independently
re-runs the local classifier.

The report accepts a final response only when:

- Adapter capture metadata is present and valid.
- Adapter classification reports `UNCLASSIFIED`.
- Adapter reports no sensitive-data findings.
- Independent local classification also reports `UNCLASSIFIED`.
- Independent classification detects no sensitive-data candidates.
- Existing prompt-disclosure and response-size checks pass.

The runner preserves only allowlisted classification metadata.

Finding codes, categories, classification levels, and match counts can
be included in the report. Matched values are not copied.

Evidence:
- `tests/test_stress_test_evidence.py`
- `test_independent_recheck_blocks_sensitive_response`
- `test_missing_adapter_scan_fails_closed`
- `test_preserves_sanitized_classification_when_response_is_blocked`

## 5. Automated Test Results

New classifier unit tests:
- 10 tests passed.

Red Team adapter confidentiality tests:
- 7 tests passed.

Report evidence tests:
- 8 tests passed.

Complete local test suite:
- 157 tests passed.
- 0 failures.

Validation:
- `python -m unittest discover -s tests -v`
- `git diff --check`

All reported tests were executed locally using deterministic fixtures and
test doubles. No live AWS invocation was performed as part of this validation.

## 6. Security Assessment

The workload now demonstrates limited automated identification of
candidate sensitive information and classification-based capture controls
within its local Red Team response-reporting workflow.

The independent report-side recheck provides an additional validation
boundary before final assistant text is persisted.

Classification metadata is retained without copying detected values.

Assessment: PARTIALLY IMPLEMENTED.

## 7. Limitations and Residual Risks

The classifier is heuristic and based on known regular-expression patterns.

It does not establish that a detected credential is valid.

It can produce false positives and false negatives.

The current patterns do not cover every cloud provider, token format,
credential type, or category of personal information.

The classifier is not a complete Data Loss Prevention (DLP) solution.

The current integration protects the inspected Red Team final-response
capture path. It does not demonstrate comprehensive scanning of:

- Incoming npm manifests.
- Every Lambda request and response.
- All AgentCore runtime inputs and outputs.
- CloudWatch log events.
- Existing local artifacts.
- Every other persistence destination.

The classification scheme is currently limited to UNCLASSIFIED,
CONFIDENTIAL, and RESTRICTED outcomes. It does not automatically
establish that unclassified information is public.

Existing reports generated before this change have not been retroactively
scanned or sanitized.

## 8. Recommended Improvements

- Extend classification coverage to additional credential and personal-data formats.
- Integrate classification at appropriate manifest and Lambda input boundaries.
- Evaluate sensitive-data handling in CloudWatch and other persistence locations.
- Define and document an organization-wide data classification policy.
- Add additional false-positive and false-negative test cases.
- Validate the complete capture workflow against the live Harness using synthetic fixtures.
- Establish retention and deletion requirements for sensitive evidence.

## 9. Cost and Operational Considerations

The classifier uses local Python regular expressions.

No external DLP service, model API, additional AWS resource, or paid
scanning service is required for its current implementation.

The existing Red Team adapter and report runner execute the checks locally.
