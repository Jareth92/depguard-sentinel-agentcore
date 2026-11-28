# SEC07-BP04 — Scalable Data Lifecycle Management Evidence

## 1. Identification

- Workload: DepGuard Sentinel
- Pillar: Security
- Question: SEC07 — Protect data in transit and at rest
- Best Practice: SEC07-BP04 — Define scalable data lifecycle management
- Assessment date: 2026-11-27
- Assessment status: NOT DEMONSTRATED
- Evidence type: Local source inspection, repository inspection,
  local artifact inventory, and AWS configuration metadata

## 2. Objective

Determine whether DepGuard Sentinel has a defined and enforceable
data lifecycle covering data creation, storage, retention, archival,
and deletion.

The assessment is limited to the available local repository,
generated test artifacts, and inspected AWS resources.

## 3. Local report persistence

The stress test runner persists its report using the following behavior
in `scripts/stress_test.py`:

- Default output: `artifacts/redteam-results.json`.
- The output directory is created when it does not exist.
- The report is serialized as JSON and written using `Path.write_text()`.
- Reusing the same output path overwrites the existing file.
- No automatic rotation, expiration, or deletion of older report files
  was identified in the inspected implementation.

The output path can be overridden through the `--output` argument.

This is report persistence, not a complete data lifecycle mechanism.

## 4. Local artifact inventory

A non-recursive inventory of files directly inside `artifacts/`
on 2026-11-27 returned:

- File count: 42
- Total size: 410,382 bytes
- Oldest observed modification time: 2026-11-20
- Newest observed modification time: 2026-11-26

The oldest file by modification time was
`redteam-hardened-v2.json`.

The newest file by modification time was
`wafr-baseline-unit-tests-20261126.txt`.

This inventory establishes that generated evidence is retained locally
across multiple days. It does not establish the contents or sensitivity
of every file, nor does it demonstrate an approved retention period.

## 5. Source-code lifecycle inspection

A search was performed in Python files under:

- `depguard/`
- `scripts/`

The search included patterns associated with retention, expiration,
time-to-live, cleanup, purge, recursive deletion, and file removal.

No matching automated data lifecycle operations were identified
in those inspected Python directories.

A repository-wide tracked-file search also found no implemented
retention policy for generated reports.

The following matches were reviewed and excluded as unrelated
to persisted data retention:

- `create-harness.example.json`: runtime session lifecycle values
  (`idleRuntimeSessionTimeout` and `maxLifetime`). These describe
  runtime session behavior, not report or log retention.
- `RULES.md`: an in-memory approval registry without expiration.
  This describes component behavior, not stored evidence retention.
- `docs/war-review-after.md`: cleanup status for temporary IAM roles.
  This concerns identity resources, not data deletion.

## 6. AWS logging retention observations

The following CloudWatch log groups were inspected:

### Lambda

- Log group: `/aws/lambda/DepGuardScanFunction`
- Log class: Standard
- Retention: Never expire
- Stored bytes observed: 922
- Log streams observed: 2

### AgentCore runtime

- Log group:
  `/aws/bedrock-agentcore/runtimes/harness_DepGuardSentinel-xg5UWVFic3-DEFAULT`
- Log class: Standard
- Retention: Never expire
- Stored bytes observed: approximately 2.74 MB
- Log streams observed: 61

These are point-in-time observations from the assessment.
The configured `Never expire` retention means that these groups
do not have a configured automatic expiration period.

The log contents were not inspected as part of this BP04 assessment.
No conclusion is made about the sensitivity of every individual event.

## 7. Data classification relationship

The project has a provisional classification model documented
in the SEC07-BP01/BP02 assessment work:

- Public: intentionally public documentation.
- Internal: architecture and configuration information without secrets.
- Confidential: manifests, prompts, agent responses, and red-team reports.
- Restricted: credentials, access tokens, and private keys.

This classification model is provisional and has not been demonstrated
as an owner-approved organizational data classification policy.

The SEC07-BP03 local classifier provides limited heuristic detection
for selected sensitive-data patterns. It does not establish retention,
archival, or deletion requirements.

## 8. Assessment findings

### Existing capabilities

- Test reports can be persisted to a configurable local path.
- The report directory is created automatically when needed.
- Reusing the same output path replaces the previous file.
- Runtime sessions have example lifecycle configuration values.
- Selected sensitive response captures have local classification
  and capture controls documented under SEC07-BP03.

### Gaps

- No approved retention schedule was identified.
- No data owner or retention owner was identified in the inspected evidence.
- No automatic expiration or cleanup process was demonstrated
  for local test artifacts.
- The inspected CloudWatch groups use `Never expire`.
- No archival procedure or lifecycle transition was demonstrated.
- No deletion verification or evidence of completed retention cycles
  was identified.
- The provisional data classification model is not yet linked
  to enforceable retention and deletion requirements.

## 9. Recommended remediation

The following actions are recommendations only. They have not
been implemented as part of this assessment.

1. Obtain owner approval for retention requirements by data class
   and storage location.
2. Define a retention matrix specifying data owner, purpose,
   retention trigger, approved duration, archival method,
   deletion method, and verification evidence.
3. Establish an approved retention period for Lambda and AgentCore
   CloudWatch logs, then configure log group retention accordingly.
4. Define a retention and cleanup procedure for local generated
   reports, including how exceptions and evidence holds are handled.
5. Automate expiration only after the retention requirements
   and deletion safeguards have been approved.
6. Periodically verify that expired data is removed and that
   the lifecycle configuration remains effective.

No arbitrary retention duration is prescribed by this assessment.

## 10. Limitations and assessment boundaries

- The local artifact inventory measured files directly in `artifacts/`;
  it was not a recursive inventory.
- The assessment did not inspect every artifact's contents.
- Local source searches cannot prove the absence of external
  operational procedures.
- The example runtime lifecycle settings do not prove the deployed
  runtime's exact session lifecycle configuration.
- CloudWatch observations are point-in-time metadata.
- No AWS retention setting or local artifact was modified or deleted
  during this assessment.

## 11. Conclusion

SEC07-BP04 is assessed as NOT DEMONSTRATED.

DepGuard Sentinel persists local test evidence and AWS logging data,
but the inspected evidence does not establish a complete, approved,
and enforceable data lifecycle.

The most visible operational gap is indefinite CloudWatch log retention,
combined with the absence of a demonstrated retention and cleanup
mechanism for local generated artifacts.

The project should define owner-approved retention requirements
and implement verifiable lifecycle controls before this practice
can be considered demonstrated.
