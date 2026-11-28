# SEC06-BP04 — Software Integrity Evidence

## 1. Identification

- Workload: DepGuard Sentinel
- Pillar: Security
- Question: SEC06 — Protecting compute
- Best Practice: SEC06-BP04 — Validate software integrity
- Region: us-east-1
- Observation date: 2026-11-27
- Assessment type: Manual evidence-based assessment

## 2. Git commit signatures

The latest eight commits were inspected using:

`git log -8 --format="%h %G? %s"`

All eight displayed the status `N`.

In Git's signature status format, `N` means that no signature
was present for the inspected commit.

The inspected commits are therefore unsigned.

This does not demonstrate that the commits were altered.
It means that cryptographic commit authorship verification
was not available for these commits.

## 3. GitHub Actions references

The inspected workflow is:

`.github/workflows/ci.yml`

It uses:

- actions/checkout@v7
- actions/setup-python@v7

Both references use version tags rather than full-length
commit SHA references.

No evidence of an Actions dependency lockfile was identified
in the inspected workflow.

GitHub recommends pinning third-party Actions to full-length
commit SHAs when immutable action references are required.

## 4. Python dependency integrity

The inspected requirements.txt contains:

- boto3==1.44.7

The exact version is pinned.

However, the inspected requirements file does not include
package hashes.

Version pinning improves reproducibility, but does not by
itself verify downloaded package bytes or publisher identity.

No hashed requirements file or package signature verification
step was identified in the inspected dependency configuration.

## 5. Container artifact observations

The AgentCore Runtime reports:

- Runtime: harness_DepGuardSentinel
- Version: 2
- Platform version: V2
- Container URI:
  public.ecr.aws/i0n3d3i5/harness-us-east-1:latest

The Harness configuration reports:

- EnvironmentArtifact: null

No customer-managed Dockerfile, Containerfile, or
docker-compose configuration was identified in the repository
search.

The runtime-reported container URI uses the `latest` tag.

The image digest, publisher provenance, and cryptographic
signature verification were not independently inspected.

The absence of a customer-managed Dockerfile does not prove
the integrity or provenance of the runtime image.

## 6. SHA-256 token digest mechanism

The code in:

- depguard/approval_binding.py
- depguard/approval_handler.py
- tests/test_approval_binding.py

uses SHA-256 to calculate a digest of an approval token.

The ApprovalRegistry stores the resulting token_digest and
uses hmac.compare_digest() when comparing the submitted
token digest against the stored digest.

The approval handler identifies the fixture as a trusted,
deterministic fixture for isolated T07 testing only.

This mechanism protects the handling of an approval token
within the test fixture.

It is not a software artifact integrity mechanism.

It does not sign or verify:
- Source code.
- Python packages.
- Container images.
- Deployment artifacts.
- Git commits.

## 7. Signing and provenance mechanisms

The inspected repository paths included:

- .github/workflows
- scripts
- depguard

The search examined references to:

- Cosign
- Notation
- AWS Signer
- Signatures
- Checksums
- SHA-256 and SHA-512
- Attestations
- Provenance

No software artifact signing or signature verification
integration was identified in the inspected scope.

The SHA-256 token digest in ApprovalRegistry is documented
separately because it has a different security purpose.

## 8. Assessment

Provisional status: NOT DEMONSTRATED.

Positive supporting controls:

- Boto3 is pinned to an exact version.
- The project maintains version-controlled source code.
- CI compiles Python sources and executes unit tests.
- ApprovalRegistry hashes test fixture tokens before storage.
- The local client validates the Harness ARN and tool names.

These controls do not establish cryptographic integrity
and provenance verification for software artifacts.

Gaps:

- The eight inspected commits are unsigned.
- GitHub Actions references are tag-based rather than
  pinned to full-length commit SHAs.
- No package hashes were identified in requirements.txt.
- No package signature verification was identified.
- No software artifact signing mechanism was identified.
- No deployment-time signature verification was identified.
- The runtime image digest and provenance were not verified.
- No evidence of signed build attestations was identified.

## 9. Recommended follow-up

- Consider signing release commits or tags.
- Pin GitHub Actions to verified full-length commit SHAs.
- Evaluate hashed Python dependency requirements.
- Verify vendor signatures for downloaded artifacts where available.
- Establish a signing process for internally produced artifacts.
- Verify signatures before deployment or execution.
- Investigate the provenance and digest of the runtime image
  before making claims about its integrity.
- Integrate signing and verification into CI/CD when justified.

Do not treat a version pin, hash, or repository commit as
equivalent to a verified digital signature.

## 10. Evidence integrity

Evidence sources:

- git log -8 signature status output.
- .github/workflows/ci.yml.
- requirements.txt.
- depguard/approval_binding.py.
- depguard/approval_handler.py.
- tests/test_approval_binding.py.
- AWS AgentCore GetAgentRuntime output.
- AWS AgentCore GetHarness output.
- Repository searches for container and signing configuration.

This assessment is limited to the inspected repository paths
and AWS configuration outputs.

It does not establish that the runtime image or all third-party
artifacts are compromised or untrusted.

No signing infrastructure, AWS resource, or deployment
configuration was modified during this assessment.