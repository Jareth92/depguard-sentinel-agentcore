# DepGuard Sentinel — Inline Function Integration

This addition implements the client-side handoff for the Harness-declared `analyze_manifest` inline function.

## What it does

1. Invokes the Harness with a caller-supplied prompt and a valid `runtimeSessionId`.
2. Reads the `InvokeHarness` event stream and detects `messageStop.stopReason == "tool_use"`.
3. Captures the `toolUseId`, tool name, and streamed JSON input for `analyze_manifest`.
4. Executes only the local `depguard.analyze_manifest.analyze_manifest` function.
5. Sends the matching `toolResult` using the same `runtimeSessionId`.
6. Repeats the handoff if needed, with a small local upper bound.

The Harness stores the pending handoff in session state. The follow-up request sends only the matching `toolResult`; it does not replay the assistant's `toolUse` block.

## Install / update boto3

```powershell
python -m pip install --upgrade boto3
```

The existing analyzer and unit tests use only the Python standard library. `boto3` is needed only for a real AWS invocation.

## Local dry run (no AWS request)

```powershell
python .\scripts\invoke_harness.py --dry-run
```

## Real invocation

The script defaults to profile `depguard-admin`, region `us-east-1`, and the current DepGuard Harness ARN. Override values with flags:

```powershell
python .\scripts\invoke_harness.py `
  --profile depguard-admin `
  --region us-east-1 `
  --harness-arn "arn:aws:bedrock-agentcore:us-east-1:<AWS_ACCOUNT_ID>:harness/<HARNESS_ID>" `
  --prompt "Analiza este package.json: {\"dependencies\":{\"lodash\":\"^4.17.21\"}}"
```

Only invoke after the Harness is `READY`. The current Harness previously returned `CREATE_FAILED`; this client does not repair or deploy Harness resources.

## Security boundaries

- Only the exact tool name `analyze_manifest` is executable by this client.
- Tool arguments must be a JSON object containing exactly `package_json`.
- The analyzer remains deterministic, read-only, and network-free.
- Unexpected tools fail closed; no tool result is fabricated for an unrecognized function.
- The same session ID is reused for every handoff in a turn.
- No shell, filesystem, AWS mutation, approval, or quarantine action is exposed here.
- The local tool result is serialized as JSON text for the model. It is not an authorization decision.

This module is an integration starter. It does not yet implement the HTTP adapter required by `scripts/stress_test.py`, the Gateway/Cedar layer, DynamoDB approvals, or quarantine execution.
