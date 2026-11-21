#!/usr/bin/env python3
"""Invoke the DepGuard Sentinel Harness and handle analyze_manifest inline calls."""
from __future__ import annotations

import argparse
import os
import sys
import uuid
from pathlib import Path

# Make the project root importable when this file is launched directly
# as `python .\scripts\invoke_harness.py` from the repository root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from depguard.agentcore_client import invoke_with_inline_tool, validate_harness_arn



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Invoke DepGuard Sentinel through Amazon Bedrock AgentCore.")
    parser.add_argument(
        "--harness-arn",
        default=os.getenv("DEPGUARD_HARNESS_ARN"),
        help="Harness ARN. Set DEPGUARD_HARNESS_ARN or pass this option.",
    )
    parser.add_argument("--region", default=os.getenv("AWS_REGION", "us-east-1"))
    parser.add_argument("--profile", default=os.getenv("AWS_PROFILE", "depguard-admin"))
    parser.add_argument("--session-id", default=None, help="Optional runtimeSessionId (33-100 chars).")
    parser.add_argument("--prompt", default=None, help="Prompt to send. Omit to enter it interactively.")
    parser.add_argument("--dry-run", action="store_true", help="Validate settings without contacting AWS.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.harness_arn:
        print(
            "ERROR: Configure DEPGUARD_HARNESS_ARN or pass --harness-arn.",
            file=sys.stderr,
        )
        return 2
    session_id = args.session_id or f"dg-{uuid.uuid4().hex}"
    try:
        validate_harness_arn(args.harness_arn)
        if args.dry_run:
            prompt = args.prompt or "[dry-run placeholder]"
            print("DRY RUN: no se realizaron llamadas a AWS.")
            print(f"Harness ARN: {args.harness_arn}")
            print(f"Region: {args.region}")
            print(f"Profile: {args.profile}")
            print(f"runtimeSessionId: {session_id}")
            print("Inline tool allowlist: analyze_manifest")
            return 0

        prompt = args.prompt if args.prompt is not None else input("DepGuard Sentinel> ").strip()
        if not prompt:
            raise ValueError("El prompt no puede estar vacÃ­o.")

        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError(
                "boto3 no estÃ¡ instalado. InstÃ¡lalo con: python -m pip install --upgrade boto3"
            ) from exc

        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        client = session.client("bedrock-agentcore", region_name=args.region)
        print("Invocando DepGuard Sentinel...\n")
        answer = invoke_with_inline_tool(
            client,
            harness_arn=args.harness_arn,
            runtime_session_id=session_id,
            prompt=prompt,
        )
        print(answer or "[El Harness terminÃ³ sin texto de respuesta]")
        return 0
    except (ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # boto3 ClientError, credential/provider errors, etc.
        # Print a compact diagnostic; do not dump request/session internals.
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        message = getattr(exc, "response", {}).get("Error", {}).get("Message")
        if code:
            print(f"AWS ERROR [{code}]: {message or 'Request failed.'}", file=sys.stderr)
        else:
            print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
