# Contributing

Thank you for your interest in DepGuard Sentinel.

## Development Environment

The project is tested with Python 3.13.

Create a virtual environment and install dependencies.

### Windows (PowerShell)

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Linux and macOS

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

The commands below assume that the virtual environment has been created and dependencies have been installed.

## Running Tests

### Windows (PowerShell)

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

### Linux and macOS

```bash
.venv/bin/python -m unittest discover -s tests -v
```

All tests should pass before submitting a contribution.

## Security Guidelines

- Keep dependency-manifest analysis read-only.
- Preserve the explicit `analyze_manifest` tool allowlist.
- Fail closed on unsupported or malformed tool requests.
- Treat package metadata and user-controlled content as untrusted.
- Never commit real AWS account IDs, Harness ARNs, credentials, access tokens, or private configuration.
- Use synthetic fixtures for AWS identifiers in tests.
- Add or update tests when changing security-sensitive behavior.
- Document new assumptions, limitations, and trust boundaries.

## Pull Requests

A pull request should explain:

1. The problem being addressed.
2. The security impact and relevant trust boundary.
3. The implementation and design trade-offs.
4. The tests executed and their results.

The GitHub Actions workflow runs Python compilation checks and the unit/component test suite.