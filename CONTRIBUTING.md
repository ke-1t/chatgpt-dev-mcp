# Contributing to chatgpt-dev-mcp

Thank you for considering a contribution. This project is a thin, security-focused policy wrapper around [`xyTom/coding-tools-mcp`](https://github.com/xyTom/coding-tools-mcp). Contributions are welcome as long as they keep the wrapper thin and the safety contract intact.

## Ground rules

* **Keep the upstream boundary.** Do not copy, vendor, or reimplement `coding-tools-mcp` source code. The runtime dependency stays pinned in `pyproject.toml` (`coding-tools-mcp==0.3.0` unless the maintainers explicitly bump it). The 0.3 command contract uses `command_id`, `kill_command`, and `command:<id>:...` output references; do not restore removed cwd tools with compatibility fakes.
* **Preserve public contracts.** The v25 Stable Gateway surface (exactly 52 direct tools) is immutable; changes that alter tool names, schemas, counts, hashes, or error semantics require maintainer review against the schema-stability tests.
* **Fail closed by default.** New capabilities must deny unknown input, avoid arbitrary shell/exec surfaces, never return credentials or raw secrets, and add tests proving the denial paths.
* **No secrets, ever.** Never commit API keys, tokens, personal configuration, local absolute paths such as `/Users/<name>/...`, or private project names. Use `example.com`, `example.invalid`, temporary directories, or `~` placeholders in fixtures and docs.
* **Minimal diffs.** No unrelated refactors or formatting-only churn.

## Development setup

```sh
git clone https://github.com/ke-1t/chatgpt-dev-mcp.git chatgpt-dev-mcp
cd chatgpt-dev-mcp
uv venv .venv
uv pip install -e .
```

Python 3.11+ is required. macOS is the primary development platform.

## Test and verify

Fast checks (connector lifecycle, read-only `server_info` stability, schema health, public-surface audit):

```sh
.venv/bin/python scripts/verify_fast.py
```

Full checks (complete unittest suite plus disposable smoke suites):

```sh
.venv/bin/python scripts/verify_full.py
```

Please run at least `scripts/verify_fast.py` before opening a pull request, and `scripts/verify_full.py` for anything touching tool surfaces, policy, Git closeout, persistence, or transport.

## Pull request checklist

1. Tests cover both the new behavior and its fail-closed denials.
2. `scripts/verify_fast.py` (and where relevant `scripts/verify_full.py`) pass.
3. No new dependency without prior discussion.
4. No personal data, credentials, or machine-specific paths in any file.
5. Docs (`README.md`, `README.ja.md`, `ARCHITECTURE.md`, `OPERATIONS_GUIDE.md`, `SECURITY_MODEL.md`) updated when behavior contracts change.

## Reporting bugs

Open a GitHub issue with a minimal reproduction that uses disposable fixtures. Redact anything environment-specific. For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of filing a public issue.
