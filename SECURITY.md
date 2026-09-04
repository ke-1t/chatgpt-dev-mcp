# Security Policy

## Scope

`chatgpt-dev-mcp` is a local policy wrapper that runs on the operator's machine and mediates an MCP client's access to explicitly registered local workspaces. It is designed to fail closed: no arbitrary shell, no credential exposure, no unguarded Git mutation, and no path escapes.

## Supported versions

Only the latest tagged release on the `main` branch receives security fixes.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for suspected vulnerabilities.

Use GitHub's private security advisory feature ("Report a vulnerability" on this repository's Security tab). If that is unavailable, contact the maintainer through a private channel listed on the maintainer's GitHub profile.

Include:

* affected version/commit,
* a minimal reproduction (disposable fixtures only — never real credentials or private repositories),
* expected vs. actual behavior,
* any structured error codes observed (for example `SENSITIVE_PATH_DENIED`, `SYMLINK_ESCAPE`).

## What belongs here

* Workspace/symlink/path containment bypasses.
* Credential-, token-, or secret-bearing output leaks.
* Approval/session/lease bypasses, including commit/push gate bypasses.
* Sensitive-file denial gaps (`.env*`, `.ssh`, `.aws`, keychains, browser stores).
* Registry/config integrity issues (digest pinning, atomic replace, TOCTOU).

## Out of scope

* The upstream `coding-tools-mcp` runtime itself — report those to [`xyTom/coding-tools-mcp`](https://github.com/xyTom/coding-tools-mcp/security) so fixes benefit both projects.
* Social engineering of ChatGPT accounts or ChatGPT platform entitlements.
* Issues requiring an operator to intentionally register a hostile workspace as fully trusted with approvals disabled.

## Disclosure policy

This is a personally maintained OSS project, so responses are best-effort: we
aim to acknowledge reports within 7 days and will work on a fix as promptly as
the maintainer's availability allows. We will credit reporters in release
notes unless anonymity is requested. Please allow a coordinated disclosure
window before publishing technical details.
