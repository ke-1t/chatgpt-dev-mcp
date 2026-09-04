# Repository agent instructions

These instructions apply to coding agents working in this repository.

## Tool boundary

- Do not use DevMCP or DevMCP Legacy for normal coding work.
- Use the coding agent's native filesystem, shell, Git, worktree, test, lint, build, browser, and subagent capabilities when available.
- Do not invoke DevMCP for workspace/session management, context bootstrap, writer leases, verification, security audit, integration, staging, commits, pushes, or approval workflows.
- DevMCP is a ChatGPT control-plane tool. A coding agent may use it only when the user explicitly requests DevMCP use for that agent in the current task.

## Execution style

- Prefer completing the requested implementation end-to-end instead of returning a patch for the user to apply.
- Run the smallest relevant verification after edits; run broader checks when the change or repository policy warrants it.
- Inspect existing code, tests, configuration, and documentation before introducing new abstractions.
- Preserve unrelated user changes. Never reset, clean, stash, discard, overwrite, or reformat unrelated work unless explicitly requested.
- Do not stop for confirmation on ordinary local, reversible development actions that are already within the user's request and the active sandbox permissions.
- Ask for or surface approval only when the harness itself requires it or the action is materially external, destructive, privileged, or outside the requested scope.

## Repository knowledge

- Treat this file as a short routing map, not a complete manual.
- Use `README.md` for product/setup/operator-facing documentation.
- Use `ARCHITECTURE.md` for the current architecture contract, `OPERATIONS_GUIDE.md` for operator procedures, `SECURITY_MODEL.md` for security invariants, and focused files under `docs/` for design/spec/plan history.
- Prefer the narrowest relevant source of truth over replaying broad conversation history.

## Change discipline

- Keep changes scoped to the task.
- Follow existing naming, formatting, typing, test, and dependency conventions unless the task explicitly changes them.
- Add or update tests for behavior changes when practical.
- Update documentation when a public contract, workflow, configuration, architecture boundary, or operator procedure changes.
- Report what changed, what verification ran, and any remaining blocker or uncertainty.
