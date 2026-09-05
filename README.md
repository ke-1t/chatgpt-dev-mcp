# chatgpt-dev-mcp

[日本語版 README](README.ja.md)

`chatgpt-dev-mcp` is a small local policy wrapper around [`xyTom/coding-tools-mcp`](https://github.com/xyTom/coding-tools-mcp). It keeps the upstream workspace/symlink/patch/command/output controls and adds an explicit registry and profile layer for ChatGPT Desktop or another MCP client.

**Relationship to upstream:** this is an independent MIT-licensed wrapper project, not a fork. It does not copy any upstream implementation code. `coding-tools-mcp==0.3.0` is declared as a runtime dependency and its Apache-2.0 notices remain in the installed package; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The upstream 0.3 command contract is canonical at the runtime boundary: commands
are addressed by `command_id`, output references use
`command:<id>:stdout`/`command:<id>:stderr`, and explicit termination uses
`kill_command`. `notifications/cancelled` only cancels the MCP request; it does
not terminate a workspace command. `get_default_cwd` and `set_default_cwd` are
not exposed; commands use an explicit workspace-relative `workdir`. DevMCP's
outer `session_id` remains the development-workspace authority, while
`process_session_id`/the legacy process `session_id` spelling are compatibility
aliases for the upstream command handle. The v26 surface advertises
`command_id` directly. The physical STDIO child retains the upstream workspace
runtime across logical reconnects, so command handles and retained output are
not tied to one MCP handshake.

## Safety contract

* The server accepts a workspace id from a local registry, never an arbitrary path from the model.
* `READ_ONLY` is the default. It exposes inspection and read-only Git tools.
* `READ_WRITE` adds guarded `apply_patch`; upstream validates workspace containment, symlinks, baselines, and atomic writes.
* `DEVELOPMENT` permits guarded `apply_patch` edits in the registered canonical workspace and adds `run_task` for commands already present in the registry under `test`, `lint`, `build`, `dev`, or `format`. The separate `arbitrary_command_preflight`/`arbitrary_command_run` pair accepts only an approval-bound argv array in the exact managed worktree; shell strings, environment injection, composition, privileged executables, and arbitrary paths remain denied. Direct arbitrary `exec_command` is hidden.
* A config-registered `DEVELOPMENT` workspace can be opened directly by its registered ID. The explicit candidate approval/session flow remains available when an isolated detached worktree is preferred.
* `.env*`, `.ssh`, `.aws`, `.config`, `.git`, browser/keychain locations, private-key names, and common credential names are denied before the upstream call. Sensitive records are also removed from Git/list/search responses.
* Output and time limits are capped. Upstream command policy stays in `safe` mode; macOS does not get Linux Landlock confinement.
* Telemetry is disabled by default for this wrapper. Set `CODING_TOOLS_MCP_TELEMETRY=debug` or another explicit upstream value if you have reviewed that choice.
* `workspace_create_worktree` is a compatibility helper gated behind an active approved development session, accepts `HEAD` only, creates a detached worktree under `~/.cache/local-dev-mcp/worktrees`, and never merges, commits, pushes, or auto-switches.
* The default discovery root is only `~/Developer` in `PROJECT_DISCOVERY` mode. Documents, Desktop, and Downloads are not exposed unless explicitly added as `READ_ONLY` roots.
* `workspace_discover` returns bounded, ephemeral candidate IDs. Opening a candidate is always `READ_ONLY`; candidate IDs are not persisted and are invalid after a server restart.
* `list_allowed_files` and `search_allowed_files` require an explicitly configured `READ_ONLY` root and skip hidden, cache, binary, oversized, credential-like, and symlink-escaping paths. `Library`, Application Support, Containers, Group Containers, browser profiles, and credential/token/session stores remain denied even inside an explicitly opted-in root.
* `host_file_preflight` / `host_file_apply` provide a separate shell-free two-phase cleanup boundary. `trash` is R2 and reversible; `delete` is R3 and permanently removes only disposable cache/log/temp roots. Receipts pin exact targets and metadata fingerprints, expire, are one-shot, and fail closed on target drift, sensitive paths, top-level symlinks, or traversal overflow. The tools accept no caller-supplied executable, shell text, environment, arbitrary destination, or general permanent-delete path.
* Discovery never grants write access. An explicit user write-intent claim can use the narrow `workspace_promote_development`/`workspace_project_create` APIs to add only a safe project below a configured `PROJECT_DISCOVERY` root; isolated development remains managed and path-scoped.
* Isolated development sessions run in `~/.cache/local-dev-mcp/worktrees/<opaque-session-id>`. Direct canonical edits remain in the registered repository and are visible to normal Git status/diff immediately.
* Optional workspace `metadata` can describe language, framework, canonical paths, architecture references, and task meanings. It is descriptive only and cannot change a profile or command.
* The Director tools add bounded `director_health`, `context_pack`, `patch_preflight`, `workspace_profile`, verification planning/receipts, task/lease coordination, `security_audit`, and `orchestration_plan`. `security_audit` is a READ_ONLY evaluation of workflow state: it may append one bounded, non-secret audit receipt, but never changes task, session, or lease state; use `director_task_ledger` for an explicit transition. They are local policy tools: `external_execution=false`, verification receipts are caller-provided evidence, and orchestration never creates ChatGPT chats.
* A registered directory without a usable Git `HEAD` remains available for safe workspace inspection, but its Director state is quarantined as `INVALID_WORKSPACE_HEAD`; the shared Director persistence store and other registered workspaces remain usable. Initialize Git locally to clear the quarantine, or keep the workspace read-only while it remains isolated.
* v0.32 adds `git_commit_preflight`, `git_commit`, `git_push_preflight`, and `git_push`. Git closeout is staged-only and approval-gated: every mutation pins the task, working tree, branch, HEAD, diff/index hashes, and (for push) the actual configured push URL/remote state. The tools use fixed Git argv only; unsupported transports, custom remote helpers, repository hooks, arbitrary shell, staging, reset, amend, force push, remote configuration, and credentials are rejected.
* v0.41 persists Director task/session state, dependency edges, lease history, verification/security/integration receipts, baseline-snapshot metadata, idempotent development-start receipts, Git closeout audit receipts, bounded request/provisioning audit events, generation-import provenance, and v26 READ_ONLY handle identity in a private SQLite database at `~/.cache/local-dev-mcp/director.sqlite3` (or the internal `LOCAL_DEV_MCP_DATA_DIR` directory). SQLite schema 14 migrations, WAL/foreign-key checks, bounded retention, corruption fail-closed behavior, and deterministic restart reconciliation are enabled. Approval tokens remain memory-only; no raw arguments, patches, command output, credentials, or side effect is replayed after restart.
* Registered DEVELOPMENT workspaces have persistent `trust_level = standard | trusted_development`. `standard` remains the default. Enabling trust is a separate human-approved Registry capability; revocation is immediate. Trust only removes redundant outer confirmation for bounded operations after all existing technical/evidence gates pass.
* `external_open`, `delivery.integrate`, and `delivery.push` are Registry-only. `external_open` uses fixed macOS `/usr/bin/open` argv with `shell=False`. Trusted delivery reuses the existing exact integration/push preflights; force/non-fast-forward push, unsafe/unknown remotes, destructive operations, scope escapes, sensitive reads, credential expansion, and external user transactions remain outside workspace trust. The Stable Gateway direct surface remains exactly 52 tools.
* `development.session.reconcile_stale_state` is a Registry-only, two-stage lifecycle reconciliation capability. It reads DevMCP-controlled session/task/lease/process/Git evidence, pins an immutable state digest, and requires an execute-time re-read. Dirty worktrees are archived for provenance and retained; missing worktrees are tombstoned only when their source, root, and absence evidence are verifiable. It never removes a worktree, prunes Git metadata, or infers success from a missing path. Legacy worktree roots are accepted only through the explicit `LOCAL_DEV_MCP_LEGACY_WORKTREE_ROOTS` setting.
* `development.session.archive` is the non-destructive retained-evidence path for stale sessions whose recorded source device/inode cannot be verified after a move but whose Git source, revision history, and managed worktree remain independently provable. It requires an explicit owner semantic disposition, archives and verifies the dirty bytes, preserves the original sidecar bytes, records `EVIDENCE_RETAINED_TERMINAL`, and transitions only the DevMCP lifecycle to `cleanup_candidate`; it never repairs source identity, integrates a patch, removes/GCs a worktree, or makes the session an integration candidate.
* `development.session.repair_source_identity` is a Registry-only, two-stage capability for a stale DEVELOPMENT session whose recorded device/inode no longer matches the same verified Git source. It requires an immutable source revision, matching Git common directory, clean retained worktree, and terminal control-plane state; it records old/new identity evidence and never removes or mutates the worktree.
* `runtime.candidate.activate` is a human-approved Registry capability for one exact runtime candidate. It requires a clean Git-pinned source, schema-14 database, 76-tool catalog, healthy doctor/canary receipt, an immutable candidate fingerprint over the deterministic database semantic digest plus physical database identity, and a known-good, clean, schema-compatible rollback authority. The semantic digest includes schema definitions and all logical application rows; only `request_lifecycle_events` rows are excluded because the request audit changes during the gateway lifecycle. An ordinary wrapper remains unbound; the installed v26 deployment binds the official current-runtime reader and fixed deployment executor only when its operator-controlled v26 environment is present. Caller-supplied paths or commands never become restart authority.
* `development.evidence.import_generation` is a human-approved, bounded generation bridge. It reads only one explicitly selected session and its dependency closure from an allowlisted private source database, preserves durable identities, records source/database/sidecar provenance, performs collision checks, and writes through one destination persistence transaction. It never copies, replaces, downgrades, deletes, or manually edits a source database or sidecar; an unstable source fails closed before any destination write.

This is a local development bridge, not proof of external marketplace/provider execution. Keep real production workspaces at `READ_ONLY`; use direct canonical `DEVELOPMENT` only for trusted repositories, or choose a dedicated disposable/feature worktree when source preservation matters.

## Install

The simplest reproducible installation uses `uv` and an isolated environment:

```sh
git clone https://github.com/ke-1t/chatgpt-dev-mcp.git chatgpt-dev-mcp
cd chatgpt-dev-mcp
uv venv .venv
uv pip install -e .
```

Create the registry directory and copy the example:

```sh
mkdir -p "$HOME/.config/local-dev-mcp"
cp config.example.json "$HOME/.config/local-dev-mcp/config.json"
```

Edit the example path to a disposable repository first. The path must be an existing directory; the upstream runtime rejects `/` and the home directory as workspace roots.

## Registry

The default registry is `~/.config/local-dev-mcp/config.json`. Set `LOCAL_DEV_MCP_CONFIG` when testing or when a separate registry is required. IDs are the only workspace selector accepted by the MCP server. If `roots` is omitted, the only root is `~/Developer` in `PROJECT_DISCOVERY` mode. If `roots` is present, it replaces the defaults; add Documents/Desktop/Downloads explicitly only when you intend to make them read-only searchable roots.

```json
{
  "version": 1,
  "roots": [
    {
      "id": "developer",
      "path": "~/Developer",
      "mode": "PROJECT_DISCOVERY"
    }
  ],
  "workspaces": {
    "sample": {
      "path": "/absolute/path/to/sample-repo",
      "profile": "DEVELOPMENT",
      "commands": {
        "test": "pytest",
        "lint": "ruff check .",
        "build": "npm run build",
        "dev": "npm run dev",
        "format": "ruff format --check ."
      }
    }
  }
}
```

An explicit general-file root is opt-in and read-only:

```json
{
  "version": 1,
  "roots": [
    {"id": "developer", "path": "~/Developer", "mode": "PROJECT_DISCOVERY"},
    {"id": "documents", "path": "~/Documents", "mode": "READ_ONLY"},
    {"id": "desktop", "path": "~/Desktop", "mode": "READ_ONLY"},
    {"id": "downloads", "path": "~/Downloads", "mode": "READ_ONLY"}
  ],
  "workspaces": {}
}
```

Use `workspace_list` to see root IDs, `workspace_discover` to find Git
repositories and project-shaped non-Git directories, then `workspace_open` with
the returned temporary candidate ID. Discovery candidates are always
`READ_ONLY` until an explicit user request is passed to the narrow promotion
API.
Discovery candidates cannot inherit write permission. To use
`READ_WRITE`/`DEVELOPMENT`, the user must either keep the operator's existing
registry entry or make an explicit write request that invokes the dedicated
promotion/create API. Those APIs can add only one validated project entry;
they cannot change roots, paths, profiles, commands, or credentials of an
existing workspace. The dedicated project policy tools remain a narrow
exception for an existing `DEVELOPMENT` workspace: they can change only the
allowlisted `isolated_development` policy after an expected config digest
check.

### Register an existing repository safely

For a Git repository that already exists but is not in the local registry, use
the two-step registration boundary:

```text
workspace_register_preflight(path, workspace_id, profile="DEVELOPMENT")
  -> inspect canonical path, Git identity, branch/HEAD/dirty state,
     duplicate/overlap/sensitive-path checks, and config digest
  -> explicit confirmation
workspace_register(preflight_id, confirmation)
```

The command profile is empty unless the caller explicitly supplies bounded
one-line commands. Registration writes only the pinned `workspaces.<id>` entry
with the default isolated-development policy (six parallel sessions,
workspace-wide scope disabled, and integration/commit/push approvals enabled).
The preflight token expires, is one-time, and cannot be reused after a source
or config change. Registration does not create a session or edit the repository;
development still starts through the normal isolated-session/lease gate. The
preflight result explicitly reports the authority that will become available
after registration.

Use `workspace_unregister_preflight`/`workspace_unregister` to remove only the
registry entry. The preflight fails closed while any session, active lease,
active task, or dirty managed worktree remains, and the repository itself is
never deleted. `workspace_registration_update_preflight`/
`workspace_registration_update` can rename a workspace or patch only the
allowlisted isolated-development policy; arbitrary JSON editing, path changes,
command changes, root changes, and approval downgrades are not supported.
For ordinary files, call `list_allowed_files`, `search_allowed_files`, or
`read_allowed_file` with an explicitly configured `READ_ONLY` root. A specific
ordinary local directory can also be opened temporarily with
`readonly_path(action="open", path=...)`. On the frozen v25 surface it returns
a process-local TTL-bound `readonly:*` capability. On `/mcp/v26-canary` it
returns a bounded, TTL-bound handle persisted in the existing Director SQLite
store, so `status`, `list_allowed_files`, `search_allowed_files`, and
`read_allowed_file` may safely use the same handle from another MCP child.
Both surfaces pin inode/device identity and use no-follow path walking; the
handle cannot become a workspace, command, Git, DEVELOPMENT, or writer
authority, and process restart never restores any such authority. Broad OS/user roots,
hidden or credential-like paths, browser/private stores, binary files, and
secret-like contents fail closed.

## Explicit development session

Discovery, direct development, and isolated development are separate paths:

```text
workspace_discover
  -> workspace_open(candidate) [READ_ONLY]
  -> workspace_request_development(candidate, config workspace)
  -> user sees the approval confirmation
  -> workspace_create_development_session(token, confirmation)
  -> isolated DEVELOPMENT worktree
  -> apply_patch -> read-back -> registered test/lint/build -> git_diff
```

For a config-registered DEVELOPMENT workspace, the direct canonical path is:

```text
workspace_list
  -> workspace_open(registered workspace) [DEVELOPMENT]
  -> apply_patch -> read-back -> registered test/lint/build -> git_diff
```

The traditional approval flow still requires an individually registered
`DEVELOPMENT` profile and one-line task commands. For a current explicit user
request, `workspace_promote_development` may add one discovered project to the
allowlisted registry without manual JSON editing; it detects only commands
backed by observed project files/scripts. The approval is bound to the
candidate, project identity, Git root, approved source commit, profile,
confirmation text, and a short expiry; it is consumed once. A canonical dirty
state or later canonical HEAD is recorded as evidence but does not invalidate
that committed baseline while the commit remains available. Integration
rechecks canonical HEAD, cleanliness, conflict, diff, verification, and
security evidence at the integration boundary.

### Create a project and start isolated DEVELOPMENT

`workspace_project_create` creates only a single safe directory directly below
the configured discovery root. `project_type=EMPTY` creates no source files;
`PYTHON` creates `src/` and `tests/`; `NODE` creates `src/`. When requested, it
performs local-only `git init` on an unborn branch, never stages or commits,
then captures a private immutable baseline snapshot and atomically adds the
default approval-preserving DEVELOPMENT policy. The tool can immediately call
the existing `director_development_start` path and return a managed session
plus path-scoped writer lease. Package installation,
network access, remotes, GitHub creation, commit, push, and canonical writes
remain separate operations.

`director_development_start` also accepts `auto_promote=true` only together
with `explicit_user_intent=true` and an ephemeral `candidate_id`. This is a
convenience for the normal “implement this discovered project” request; it is
not arbitrary filesystem write authority. READ_ONLY, discovery-only claims,
root escapes, symlink paths, sensitive directories, path overlap, and unsafe
repository identity fail closed.

After a reconnect or lease expiry, a registered project with
`auto_resume_sessions=true` may first repeat the same
`director_development_start` request for the same owner/task; the safe-local
path retains all session/task/worktree IDs and only reacquires a valid lease.
For policy exceptions, cross-owner recovery, or a disabled policy, inspect
`workspace_list_development_sessions`, request
`workspace_request_development_session_attach(session_id)`, show the returned
confirmation, and then call `workspace_attach_development_session` with its
approval token and exact confirmation. Attach revalidates the registered
workspace, source Git identity/HEAD, managed worktree identity, managed-root
containment, symlink state, and metadata binding. It reuses the same dirty
worktree but issues a new session ID and lease; the expired session is never
silently revived, no second worktree is created, and no canonical path can be
provided by the caller.

An isolated session reports `active` only while its lease is valid and held by
the current runtime. Expiry becomes `expired_dirty_retained` or
`expired_clean`, releases the workspace-switch lock, and never deletes a dirty
worktree. `workspace_status` can report an expired session, but old-lease
`apply_patch` and `run_task` calls fail closed until explicit reattach.

The isolated-session path never checks out, stashes, resets, or overwrites the
source working tree. Direct canonical DEVELOPMENT edits intentionally change
the registered repository and are visible to Git immediately. The MCP exposes
no unguarded commit/push, merge, rebase, reset, checkout, branch-delete,
force-cleanup, or arbitrary-shell operation. The separate commit/push
closeout tools remain staged-only and one-shot approval-gated. Use
`workspace_status` for direct canonical work;
use `workspace_session_status`, `workspace_list_development_sessions`, and
`workspace_close_development_session` to inspect and end an isolated session.
Closing a dirty worktree stops with a review-required error and does not delete it.

Task strings are configuration, not model-provided shell. They must be one line and remain subject to upstream `safe` command policy. Do not put `sudo`, credential reads, package-install commands, network tooling, or destructive commands in the registry.

The compatibility `workspace_create_worktree` tool cannot be used as a second
permission-elevation path. Calls without an active approved development
session are denied; use `workspace_request_development` and
`workspace_create_development_session` first.

## Parallel auto-session development

For a project that the operator explicitly trusts, add the policy below either
under the workspace's `metadata` object or as the workspace-level
`isolated_development` key. The default is disabled; MCP tools cannot create or
elevate this policy.

```json
"isolated_development": {
  "auto_create_sessions": true,
  "max_parallel_sessions": 6,
  "allowed_base": "registered_project",
  "allow_workspace_wide": false,
  "integration_requires_approval": true,
  "commit_requires_approval": true,
  "push_requires_approval": true
}
```

Once enabled, each chat sends only a bounded request to
`director_development_start` with the registered project, task title/owner, and
at least one path/resource. An empty scope is rejected; a workspace-wide lease
requires explicit `workspace_wide=true`, a bounded `scope_reason`, policy
permission, and no active project writer. The Director registers the task,
pins an exact committed baseline, records canonical dirty evidence without
copying it, creates a managed detached worktree, assigns a lease, and returns
the session, task, lease, and worktree identities. A second chat repeats the
same call for the same logical project; the `(workspace_id, request_id)` record
replays the same result instead of creating another session. To share dirty
canonical content, call `director_baseline_snapshot` once and pass its
`source_snapshot_id` to each start request; no snapshot is copied implicitly.
Disjoint paths/resources run in parallel. Overlapping paths or resources are
returned as `PROJECT_CONFLICT`/blocked, and declared dependencies wait as a
later task.

`workspace_open` remains a selected-workspace convenience for older single
client flows. It is not the routing authority for parallel work. Read, diff,
task, and mutation calls should pass the returned `session_id` (and mutations
the matching `lease_id`); `workspace_ref` is an explicit logical-workspace
fallback. A call with an explicit handle never consults the selected workspace.

Typical use:

```text
Chat A: 「Project XのAPIバグを直して」
Chat B: 「Project Xの画面を改善して」
Chat C: 「Project Xのテストを増やして」
```

The shared `project_id`, `logical_workspace_id`, Task Ledger, session,
worktree, lease, verification, audit, and integration records coordinate those
requests. Use `director_status_summary` to see canonical baseline/current HEAD,
active sessions/writers, safe parallelism, task readiness/conflicts, lease
expiry, evidence, integration queue, stale/replan candidates, and cleanup
candidates. Integration still requires a clean canonical preflight and a
separate explicit approval; commit and push remain separately approved. If the
MCP cannot create external ChatGPT conversations, `external_chat_creation` is
reported as `false` and the already-connected chat remains the human boundary.

### Registered project policy changes

Use `workspace_project_policy_get(workspace_id)` to inspect the effective
policy and its SHA-256 `config_digest`. Use
`workspace_project_policy_update(workspace_id, expected_config_digest,
isolated_development)` only for an existing registered `DEVELOPMENT` project.
This is a hard allowlist, not a JSON editor: roots, workspace paths, profiles,
commands, arbitrary metadata, platform/credential settings, GitHub auth,
config version, and workspace creation/deletion are not writable. The server
pins the regular config file identity, rejects symlinks and stale digests,
validates the complete candidate document, writes through an fsync'd
same-directory atomic replace, reads back the result, and returns a durable
before/after receipt. `auto_resume_policy` accepts only
`same_owner_same_task_safe_local`, and approval requirements cannot be changed
from true to false. Setting `allow_workspace_wide=true` does not remove its
explicit reason, zero-active-writer, and approval gates.

## MCP client configuration

For a client that supports local STDIO MCP servers, use the absolute executable and set the working directory to the project:

```json
{
  "mcpServers": {
    "chatgpt-dev-mcp": {
      "command": "<path-to-project>/.venv/bin/chatgpt-dev-mcp",
      "args": [],
      "cwd": "<path-to-project>",
      "env": {
        "LOCAL_DEV_MCP_CONFIG": "$HOME/.config/local-dev-mcp/config.json",
        "CODING_TOOLS_MCP_TELEMETRY": "off"
      }
    }
  }
}
```

Replace `<path-to-project>` with the absolute path where you cloned this repository. The JSON above is for a local-STDIO client such as Codex or desktop developer tooling. It is not the normal ChatGPT connection path. When ChatGPT Developer Mode and a Secure MCP Tunnel are available on your account, the path is:

```text
Normal ChatGPT
  -> private Developer Mode app: ChatGPT Dev MCP
  -> Secure MCP Tunnel: chatgpt-dev-mcp-local
  -> tunnel-client LaunchAgent
  -> local STDIO chatgpt-dev-mcp
  -> registered workspace
```

Keep any Tunnel runtime key in your local secret store (for example macOS Keychain). Never paste a runtime key into ChatGPT or into this repository. Availability of Developer Mode, private apps, and Hosted/Secure MCP Tunnels depends on your ChatGPT account, workspace, and app build; entitlement for full write access through a Hosted MCP app is not guaranteed.

The Streamable HTTP prototype below is validated locally only. A Hosted Secure MCP Tunnel + ChatGPT HTTP end-to-end run has not been executed by this project; STDIO remains the verified production path, fallback, and rollback transport.

### ChatGPT connector compatibility

The STDIO entrypoint runs a long-lived broker whose physical child owns one process-scoped `WrapperRuntime`. Each logical MCP connection gets fresh `InitializeReplayState` and request-registry state while process-owned workspace bindings, managed development runtimes, process sessions, and Director handoff state remain with the physical child. The measured `server/discover` plus duplicate `initialize` probe is handled by one bounded, compatible pre-operation replay in that connection. After normal operation, the next connection boundary retires only protocol-local state; handshake parameters, request-id epochs, and `id=0` are not treated as durable workspace/session authority. Explicit connection markers are honored when present, and stale marker traffic is rejected. A live side-effecting or outcome-ambiguous request blocks replacement with `outcome_unknown`/`read_back_required`; no write or external side effect is replayed. Director SQLite, task/lease state, retained worktrees, verification receipts, and v26 READ_ONLY handles remain persistent and can be resumed only through their explicit identity and policy checks. Request audit events pin the schema revision/hash, transport generation, physical child, and logical connection at acceptance; reconnects cannot rewrite that identity. The upstream tracking issue is [xyTom/coding-tools-mcp#39](https://github.com/xyTom/coding-tools-mcp/issues/39).

The wrapper advertises `initialize.capabilities.tools.listChanged=true`. The v25 Stable Gateway exposes exactly 52 direct MCP tools under `tool-registry-v25-stable`; `/mcp/v26-canary` exposes the versioned 76-tool canary surface under `tool-registry-v26-canary`. Long-tail capabilities such as `director_audit_log`, `director_usage`, host-file mutation, platform-profile registration, and verified-commit helpers are discovered and invoked through `capability_catalog` / `capability_describe` / `capability_preflight` / `capability_execute`. Binding-free direct diagnostics include `server_info`, `director_health`, `check_exec_environment`, `workspace_list`, and `workspace_list_development_sessions`. `server_info` always reports `tool_schema.revision`, `tool_schema.count`, and a deterministic lowercase SHA-256 `tool_schema.hash` over the wrapper-visible direct tool definitions; profile/workspace details are added only after selection. Count/hash provide an independent exact-definition check, and Registry-only capabilities are not misrepresented as direct tools. `director_audit_log` returns bounded request/provisioning evidence without raw inputs or outputs when invoked through the Capability Registry. This release does not add a first-scan `notifications/tools/list_changed` compatibility shim or emit unsolicited notifications. If a ChatGPT App still shows an older schema snapshot, reconnect or rescan it from the ChatGPT side after confirming this local metadata.

`server_info.health` now reports `health-v1` diagnostics for the live process,
registry validity, local `tools/list` versus schema consistency, and (for the
STDIO runtime) the loopback Tunnel `/healthz`/`/readyz` probe. The HTTP
`/healthz` and `/readyz` endpoints independently validate the wrapper registry,
schema, and session manager; they do not depend on production Tunnel health.
It never returns credentials,
command bodies, raw config contents, or external HTTP response bodies. The
server cannot inspect ChatGPT's private in-memory cache: compare the client's
observed count/revision/hash with `server_info.tool_schema` to classify
`matched`, `mismatched`, or `not_available`.
The STDIO runtime diagnostics additionally include `protocol_state`,
connection-local `transport_generation`/`protocol_session_generation`, and
`logical_connection_id`/`protocol_runtime_identity` so a persistent Tunnel
child can be distinguished from the fresh logical runtime currently using it.

### Disposable Streamable HTTP prototype

The repository also contains a rollback-safe, wrapper-owned Streamable HTTP
prototype. It is separate from the production STDIO entrypoint and binds to
loopback by default:

```sh
LOCAL_DEV_MCP_CONFIG="$HOME/.config/local-dev-mcp/config.json" \
  .venv/bin/python -m chatgpt_dev_mcp.http_entrypoint --host 127.0.0.1 --port 8000
```

`POST /mcp` creates a server-generated opaque `Mcp-Session-Id`; each session
gets a new `WrapperRuntime`. Unknown, expired, deleted, and reused session IDs
fail closed, and `DELETE /mcp` closes the bound runtime. Active sessions, idle
TTL, and retired-session metadata are bounded; an over-limit initialize fails
closed. Requests in one session are serialized by a per-session mutex. Request
socket timeouts, maximum in-flight requests, active session count, idle TTL,
and a bounded session-creation rate fail closed under load. `GET /healthz` and
`GET /readyz` expose non-tool JSON diagnostics for transport status, active
sessions, `health-v1`, and the wrapper schema revision/count/hash; readiness
rechecks the local registry and session manager on every request. The HTTP path calls the same wrapper dispatcher as STDIO,
so it preserves the exact 52-tool `tool-registry-v25-stable` surface, `listChanged=true`, the
sensitive-path checks, and the hidden dangerous operations. The four Git
closeout tools remain separate operations and never auto-chain commit to push.

Use `scripts/smoke_http_session.py` for a disposable local check. A Tunnel
experiment must use a separate temporary `server_urls` profile pointing at
`http://127.0.0.1:<port>/mcp`; do not change the production STDIO profile,
LaunchAgent, ChatGPT app, credentials, or local registry. The HTTP prototype
does not publish a non-loopback listener or replace the current ChatGPT path.

## Daily loop

1. Call `workspace_list` to see explicitly registered workspaces and allowed roots.
2. Use `workspace_discover` under the Developer discovery root, then open a returned candidate with `workspace_open` (always `READ_ONLY`).
3. For an explicitly configured Documents/Desktop/Downloads root, use `list_allowed_files` or `search_allowed_files` for bounded ordinary-file discovery.
4. For an approved code change, call `workspace_request_development`, show the returned confirmation to the user, then call `workspace_create_development_session` only after explicit confirmation.
5. Call `workspace_status` / `workspace_session_status`, then use `read_file`, `list_files`, `search_text`, `git_status`, and `git_diff` with the explicit `session_id` returned by the isolated start.
6. For concurrent writers, create Task Ledger records, acquire `director_writer_lease` with `task_id`, `paths[]`, and optional `resources[]`, then pass the matching `session_id` and `lease_id` to both `patch_preflight` and `apply_patch`. Empty scopes fail closed; overlapping path/resource scopes fail closed across the logical project.
7. Use only config-registered `run_task(test|lint|build|format|dev)` commands with `session_id`. For a separately approved bounded argv operation, use `arbitrary_command_preflight` then `arbitrary_command_run`; it uses a fixed cwd, expected HEAD, scrubbed environment, timeout, and bounded output. Poll with the returned canonical `command_id` (the outer `process_session_id` alias is retained for compatibility) plus `development_session_id`; stop a long-lived task with `task_stop`. Record verification with the same session/task identity; receipts are pinned to the current revision/diff and become stale after later writes.
8. Run `security_audit` after verification. Its deterministic receipt is pinned to the same worktree, revision/diff, and verification receipt; the receipt is task-agnostic, retries retain the first audit timestamp, and conflicting identity reuse fails closed. `workspace_integration_preflight` requires matching verification/security evidence before it issues an explicit integration confirmation challenge.
9. Use `workspace_session_diff` to review a retained DEVELOPMENT session. After an approved `workspace_integration_preflight`, `workspace_integrate_development_session` may apply that exact patch to a clean/conflict-free canonical repository. It never commits, pushes, checks out, or deletes the session worktree.
10. Close with `workspace_close_development_session`; clean worktrees are removed, dirty worktrees are retained for review.
11. Treat `ok=false`, `isError=true`, `STALE_WRITE_BASE`, timeouts, permission denials, or ambiguous task/session state as a stop. Do not retry an outcome-unknown external action.
12. For an approved local closeout, ensure the Task Ledger has fresh verification/security receipts, then call `git_commit_preflight`. Review its staged/unstaged/untracked state, exact diff/index hashes, message, and approval challenge. Only a human may pass the one-shot confirmation to `git_commit`; it never stages files or pushes.
13. After a successful commit, call `git_push_preflight` with the configured remote name, current branch, and exact commit. Review remote URL hash, expected remote branch state, protected/default branch policy, and approval challenge. Only a human may call `git_push`; a stale or unknown network result is not success and is never retried automatically.
14. Review `workspace_status` and `git_diff` after closeout. This server never auto-chains commit to push, changes remotes/credentials, or accepts reset/amend/force operations.

### Director parallel-development contract

`director_writer_lease` is bound to the real working-tree identity and logical
project. A lease records `workspace_id`, `working_tree_id`,
`owner_id`, `task_id`, normalized `paths[]`, optional runtime `resources[]`,
`base_revision`, scoped file hashes, `lease_id`, and TTL. Parent/child path
overlap conflicts across sessions in the same logical project; runtime resources such as
`port:8765`, `sqlite:test-db`, browser profiles, or Tauri instances conflict
globally while leased. Different logical projects may own the same relative path.

`apply_patch` and `patch_preflight` require a covering active lease. They reject
missing coverage as `WRITER_LEASE_REQUIRED`, wrong-tree leases as
`WRITER_LEASE_SCOPE_MISMATCH`, and changed HEAD/file content as
`STALE_WRITE_BASE`. After a successful owned patch, the lease snapshot advances
to the writer's new state while prior verification/security receipts are
invalidated.

`orchestration_plan` understands dependency ordering: two independent writers
with overlapping paths/resources conflict, while `A -> B` may intentionally
touch the same path because they cannot run concurrently. The plan exposes
parallel batches, suggested lease scopes, an integration owner, and
`max_safe_parallel_writers`.

### Which interface to use

* **Normal ChatGPT + ChatGPT Dev MCP**: repository investigation, targeted bug fixes, small/medium implementation, approved tests/lint/build tasks, diff review, code review, and worktree-based development.
* **Codex**: very large repo-wide refactors, complex autonomous debugging, richer browser/GUI automation, or work where long autonomous execution is more valuable than conversational iteration.
* **Direct IDE/terminal**: trivial manual operations, highly sensitive manual actions, and interactive visual debugging.

## Verification

For the normal development loop, use the verification ladder below. These
commands run with the repository virtual environment, fail fast, and do not
restart the managed Tunnel or change LaunchAgent configuration.

Fast local checks (connector lifecycle, read-only `server_info`, schema, and
public-surface consistency):

```sh
.venv/bin/python scripts/verify_fast.py
```

Full local checks (the complete unittest suite plus disposable policy,
development-session, schema, HTTP, and public-surface smoke tests):

```sh
.venv/bin/python scripts/verify_full.py
```

Live lifecycle checks (the installed executable's raw MCP protocol, repeated
global diagnostics, reconnect/child restart, three-client isolation, and the
managed Tunnel health/readiness endpoints):

```sh
.venv/bin/python scripts/verify_live_lifecycle.py
```

The live command requires the managed Tunnel to already be running. It does
not restart the Tunnel. Set `LOCAL_DEV_MCP_TUNNEL_HEALTH_URL` only when the
managed health endpoint uses a different loopback URL.

Run the local disposable-repository smoke test:

```sh
.venv/bin/python scripts/smoke_disposable.py
```

The test creates a temporary Git repository and proves safe-file access, parent-path denial, symlink escape denial, sensitive-file denial, read-only patch denial, guarded patch success, approved task success, and command path escape denial. It never touches a real project.

Run the isolated development-session smoke test:

```sh
.venv/bin/python scripts/smoke_development_session.py
```

It uses a temporary HOME and repository to prove READ_ONLY discovery,
explicit approval, detached worktree patch/read/diff/test, source preservation,
arbitrary-shell denial, and dirty cleanup refusal.

Run the discovery-hardening smoke test:

```sh
.venv/bin/python scripts/smoke_discovery.py
```

It uses a disposable HOME to prove real Git identity/HEAD checks, nested-repo
discovery, complete staged/unstaged/untracked dirty metadata, sensitive-path
omission, binary/oversized-file omission, and depth/entry limits.

Run the schema-health smoke test:

```sh
.venv/bin/python scripts/smoke_schema_health.py
```

It compares `initialize`, `tools/list`, and `server_info` in a temporary
STDIO runtime, verifies local consistency, and classifies a simulated stale
23-tool observation as `mismatched` without changing the tool surface.

Run the final public-surface audit:

```sh
.venv/bin/python scripts/audit_public_surface.py
```

It verifies the exact 52-tool Stable Gateway manifest, Registry exposure for
long-tail capabilities, schema/health metadata, dangerous-tool absence,
`listChanged=true`, and the intentionally absent notification shim.

Run the installed executable's live MCP schema regression test:

```sh
DEVMCP_RUN_LIVE_TESTS=1 .venv/bin/python -m unittest -v tests.test_live_schema
```

It starts `.venv/bin/chatgpt-dev-mcp` as a real STDIO child, compares its
`tools/list` response with the in-process registry, checks explicit
workspace/session routing fields and global diagnostics, and verifies that an
old client schema is reported as `CLIENT_TOOL_SCHEMA_STALE` with
`reconnect_and_rescan`.

Run the disposable HTTP session/health smoke:

```sh
.venv/bin/python scripts/smoke_http_session.py
```

It verifies per-session isolation, bounded lifecycle behavior, 52-tool Stable Gateway schema
parity, and the loopback `/healthz`/`/readyz` contract without touching the
production STDIO Tunnel.

See [ARCHITECTURE.md](ARCHITECTURE.md),
[OPERATIONS_GUIDE.md](OPERATIONS_GUIDE.md), and
[SECURITY_MODEL.md](SECURITY_MODEL.md) for the current platform contract.

### Verified disposable-workspace behavior

The disposable smoke suites exercise the following through normal MCP calls against temporary repositories:

* a `READ_ONLY` workspace denies sensitive files, parent paths, an escaping symlink, arbitrary `exec_command`, and `apply_patch` with structured errors (`SENSITIVE_PATH_DENIED`, `PATH_OUTSIDE_WORKSPACE`, `SYMLINK_ESCAPE`, and `PROFILE_DENIED`);
* a `READ_WRITE` workspace completes `read -> apply_patch -> read -> git_diff`, changing only the intended file; no commit or push occurs.
* a `DEVELOPMENT` workspace completes `run_task(test)` failure -> minimal patch -> `run_task(test)` success -> `git_diff`.
* `workspace_create_worktree(ref=HEAD)` creates a detached worktree under the allowed cache root with `external_execution=false`, `merge=false`, and `push=false`; the canonical worktree stays unchanged.

These are local/fixture behaviors proven by the disposable suites. They do not describe any hosted or external service entitlement.

### Verified safe discovery behavior

The temporary-HOME regression suite verifies that:

* the default root is only `~/Developer` and general-file roots require explicit config opt-in;
* nested Git repositories are discoverable without traversing `.git` internals, hidden directories, or package caches;
* a Git candidate is returned only when `git rev-parse --show-toplevel` matches its path and either a real HEAD or a valid symbolic unborn branch exists; malformed `.git` markers remain omitted, while project-shaped non-Git directories are reported as `PROJECT_DIRECTORY`;
* Git metadata marks repositories dirty when staged, unstaged, or untracked changes are present;
* candidate IDs are opaque, process-local, rejected when forged, and invalid after restart;
* `workspace_open` re-checks candidate containment and symlinks, and candidates always open `READ_ONLY`;
* a Developer discovery root cannot grant `READ_WRITE`/`DEVELOPMENT`; an individually configured `READ_WRITE` project uses the guarded patch flow, while an individually configured `DEVELOPMENT` project can use guarded canonical edits or the explicit isolated-session flow;
* file listing/search enforce relative paths, per-directory entry/depth/visited-directory/result/byte limits, and skip credentials, binary, oversized, cache, and symlink-escaping paths.

### Verified explicit development behavior

The temporary development-session suite verifies that a discovered candidate
cannot write until the user-facing approval challenge is confirmed. After
approval, only a config-registered `DEVELOPMENT` project can create a managed
detached worktree. The suite covers source identity/HEAD/symlink/`.git`
TOCTOU changes, approval expiry/replay/restart, canonical lifecycle boundary
states, lock release for expired dirty worktrees, new-lease reattach with a
preserved diff, session status/list consistency, patch and registered task
execution, source dirty preservation, clean cleanup, dirty cleanup refusal,
stale sidecars, and hidden commit/push/arbitrary-shell tools.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security-sensitive findings have a
private reporting path in [SECURITY.md](SECURITY.md); please do not open public
issues for them.

## License

This wrapper is released under the MIT License; see [LICENSE](LICENSE).
The `coding-tools-mcp` runtime dependency is licensed under Apache-2.0 by its
upstream authors and is not modified or redistributed in source form here; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
