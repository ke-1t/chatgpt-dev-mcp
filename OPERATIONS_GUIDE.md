# chatgpt-dev-mcp Operations Guide

## Safe daily workflow

The v0.41 Director state database is kept outside the repository at
`~/.cache/local-dev-mcp/director.sqlite3` (or the internal
`LOCAL_DEV_MCP_DATA_DIR` directory). It is private SQLite state, not a task
queue: migrations and integrity checks run at startup, terminal history is
bounded by retention, and a corrupt/unknown database blocks Director mutation.
After a child restart, inspect `server_info.health.director_persistence` and
the normal workspace/task/lease tools. Expired leases and stale evidence must
be revalidated before reuse. A project may explicitly opt into bounded
same-owner/same-task local session resume; otherwise stale sessions remain
attach-gated. Commit/push/integration are never replayed.

1. Check `server_info` before selecting a workspace. The Director v0.41 Stable
   Gateway exposes exactly 52 direct tools under `tool-registry-v25-stable`;
   confirm count/hash and
   `health-v1` consistency. When client schema evidence is available, pass it
   to `director_health`. If `schema_compatibility.rescan_required=true` or
   `CLIENT_TOOL_SCHEMA_STALE` is returned, reconnect/rescan the client before
   relying on newly added tools.
2. Call `workspace_list` to inspect registered roots and workspaces.

### STDIO reconnect lifecycle

The production Tunnel may retain one broker process and one process-scoped
`WrapperRuntime`; each logical MCP connection receives fresh protocol/request
state. A
pre-operation duplicate `initialize` is replayed once. After `tools/list` or
`tools/call`, a later `initialize` starts a new logical runtime; request IDs,
`id=0`, handshake-parameter equality, and `server/discover` are not used to
guess that boundary. If a side-effecting request is still active, replacement
fails closed with `outcome_unknown` and `read_back_required`; do not retry the
write. Logical runtime retirement leaves Director/session/lease records and
retained worktrees persistent; a real broker shutdown still marks active
sessions stale for explicit recovery. Persistent development sessions are
resumed only with their explicit session handle, and workspace selection is
not copied to the new runtime.

For one-off inspection outside configured roots, `readonly_path` may open only
a specific ordinary local directory allowed by policy. On the frozen v25
surface the returned `readonly:*` handle is process-local and TTL-bound. On
`/mcp/v26-canary`, its bounded handle identity is stored in the existing
Director SQLite database, so `status`, `list_allowed_files`,
`search_allowed_files`, and `read_allowed_file` can continue from another MCP
child. The v26 handle still expires, is inode/device and path-confined, and
cannot be passed to `workspace_open`, execution, Git, DEVELOPMENT, or writer
tools. An unknown, expired, closed, or identity-drifted handle fails closed.

### Bounded host filesystem mutation

Use `host_file_preflight` and `host_file_apply` for local cleanup instead of
opening arbitrary command authority. Preflight does not change the target: it
canonicalizes each path, checks policy, records metadata-only recursive
fingerprints and estimated bytes, and returns a short-lived exact confirmation.
Apply accepts only that preflight ID and confirmation, revalidates the targets,
then consumes the receipt before performing the pinned operation.

- `trash` is R2 and reversible. It is allowed for ordinary paths beneath the
  user's home and top-level `.app` bundles beneath `/Applications`, subject to
  the sensitive-root and symlink deny rules.
- `delete` is R3 and irreversible. It is limited to disposable roots such as
  `~/Library/Caches`, `~/Library/Logs`, `~/.cache`, and bounded cache/temp
  subtrees beneath `~/.codex`.

If a target changes after preflight, the receipt expires, confirmation differs,
or inspection crosses a denied/oversized boundary, do not retry the old apply;
run a fresh preflight. The tools accept no shell string, executable, environment
injection, arbitrary destination, or general-purpose permanent-delete path.

### Automatic parallel sessions

For a registered `DEVELOPMENT` project, the operator may explicitly enable
`isolated_development.auto_create_sessions=true` with a bounded
`max_parallel_sessions` (maximum 16). MCP cannot write or elevate this local
policy through an arbitrary editor. Use `workspace_project_policy_get` and
`workspace_project_policy_update` for the narrow allowlisted policy keys only;
each update requires the current config digest and returns a before/after
receipt. Each chat calls `director_development_start` with the project ID, task
title/owner, and a non-empty path/resource scope. Empty scope is rejected;
`workspace_wide=true` additionally requires `scope_reason`, policy permission,
and zero active project writers. The Director pins an exact committed baseline,
records dirty canonical evidence without copying it, provisions a managed
detached worktree/session, and assigns the lease. To share dirty canonical
content, first call `director_baseline_snapshot` and pass its immutable
`source_snapshot_id`; no dirty content is copied implicitly.

Optional `isolated_development.auto_resume_sessions=true` with
`auto_resume_policy="same_owner_same_task_safe_local"` allows a disconnected
retained session to reacquire a fresh writer lease without changing its
session/task/worktree identity. Resume is fail-closed unless the stored owner,
task, registered project, source commit, managed worktree identity, path/resource
scope, and local policy still match. Cross-owner takeover, workspace-wide
scope, terminal sessions, missing worktrees, and active conflicting leases do
not auto-resume. Manual attach remains the fallback.

The policy update tool cannot change roots, workspace paths, profiles,
commands, platform credentials, authentication, metadata, or config version.
It rejects symlinked config files, identity/digest races, unknown keys,
invalid values, and any `true -> false` approval downgrade. A policy change is
not a workspace-wide writer approval: the explicit scope reason, zero-writer
preflight, integration approval, commit approval, and push approval boundaries
remain in force.

Use `director_status_summary` for the shared project view: baseline/current
canonical HEAD, dirty evidence, sessions, writers, task/dependency readiness,
lease expiry, verification/security receipts, integration queue order,
stale/replan candidates, and cleanup candidates. Disjoint path/resource scopes
run in parallel; overlap returns `PROJECT_CONFLICT` or a dependency wait.
Integration remains an explicit clean-canonical preflight and approval, and
commit/push remain separately approved.

### Stale session lifecycle reconciliation

Use the Registry capability `development.session.reconcile_stale_state` only
for one explicitly selected session at a time. `capability_preflight` returns
the bounded DevMCP evidence record and immutable `state_digest`; call
`capability_execute` only with that exact preflight. The handler re-reads the
session row, sidecar, Git worktree metadata, task ledger, leases, processes,
and receipts before any lifecycle write. Active/nonterminal evidence,
identity/root mismatch, or evidence conflicts fail closed. An existing dirty
worktree is archived for provenance and left byte-for-byte in place; a missing
worktree is recorded as `cleanup_candidate`/tombstoned only when its source and
Git absence evidence are verifiable. Reconciliation never runs `worktree
remove`, `worktree prune`, reset, clean, stash, or canonical relocation. Legacy
worktree roots must be listed explicitly in
`LOCAL_DEV_MCP_LEGACY_WORKTREE_ROOTS`; arbitrary filesystem scans are not an
authority source. Re-run preflight after any failure or state change rather
than replaying an old execute receipt. If a durable receipt exists but its
sidecar write failed, a fresh execute may repair only when the receipt and all
immutable source/worktree/control-plane evidence still match; a failed repair
remains an error. Staged/index-dirty worktrees stay blocked because the
existing archive contract cannot prove exact index-byte preservation.

When the source identity itself is no longer verifiable but the source Git
history and retained worktree are independently provable, use the Registry
capability `development.session.archive`. It is a bounded, non-destructive
archive-and-terminal operation: an explicit owner semantic disposition is
required; the original sidecar bytes and worktree stay in place, the durable
archive and reconciliation receipts are read back, and the session is marked
`EVIDENCE_RETAINED_TERMINAL`/`cleanup_candidate`. This does not repair source
identity, integrate the patch, or authorize GC. Active tasks, leases,
processes, unresolved dirty state, identity conflicts, and unknown evidence
remain blockers.

### Runtime candidate activation and generation import

`runtime.candidate.activate` is the only Registry path for repinning a managed
runtime. It is human-approved and requires a fresh canary receipt, exact Git
HEAD/optional base and patch identity, a healthy schema-14 database, the
expected 76-tool catalog, healthy doctor/tunnel evidence, isolated state and
port evidence, a deterministic semantic database digest, physical database
identity, and a known-clean, schema-compatible last-known-good rollback
authority. The semantic digest includes the schema definitions and every
logical application row; only `request_lifecycle_events` rows are excluded
because the request audit changes during the gateway lifecycle. The
ordinary wrapper remains unbound; the installed v26 wrapper binds the official
read-only current-runtime reader and fixed deployment executor when
`LOCAL_DEV_MCP_V26_DURABLE_ROOT` is explicitly present. The binding uses the
operator-owned deployment wrapper/manifest and a fixed LaunchAgent label; it
does not accept caller-supplied commands or database paths. Never treat a
missing binding as permission to restart a service.

The v26 wrapper invokes `bootstrap-v26-runtime` before importing the server.
That check opens the existing schema-14 Director database read-only and fails
closed on an incompatible or unsafe state. It never copies, downgrades,
deletes, or edits a database, and it does not import v25 evidence.

### Native external operator

The `local-dev-mcp-operator` entrypoint is a private-canonical maintenance
surface. It is intentionally omitted from the public publication artifact;
public installations must use the ordinary MCP surface. The private native
operator documentation is maintained outside the public publication tree.

`development.evidence.import_generation` is the bounded bridge for retained
state from another recognized generation. Preflight pins the private source
database inode/hash/data-version, schema, selected session, task dependency
closure, optional sidecar provenance, and destination identity. Execute
revalidates those pins and writes through one destination persistence
transaction. A changing source, cross-workspace record, identity collision, or
missing dependency fails closed; the source database and sidecar are never
copied, replaced, downgraded, deleted, or manually edited. Re-run a fresh
preflight after a failure instead of retrying an old receipt.

`workspace_open` is only a selected convenience view. After a parallel start,
pass its returned `session_id` to every read/diff/task/verification call and
pass the matching `lease_id` to mutations. `workspace_ref` is an explicit
logical-workspace fallback. Explicit handles resolve directly to the persisted
session and managed worktree, so another chat's `workspace_open` cannot change
the target or lifecycle of the call.

### Explicit project provisioning

To register an existing Git repository without hand-editing the registry, use
the approval-gated pair first:

```text
workspace_register_preflight(path, workspace_id, profile="DEVELOPMENT")
  -> inspect and pin path/Git/config state
workspace_register(preflight_id, confirmation)
```

The preflight rejects sensitive credential/browser paths, duplicate IDs and
overlapping paths, non-Git directories, unsafe ownership/permissions, and
stale config state. Commands are `{}` unless explicitly supplied. The write is
an allowlisted atomic addition only; no session, commit, push, remote, or
canonical repository write is implicit.

When retiring a registration, use
`workspace_unregister_preflight`/`workspace_unregister`. It never removes the
repository and is blocked by any session, active lease/task, or dirty managed
worktree. `workspace_registration_update_preflight`/
`workspace_registration_update` are limited to an identifier rename and
allowlisted isolated-development policy keys; paths, roots, commands, and
approval requirements cannot be changed there.

When the current user request is clearly a write request, the normal no-manual-
config path is:

```text
workspace_discover
  -> workspace_project_create                 # new project
  -> workspace_promote_development            # existing discovered project
  -> director_development_start               # optional auto_promote shortcut
  -> isolated session + path-scoped lease
```

`workspace_project_create` accepts only a safe project name and configured
`root_id`. It creates one directory atomically, optionally runs local-only
`git init -b main` (an unborn branch is supported), detects commands only from
observed files/scripts, and writes only the new `workspaces.<id>` registry
entry. A new project also receives an immutable baseline snapshot before its
isolated session is started. `workspace_promote_development` requires
`intent=EXPLICIT_USER_REQUEST`; `READ_ONLY`, discovery-only, arbitrary paths,
root escapes, symlinks, sensitive directories, duplicate/overlapping projects,
and unsafe ownership fail closed. Both operations use a lock, expected digest
when supplied, schema validation, fsync'd atomic replacement, read-back, and
private SQLite provisioning events. They never stage, commit, add remotes,
install dependencies, access credentials, integrate, or push.

For a one-call existing-project start, pass `candidate_id`,
`auto_promote=true`, and `explicit_user_intent=true` to
`director_development_start`. The intent claim is an authority boundary, not a
general filesystem write grant; all path and repository invariants are still
rechecked server-side.

If a project is created with `initialize_git=false`, it can be registered for
inspection but cannot start a DEVELOPMENT session until the operator performs
the separate local Git initialization operation. Empty projects still use a
future-file path scope (`README.md`) rather than an inferred workspace-wide
lease.
3. For direct canonical editing, call `workspace_open` with the registered
   `DEVELOPMENT` workspace ID, then inspect `workspace_status` before editing.
   Use `director_health` to distinguish local runtime health from unavailable
   ChatGPT-side schema evidence, and `workspace_profile` to review the bounded
   project profile.
4. For an isolated worktree, call `workspace_discover` under the
   `PROJECT_DISCOVERY` root when looking for a project. Treat returned candidate
   IDs as temporary.
5. Call `workspace_open` with that candidate ID. Inspect using
   `workspace_status`, `read_file`, `list_files`, `search_text`, and read-only
   Git tools. The profile must remain `READ_ONLY`.
6. For an explicitly isolated change, call
   `workspace_request_development` with the matching config workspace. Show
   the returned confirmation to the user.
7. Only after exact confirmation, call
   `workspace_create_development_session`.
8. Before a write, create or reuse the task's `director_task_ledger` record and
   acquire `director_writer_lease` with `owner_id`, `task_id`, normalized
   `paths[]`, and any exclusive runtime `resources[]` such as `port:8765`,
   `sqlite:test-db`, a browser profile, or a Tauri instance. The returned lease
   is bound to the selected real `working_tree_id`, baseline HEAD, and scoped
   file hashes. Different chats may hold disjoint path leases concurrently
   across separate managed worktrees in one logical project. Parent/child path
   overlap and duplicate runtime resources are rejected project-wide.
9. Call `patch_preflight` with the proposed patch and that `lease_id`, then pass
   the same `lease_id` to `apply_patch`. Missing coverage fails as
   `WRITER_LEASE_REQUIRED`; a lease for another worktree fails as
   `WRITER_LEASE_SCOPE_MISMATCH`; changed HEAD/file state fails as
   `STALE_WRITE_BASE`. A successful write advances only that lease's snapshot
   and invalidates older verification/security receipts. Continue to use
   `read_file`, `search_text`, `list_files`, `git_status`, `git_diff`, and only
   registered `run_task` commands.
10. Read back the patch, run the narrowest relevant test/lint/build task, and
   inspect the diff. Stop on any failed, timed-out, or ambiguous task result.
   After selecting changed paths, call `verification_plan`. `context_pack` is
   a bounded, redacted read-only alternative to collecting ad-hoc file
   contents and returns a revision-pinned `context_pack_id` plus per-file
   hashes. Use `verification_record` only for evidence that actually came from
   the registered task. Its receipt is pinned to the current revision/diff.
   Then call `security_audit`; it performs a READ_ONLY evaluation and appends
   one bounded non-secret deterministic receipt pinned to that worktree,
   diff, and verification receipt without changing task, session, or lease
   state. The receipt is task-agnostic: retries retain its first audit time,
   while conflicting identity reuse fails closed. If the workflow
   needs a state transition, call `director_task_ledger` explicitly.
   `orchestration_plan` computes dependency-aware safe
   batches, suggested leases/resources, an integration owner, and
   `max_safe_parallel_writers`; it never creates child chats itself.
11. For an isolated DEVELOPMENT session that is ready to return to canonical,
   review `workspace_session_diff`. Call `workspace_integration_preflight` only
   after matching verification and security receipts exist. Preflight checks
   canonical cleanliness/current revision, `git apply --check`, and evidence
   freshness. If ready it returns a short-lived `approval_token` and exact
   confirmation string. Only after explicit human approval call
   `workspace_integrate_development_session` with that token and exact text.
   The tool applies that exact patch to canonical and leaves it dirty for human
   review; it does not commit, push, checkout, merge, or delete the session.
12. After a chat or transport reconnect, repeat the same
    `director_development_start` request first when the registered policy
    enables safe-local auto-resume and the owner/task are unchanged. It should
    return the same session/task/worktree IDs and only reuse or reacquire the
    scoped lease. For a policy exception, cross-owner recovery, or disabled
    auto-resume, inspect `workspace_list_development_sessions`, call
    `workspace_request_development_session_attach`, show its confirmation, then
    call `workspace_attach_development_session` with the approval token and
    exact confirmation. The server revalidates the registered workspace,
    source commit, worktree identity, containment, symlink state, and managed
    root, then issues a new lease/session ID without recreating or deleting the
    worktree.
    The MCP handshake is connection-scoped: `server_info.health.runtime`
    should show `READY` plus a new `transport_generation`/
    `protocol_session_generation`. A same-generation duplicate initialize
    after normal operation is an error, while a discovery probe or new request
    epoch rotates only protocol state and leaves the DEVELOPMENT lease intact.
13. Close only a clean isolated session with
    `workspace_close_development_session`.
   Dirty worktrees are retained for human review and are never force-deleted.
14. For an approved staged closeout, call `git_commit_preflight` and inspect its
    exact staged/unstaged/untracked state, task/evidence binding, HEAD, diff
    hash, index hash, message hash, and one-shot TTL challenge. Only after the
    human confirms the exact challenge may `git_commit` run. It never stages,
    resets, amends, or pushes.
15. After a successful local commit, call `git_push_preflight` with a configured
    remote name and exact branch/HEAD. Review the actual push URL hash
    (including any configured `pushurl`), expected remote OID,
    default/protected-branch policy, and challenge. Only after the
    human confirms may `git_push` run. It uses a normal non-force push only;
    non-fast-forward, stale remote, credential-bearing/unsupported URL, custom
    remote helper, repository hook, and unknown network result fail closed.
    Commit and push never auto-chain.

## Stop conditions

Stop immediately on:

- `CANDIDATE_CHANGED` or `DEVELOPMENT_SOURCE_CHANGED`; `SOURCE_NOT_CLEAN` is an
  integration-preflight blocker, while canonical dirty state is recorded as
  evidence during isolated-session provisioning;
- `DEVELOPMENT_APPROVAL_REQUIRED`, expired/replayed approval, or a stale session
  that has not passed explicit `workspace_attach_development_session` validation;
- switching workspaces while a development session is active;
- sensitive path, symlink escape, containment, ownership, or worktree identity
  errors;
- `WRITER_LEASE_REQUIRED`, `WRITER_LEASE_SCOPE_MISMATCH`,
  `STALE_WRITE_BASE`, path/resource lease conflict, or an expired lease;
- stale/missing verification or security receipts, canonical-dirty state,
  integration conflict, expired integration approval, or changed approved
  patch/canonical revision;
- missing registry entry, unknown task, task timeout, or `ok=false`/`isError`;
- schema mismatch, `CLIENT_TOOL_SCHEMA_STALE`, unhealthy registry, or
  unavailable Tunnel readiness;
- any request to expose arbitrary shell, unrestricted command/environment
  execution, credentials, arbitrary config editing, or automatic commit/push.
  The
  bounded argv command pair is still subject to one-shot approval and exact
  worktree/HEAD binding.

## Session lifecycle

`workspace_list_development_sessions` and `workspace_session_status` expose a
canonical `status` (`active`, `expired_dirty_retained`, `expired_clean`,
`stale_dirty_retained`, `stale_clean`, or an explicit `*_unavailable` state)
together with `stale`, `expired`,
`active`, `blocks_workspace_switch`, `dirty`, `diff_remaining`, and
`worktree_available`. `active` is true only for an unexpired lease held by the
current runtime, independent of which session is selected. Expiry always releases the workspace-switch lock; dirty
worktrees remain under the managed root for review. After restart, sidecars are
never restored as active. A retained worktree can be explicitly reattached
only through the two-step approval/new-lease flow above. Clean expired
sessions can be safely closed; dirty sessions cannot be force-deleted.

## Configuration discipline

The local operator owns `~/.config/local-dev-mcp/config.json`. Keep ordinary
file roots explicit and `READ_ONLY`. Register only individual projects for
DEVELOPMENT and provide one-line commands under the fixed task allowlist.
Optional project metadata is descriptive only; it cannot grant permission.
Never put credentials, tokens, private keys, network commands, destructive
commands, or secret-bearing output in task definitions.

## Verification ladder

Use the shortest command that matches the change. All commands use the
repository virtual environment and fail fast; none restarts the managed
Tunnel or changes LaunchAgent configuration.

Fast local loop:

```sh
.venv/bin/python scripts/verify_fast.py
```

Full local suite and disposable smoke matrix:

```sh
.venv/bin/python scripts/verify_full.py
```

Installed executable, raw MCP lifecycle, multi-client/reconnect checks, and
managed Tunnel health/readiness:

```sh
.venv/bin/python scripts/verify_live_lifecycle.py
```

The live command expects an already-running managed Tunnel. It is intentionally
read-only with respect to the Tunnel process and LaunchAgent.

Individual runtime checks remain useful when narrowing a failure:

```sh
.venv/bin/python scripts/audit_public_surface.py
.venv/bin/python scripts/smoke_discovery.py
.venv/bin/python scripts/smoke_development_session.py
.venv/bin/python scripts/smoke_schema_health.py
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

## Local MCP directory roles

The canonical source repository is resolved by the installed wrapper's
workspace locator and is used by the `.venv/bin/chatgpt-dev-mcp` executable.
Other similarly named directories are not automatically additional live MCP
servers:

* `~/.cache/.../worktrees` contains managed detached worktrees for isolated
  development sessions.
* Directories named `chatgpt-dev-mcp-*` outside the canonical locator are
  disposable E2E fixtures or historical verification snapshots when their Git
  history/version shows an older release.
* `~/Developer/mcp-run-task-*` directories are temporary task-run fixtures
  created by development-session tests.
* `~/Developer/<other-project>/automation/mcp` belongs to that other project
  and is not the `chatgpt-dev-mcp` runtime.
* An empty, similarly named directory can be an old initial working location;
  verify the canonical path and executable before treating it as a server.

Keep disposable or dirty directories until their task is explicitly closed.
For a read-only inventory, list the directories first and inspect each path's
Git root, branch, HEAD, and status. Do not delete or move them as a shortcut for
fixing a lifecycle problem.

For the disposable HTTP prototype, start it on an unused loopback port and
check its JSON endpoints directly:

```sh
.venv/bin/python -m chatgpt_dev_mcp.http_entrypoint --host 127.0.0.1 --port 8000
curl -fsS http://127.0.0.1:8000/healthz
curl -fsS http://127.0.0.1:8000/readyz
```

The loopback endpoints are diagnostics only. They do not prove ChatGPT's
private App cache has refreshed; compare the App's observed schema manually.
The HTTP health endpoints validate only the local wrapper registry/schema and
session manager. They do not call the production Tunnel health endpoint.

For a schema mismatch, `director_health` can compare supplied client metadata
and optional client tool names with the local 52-tool Stable Gateway manifest. Treat
`missing_on_client[]`, `extra_on_client[]`, and `rescan_required` as diagnostic
evidence only: the MCP cannot force the ChatGPT client to discard its cached
tool schema.

The HTTP server defaults to a 30-second request socket timeout, 64 concurrent
requests, 128 active sessions, a 60-minute idle TTL, and 32 session creations
per 60 seconds. Tune these only for a disposable process and keep the
loopback-only bind.

## HTTP prototype rollback

HTTP is not the production transport. If a disposable HTTP run must stop:

1. Stop the HTTP process that you started (normally with `Ctrl-C`) and confirm
   that its loopback port is no longer listening. The server closes active
   runtimes and refuses new sessions during shutdown.
2. Do not edit the production Tunnel profile, LaunchAgent, registry, or
   credentials. Discard only the separately created disposable Tunnel/App
   draft if one was used.
3. Confirm the existing production STDIO route remains the selected path, then
   re-check its `/healthz`, `/readyz`, and public-surface audit. A healthy
   STDIO route is the rollback state; no repository reset, stash, checkout, or
   credential rotation is required.
4. Preserve any dirty disposable worktree for review. Never force-delete a
   dirty development session as part of transport rollback.
