# chatgpt-dev-mcp Security Model

## Trust boundaries

| Boundary | Trust level | Control |
|---|---|---|
| ChatGPT/model arguments | untrusted | ID-only selection, relative paths, schemas, fixed task names |
| Local registry | operator-controlled | read-only discovery plus a fixed-path, digest-pinned allowlist policy tool; profiles, paths, commands, and credentials remain operator-only |
| Discovery candidate | ephemeral/untrusted | process-local opaque ID and open-time identity revalidation |
| Canonical repository | registered mutation target | workspace containment, symlink checks, guarded atomic patches, and sensitive-path denylist |
| Development worktree | optional bounded mutation area | managed-root ownership/symlink/identity checks |
| Registered task code | project-controlled | upstream safe policy and bounded timeout/output; not a kernel sandbox |
| Secure MCP Tunnel | transport boundary | health/readiness diagnostics; credentials never returned |
| Director control plane | local policy plus private SQLite state | revision-pinned context, path/resource leases, stale-write checks, verification/audit receipts, task ledger, orchestration, lifecycle reconciliation, and explicit integration preflight |

## Invariants

- Discovery is `PROJECT_DISCOVERY` and never inherits write permission.
- `workspace_register_preflight/register`,
  `workspace_unregister_preflight/unregister`,
  `workspace_registration_update_preflight/update`,
  `workspace_project_policy_get/update`, and the project provisioning tools
  are the only registry mutation paths. Registration requires an exact
  one-time preflight confirmation and pins canonical path, Git identity,
  branch/HEAD/dirty state, config digest, and the default approval-preserving
  policy. Unregistration is blocked by sessions, active leases/tasks, or dirty
  managed worktrees and never deletes the repository. Registration update may
  change only an identifier and bounded policy keys; approval flags cannot be
  downgraded. All mutations use a process/advisory lock, complete-document
  validation, same-directory fsync'd atomic replacement, read-back, and
  non-secret provisioning events. None is an arbitrary JSON editor: roots,
  unrelated workspaces, credentials, platform/GitHub auth, config version, and
  existing project contents remain outside the allowlist.
- General-file roots normally require explicit local `READ_ONLY` registration.
  A bounded exception is `readonly_path`: v25 mints a process-local,
  TTL-limited handle, while v26 stores the same minimal handle identity in the
  existing Director SQLite database for cross-child status/list/read calls
  within the same server-owned HTTP logical connection. The durable row is
  bound to its owner/session and selected workspace, so a different client or
  workspace cannot enumerate or read it. The v26 row is bounded, expires
  without sliding on access, contains no caller authority, and is read-only
  apart from its lifecycle state. Both surfaces pin device/inode identity, use
  no-follow traversal, reject traversal and symlink escapes, and cannot become
  workspace, execution, Git, DEVELOPMENT, or writer authority. STDIO remains
  process-local and does not use the HTTP binding.
- Host filesystem mutation is isolated from the workspace command boundary.
  `host_file_preflight` accepts only `trash` or `delete` plus bounded absolute
  or home-relative target paths, canonicalizes and classifies each target, and
  persists only a short-lived one-shot receipt with metadata-only recursive
  fingerprints. `host_file_apply` accepts only the receipt ID plus its exact
  confirmation, revalidates every target, consumes the receipt before mutation,
  and executes no caller-supplied command. `trash` is R2/reversible and moves
  only policy-allowed user paths or top-level `/Applications/*.app` bundles to
  the current user's Trash. `delete` is R3/irreversible and is restricted to
  disposable cache/log/temp roots. Sensitive home roots, the receipt store,
  top-level symlinks, parent-symlink escape, traversal overflow, stale targets,
  arbitrary destinations, and broad permanent deletion fail closed.
- Sensitive roots and representative credential/token/session paths are denied
  in a common policy layer; binary and oversized file content is skipped.
- Candidate open compares path, device/inode, resolved Git root, safe `.git`
  marker, and either the committed HEAD or a valid symbolic unborn-branch
  sentinel against the discovery snapshot. Expected marker metadata changes
  caused by managed worktree bookkeeping do not replace those anchors.
- Development approval binds candidate ID, workspace ID, repo identity,
  immutable approved source commit, profile, confirmation text, expiry, and
  one-time consumption. Canonical dirty state and later HEAD advancement are
  evidence, not a reason to copy uncommitted content or silently change the
  source commit.
- A registered `DEVELOPMENT` workspace can be opened directly by ID for guarded
  canonical edits. Multiple managed sessions may coexist under one logical
  project; `workspace_open(session:<id>)` changes only selected convenience
  state and never stales another active session. Explicit `session_id` routing
  resolves the persisted session, exact worktree identity, and managed path.
  Stale/expired sessions remain attach-gated unless the registered project
  explicitly enables `same_owner_same_task_safe_local` auto-resume. Expired
  dirty sessions retain their managed worktree for review/reattach.
- Isolated session provisioning validates only the registered project anchor and
  exact source commit; canonical dirty state is recorded as warning/evidence
  and never copied into a managed worktree unless an explicit immutable,
  secret-safe baseline snapshot is supplied. Snapshot materialization verifies
  tracked-patch and untracked-manifest hashes; canonical cleanliness, HEAD,
  conflict, diff, verification, and audit are rechecked strictly at
  integration.
- Optional worktree creation is detached and is verified before session
  activation.
- Session lifecycle metadata is evaluated centrally for every workspace/session
  operation. `expired_dirty_retained` never grants the old lease. Safe-local
  auto-resume, when explicitly enabled, may grant only a fresh lease to the
  same stored owner/task/session/worktree after identity and scope checks;
  otherwise reattach requires explicit approval. Manual reattach may create a
  new session lease over the retained managed worktree.
- `development.session.reconcile_stale_state` is a two-stage, Registry-only
  capability. Its authority is limited to DevMCP-controlled durable evidence:
  session rows, task/lease state, archive and other receipts, registered
  sidecars, explicitly configured managed/legacy roots, Git worktree metadata,
  filesystem identities, and known DevMCP process bindings. It never requires
  proof about arbitrary unregistered files. Preflight records a bounded,
  immutable digest and execute rejects drift. Active/nonterminal tasks, live
  leases/processes, identity or evidence conflicts, unknown source revisions,
  and untrusted roots fail closed. Dirty existing worktrees are archived and
  retained; missing worktrees are tombstoned only with verifiable source and
  Git-absence evidence. The capability never removes a worktree or calls an
  unconditional Git prune, and a missing path is never treated as success.
- `runtime.candidate.activate` and `development.evidence.import_generation`
  are separate human-approved boundaries. Candidate activation pins source
  Git identity, schema-14 database/catalog/doctor evidence, a deterministic
  semantic digest of schema definitions and all logical application rows
  (excluding only `request_lifecycle_events` rows), physical database
  identity, and a known-good schema-compatible rollback authority; it cannot
  execute without an official maintenance executor. Generation import is allowlisted and dependency
  closed: it pins source/destination database identity and data-version,
  preserves session/task/receipt identities, rejects cross-workspace records
  and collisions, and performs one transactional destination write. Source
  databases and sidecars are read-only and never copied, replaced, or edited.
- `apply_patch` remains containment-, symlink-, sensitive-path-, and atomicity-
  guarded by the wrapper and upstream runtime, and additionally requires an
  active covering Director lease. The mutation resolves `lease_id` → task →
  session → `working_tree_id` and validates owner/task, normalized
  paths/resources, HEAD, and scoped file hashes immediately before execution.
  Missing coverage fails `WRITER_LEASE_REQUIRED`; changed HEAD/file content
  fails `STALE_WRITE_BASE`.
- Registered task execution accepts only task names and configured command
  strings. Direct arbitrary `exec_command` is not visible. The separate public
  argv command pair is approval-bound to a managed DEVELOPMENT worktree and
  rejects shell strings, environment injection, composition, privileged
  executables, arbitrary cwd paths, and unbounded timeout/output.
- Empty writer scopes are invalid unless `workspace_wide=true` is explicit.
  Workspace-wide scope requires a bounded reason, project policy permission,
  zero active project writers, and the normal lease TTL; it is never inferred
  from omitted paths/resources.
- Director `context_pack` reads only through the existing safe `read_file`
  path policy and redacts common credential shapes. Context schema v2 pins the
  source revision and per-file hashes. `patch_preflight` never applies a patch
  and requires the same lease/stale-base checks as `apply_patch` for an
  otherwise allowable patch. `verification_record` is evidence normalization,
  not proof of provider or marketplace success.
- Task/lease state is bounded process state mirrored to the private Director
  SQLite ledger. It is not a durable queue and does not create processes.
  Multiple writers are permitted only when their path scopes and runtime
  resources are disjoint across every worktree of one logical project.
  Parent/descendant paths conflict; dependency edges may defer an overlapping
  task until its predecessor succeeds. SQLite acquisition checks the same
  project-wide scope atomically so separate MCP children cannot race through a
  local-only lease check.
- v0.41 records the bounded Director ledger, dependency edges, session/worktree
  identities, baseline-snapshot metadata, idempotent start requests, and receipt history in
  `~/.cache/local-dev-mcp/director.sqlite3` (or the internal data-dir override)
  using stdlib SQLite internal schema 14 with migrations plus additive bounded audit tables, `foreign_keys=ON`, WAL,
  `busy_timeout`, full synchronous writes, private file permissions, and
  transactional rollback. The database stores hashes and bounded summaries,
  never raw patches, credentials, command output, or approval tokens.
- Restart reconciliation checks registry/worktree identity, source/current
  HEAD, lease expiry, and pinned diff/path hashes. Expired leases are never
  active; unverified leases/evidence become stale; persisted `leased`/
  `running`/`verifying` tasks become `ready`, `stale`, or `blocked` only after
  fresh identity facts, never running. Side effects are never replayed.
  Commit, push, and integration are never automatically resumed, and corrupt
  or unknown-schema state blocks Director mutation rather than being replaced.
- Verification and security-audit receipts are pinned to worktree identity and
  revision/diff hashes. Security-audit receipt identity is task-agnostic;
  Task Ledger records own task-to-receipt bindings, identical retries retain
  the first audit time, and conflicting receipt reuse fails closed. Later
  owned writes invalidate prior receipts, and integration rechecks the
  current state so external drift also fails closed. `security_audit` is a
  READ_ONLY evaluation that may append one non-secret audit receipt, but it
  does not transition tasks or acquire/release leases; workflow state changes
  use the explicit Task Ledger mutation path. Request audit events pin the
  actual accepted schema generation and connection identity, and provisioning
  audit events retain only bounded project/session lifecycle labels and safe
  error codes.
- `workspace_integration_preflight` never mutates canonical state. It requires
  a bounded session diff, clean canonical worktree, conflict-free `git apply
  --check`, and matching verification/security receipts before issuing a
  short-lived exact confirmation. `workspace_integrate_development_session`
  consumes that confirmation and applies only the preflighted patch; it never
  commits, pushes, checks out, or deletes the retained session worktree.
- v0.32 Git closeout is a separate fixed-argv boundary. `git_commit_preflight`
  and `git_push_preflight` are read-only and pin Task Ledger evidence, working
  tree identity, branch, HEAD, diff/index hashes, remote URL hash, and expected
  remote OID. `git_commit` and `git_push` require distinct one-shot TTL human
  approvals and revalidate every pin immediately before mutation.
- Git closeout is staged-only and fail-closed for unstaged/untracked state. It
  rejects sensitive/symlink-escaping paths, detached HEAD, invalid/missing
  remotes, unsupported push URLs/custom remote helpers, repository hooks,
  protected/default branches, stale local/remote state, and
  non-fast-forward pushes. It never stages, resets, amends, force-pushes,
  changes remotes/credentials, accepts arbitrary argv, or auto-chains commit
  to push. Commit tree/diff and push remote OID receive independent read-back;
  ambiguous network results are `outcome_unknown`, never success or retry.
- `orchestration_plan` detects dependency and concurrent writer/resource
  conflicts, emits safe batches and suggested leases, but cannot create
  ordinary ChatGPT conversations; that remains a separate ChatGPT-side
  connector boundary.
- `director_development_start` is allowed only for a config-registered project
  whose explicit local `isolated_development` policy enables auto sessions. Its
  `auto_promote` convenience path still requires `candidate_id` plus
  `explicit_user_intent=true` and all promotion invariants; discovery alone
  cannot elevate a project. It may create only a managed isolated worktree,
  local implementation scope, registered tests, and verification/audit state.
  An unborn repository uses an orphan worktree and a zero-commit sentinel; no
  empty commit is created. The MCP cannot mutate policy through an arbitrary
  editor, create an external chat, integrate to canonical, commit, or push.
  Those boundaries retain explicit approvals.
- Merge, rebase, reset, checkout, branch deletion, and forced cleanup are not
  exposed. The v0.32 commit/push tools are the only explicit closeout path and
  remain guarded by the contract above.
- The HTTP prototype binds only to loopback, creates a fresh runtime per
  `Mcp-Session-Id`, bounds active/retired session metadata and idle lifetime,
  rejects unknown/expired/deleted IDs, serializes each session with a mutex,
  and bounds request timeout, in-flight requests, and session creation rate.
  It never exposes health endpoints as MCP tools.
- HTTP `/healthz` and `/readyz` return only non-secret transport and schema
  diagnostics from the local wrapper. Readiness rechecks registry validity and
  fails closed when the session manager is closed or the wrapper registry/schema
  is inconsistent; it does not depend on production Tunnel health.

## Residual risks

- macOS is not a kernel-level sandbox for project-controlled task code. A
  registered test/lint/build command may still access capabilities that are
  not visible from its short command string.
- Sensitive-path protection is defense-in-depth denylisting, not complete DLP.
  Unknown credential filenames, generated secrets, embedded tokens, and
  secrets inside binary/image content are not guaranteed to be detected.
- The local registry is trusted operator input. A malicious or unsafe task
  command in the registry remains a local policy/configuration risk.
- Tunnel health and local schema consistency do not reveal ChatGPT's private
  connector cache. `matched`, `mismatched`, and `not_available` must be kept
  distinct. When client schema evidence is supplied, Director reports
  `missing_on_client`, `extra_on_client`, `rescan_required`, and
  `CLIENT_TOOL_SCHEMA_STALE` without claiming the rescan occurred.
- Public registry/schema changes require a new explicit tool-schema revision;
  count and deterministic hash remain independent stale-snapshot evidence.
- The Streamable HTTP path is a disposable prototype until a separately
  authorized Hosted Secure MCP Tunnel + ChatGPT E2E is completed. Production
  rollback remains the unchanged STDIO route.
- Any workspace audited during development was READ_ONLY; opting a registered
  workspace into direct canonical DEVELOPMENT editing remains an explicit,
  separate operator decision.
- External marketplace/provider success, receipts, independent read-back,
  upload, delivery, contract acceptance, and completion are outside this MCP.

## Incident response

On identity, schema, health, task, or session ambiguity: stop, preserve the
worktree, do not retry an unknown external action, and collect `server_info`,
`workspace_status`, session status, and `git_diff` for human review. Never use
reset, forced cleanup, credential rotation, or arbitrary config edits as a
recovery shortcut; a policy change must use the digest-pinned allowlist tool.
