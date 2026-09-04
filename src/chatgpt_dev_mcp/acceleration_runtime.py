"""High-level, bounded runtime services for acceleration MCP tools.

The server owns workspace/session authority.  This module owns only the
side-effect-free semantic/context/capability composition so the public MCP
handlers stay thin and the policy boundary remains explicit.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .capability_adapters import CapabilityAdapterCatalog
from .capability_gateway import CapabilityGateway
from .context_checkpoint import ContextCheckpoint
from .context_engine import BootstrapInputs, ContextEngine, InstructionContext, build_instruction_context
from .decision_memory import DecisionRecord
from .development_context import DevelopmentContextBuilder
from .development_loop import DevelopmentLoopState, LoopEvent, advance
from .director_dispatch import DirectorNextAction
from .observability import AccelerationObserver
from .project_capsule import CapsuleSection
from .repo_map import build_repo_map
from .semantic_index import BACKEND_REVISION, SemanticIndex, SemanticQuery
from .warm_runtime import WarmRuntimeManager


CONTEXT_SCHEMA_REVISION = "context-engine-v1"


@dataclass(frozen=True, slots=True)
class WorkspaceStateEvidence:
    clean: bool
    fingerprint: str


def workspace_state_evidence(payload: Mapping[str, object] | None) -> WorkspaceStateEvidence:
    """Convert bounded git-status metadata into a deterministic cache boundary."""

    if not isinstance(payload, Mapping):
        return WorkspaceStateEvidence(False, "status-unavailable")
    raw_entries = payload.get("entries", [])
    if not isinstance(raw_entries, list):
        return WorkspaceStateEvidence(False, "status-invalid")
    entries: list[dict[str, str]] = []
    for item in raw_entries[:1000]:
        if not isinstance(item, Mapping):
            continue
        entries.append(
            {
                "path": str(item.get("path", ""))[:512],
                "index_status": str(item.get("index_status", ""))[:8],
                "worktree_status": str(item.get("worktree_status", ""))[:8],
            }
        )
    clean = bool(payload.get("clean", not entries)) and not entries
    if clean:
        return WorkspaceStateEvidence(True, "clean")
    encoded = json.dumps(entries, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return WorkspaceStateEvidence(False, hashlib.sha256(encoded.encode("ascii")).hexdigest())


class AccelerationRuntimeServices:
    """Compose acceleration engines without acquiring additional authority."""

    def __init__(
        self,
        *,
        persistence: object | None,
        warm_runtimes: WarmRuntimeManager,
        observer: AccelerationObserver,
        capability_catalog: CapabilityAdapterCatalog,
        capability_gateway: CapabilityGateway,
    ) -> None:
        self._persistence = persistence
        self._warm = warm_runtimes
        self._observer = observer
        self._catalog = capability_catalog
        self._gateway = capability_gateway

    @staticmethod
    def _identity(workspace_id: str, working_tree_id: str, source_revision: str) -> str:
        raw = (workspace_id, working_tree_id, source_revision, BACKEND_REVISION)
        return hashlib.sha256(repr(raw).encode("utf-8")).hexdigest()

    def _restore_clean_index(
        self,
        root: Path,
        *,
        identity: str,
        workspace_id: str,
        working_tree_id: str,
        source_revision: str,
    ) -> SemanticIndex:
        index = SemanticIndex(root, identity=identity)
        restored = False
        loader = getattr(self._persistence, "load_semantic_metadata", None)
        if callable(loader):
            try:
                records = loader(
                    workspace_id=workspace_id,
                    working_tree_id=working_tree_id,
                    source_revision=source_revision,
                    backend_revision=BACKEND_REVISION,
                )
                if isinstance(records, list):
                    ordinary = [
                        item
                        for item in records
                        if isinstance(item, Mapping)
                        and isinstance(item.get("path"), str)
                        and not (root / str(item["path"])).is_symlink()
                        and (root / str(item["path"])).is_file()
                    ]
                    restored = bool(ordinary) and index.restore_metadata(ordinary)
            except (OSError, RuntimeError, TypeError, ValueError):
                restored = False
        if not restored:
            index.build()
        return index

    def semantic_index(
        self,
        root: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        source_revision: str,
        state: WorkspaceStateEvidence,
        refresh_paths: Sequence[str] = (),
        updated_at: str,
    ) -> SemanticIndex:
        """Return a trustworthy semantic index for the exact workspace state.

        Clean revisions may reuse persisted/warm metadata. Dirty worktrees are
        rebuilt for every request so changing uncommitted content can never be
        hidden behind a stale cache identity.
        """

        identity = self._identity(workspace_id, working_tree_id, source_revision)
        if state.clean:
            value = self._warm.get_or_create(
                "semantic-index",
                identity,
                lambda: self._restore_clean_index(
                    root,
                    identity=identity,
                    workspace_id=workspace_id,
                    working_tree_id=working_tree_id,
                    source_revision=source_revision,
                ),
            )
            if not isinstance(value, SemanticIndex):
                raise RuntimeError("warm semantic index has an invalid type")
            index = value
            if refresh_paths:
                index.refresh(tuple(refresh_paths))
            saver = getattr(self._persistence, "save_semantic_metadata", None)
            if callable(saver):
                try:
                    for record in index.metadata_records(
                        workspace_id=workspace_id,
                        working_tree_id=working_tree_id,
                        source_revision=source_revision,
                        updated_at=updated_at,
                    ):
                        saver(record)
                except (RuntimeError, TypeError, ValueError):
                    # Semantic persistence is an optimization, never authority.
                    pass
            return index

        dirty_identity = hashlib.sha256(
            repr((identity, state.fingerprint)).encode("utf-8")
        ).hexdigest()
        index = SemanticIndex(root, identity=dirty_identity)
        index.build()
        return index

    def semantic_query(
        self,
        root: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        source_revision: str,
        state: WorkspaceStateEvidence,
        query: SemanticQuery,
        refresh_paths: Sequence[str] = (),
        updated_at: str,
    ) -> dict[str, object]:
        index = self.semantic_index(
            root,
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            source_revision=source_revision,
            state=state,
            refresh_paths=refresh_paths,
            updated_at=updated_at,
        )
        matches = index.query(query)
        hashes = tuple(dict.fromkeys(item.source_hash for item in matches))[:128]
        receipt = self._observer.record(
            "semantic",
            subject_id=workspace_id,
            reason="semantic_query",
            evidence_hashes=hashes,
            metadata={
                "working_tree_id": working_tree_id,
                "source_revision": source_revision,
                "backend_revision": BACKEND_REVISION,
                "match_count": len(matches),
                "clean": state.clean,
            },
        )
        return {
            "workspace_id": workspace_id,
            "working_tree_id": working_tree_id,
            "source_revision": source_revision,
            "backend_revision": BACKEND_REVISION,
            "matches": [item.as_dict() for item in matches],
            "receipt_id": receipt["receipt_id"],
            "external_execution": False,
        }

    def development_context(
        self,
        root: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        source_revision: str,
        state: WorkspaceStateEvidence,
        task_id: str,
        query: str,
        target_paths: Sequence[str],
        diff_paths: Sequence[str],
        max_bytes: int,
        safe_reader: Callable[[str], str],
        diff_reader: Callable[[str], str],
        updated_at: str,
    ) -> dict[str, object]:
        index = self.semantic_index(
            root,
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            source_revision=source_revision,
            state=state,
            refresh_paths=tuple(dict.fromkeys((*target_paths, *diff_paths))),
            updated_at=updated_at,
        )
        pack = DevelopmentContextBuilder(index, safe_reader=safe_reader, diff_reader=diff_reader).build(
            task_id=task_id,
            query=query,
            target_paths=tuple(target_paths),
            diff_paths=tuple(diff_paths),
            max_bytes=max_bytes,
        )
        hashes = tuple(
            dict.fromkeys(
                str(item.as_dict().get("source_hash"))
                for item in pack.items
                if item.as_dict().get("source_hash")
            )
        )[:128]
        receipt = self._observer.record(
            "context",
            subject_id=task_id,
            reason="development_context",
            evidence_hashes=hashes,
            metadata={
                "workspace_id": workspace_id,
                "working_tree_id": working_tree_id,
                "item_count": len(pack.items),
                "used_bytes": pack.used_bytes,
                "clean": state.clean,
            },
        )
        return {
            **pack.as_dict(),
            "workspace_id": workspace_id,
            "working_tree_id": working_tree_id,
            "receipt_id": receipt["receipt_id"],
        }

    def context_bootstrap(
        self,
        root: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        source_revision: str,
        state: WorkspaceStateEvidence,
        base_sections: Sequence[CapsuleSection] = (),
        decisions: Sequence[DecisionRecord] = (),
        checkpoint: ContextCheckpoint | None = None,
        previous_checkpoint: ContextCheckpoint | None = None,
        query: str = "",
        max_bytes: int = 16384,
        instructions_reader: Callable[[str], str] | None = None,
        updated_at: str,
    ) -> dict[str, object]:
        """Return bounded bootstrap context, caching only exact clean-state inputs."""

        sections = tuple(base_sections)
        decision_records = tuple(decisions)
        if checkpoint is not None:
            if checkpoint.state.workspace_id != workspace_id or checkpoint.state.head != source_revision:
                raise ValueError("checkpoint does not match the current workspace revision")
        if any(record.workspace_id != workspace_id for record in decision_records):
            raise ValueError("decision memory does not match the current workspace")
        if not isinstance(query, str) or len(query) > 1000 or "\x00" in query:
            raise ValueError("context bootstrap query is invalid")

        instructions = InstructionContext("missing")
        if instructions_reader is not None:
            if not callable(instructions_reader):
                raise ValueError("instructions reader is invalid")
            try:
                instructions = build_instruction_context(instructions_reader("AGENTS.md"))
            except FileNotFoundError:
                instructions = InstructionContext("missing")
            except (OSError, RuntimeError, ValueError):
                instructions = InstructionContext("unavailable")

        input_fingerprint = hashlib.sha256(
            repr(
                (
                    sections,
                    decision_records,
                    checkpoint,
                    previous_checkpoint,
                    instructions.status,
                    instructions.source_hash,
                    query,
                    max_bytes,
                    CONTEXT_SCHEMA_REVISION,
                )
            ).encode("utf-8")
        ).hexdigest()
        cache_identity = hashlib.sha256(
            repr((self._identity(workspace_id, working_tree_id, source_revision), input_fingerprint)).encode("utf-8")
        ).hexdigest()
        created = False

        def build() -> object:
            nonlocal created
            created = True
            index = self.semantic_index(
                root,
                workspace_id=workspace_id,
                working_tree_id=working_tree_id,
                source_revision=source_revision,
                state=state,
                updated_at=updated_at,
            )
            snapshot = index.refresh(())
            repo_budget = max(512, min(8192, max_bytes // 2))
            repo_map = build_repo_map(
                snapshot,
                query=query,
                max_items=64,
                max_bytes=repo_budget,
            )
            return ContextEngine().bootstrap(
                BootstrapInputs(
                    workspace_id=workspace_id,
                    source_revision=source_revision,
                    base_sections=sections,
                    decisions=decision_records,
                    repo_map=repo_map,
                    checkpoint=checkpoint,
                    instructions=instructions,
                ),
                max_bytes=max_bytes,
                previous_checkpoint=previous_checkpoint,
            )

        if state.clean:
            value = self._warm.get_or_create("context-capsule", cache_identity, build)
            cache_status = "miss" if created else "hit"
            freshness = "clean_cached"
        else:
            value = build()
            cache_status = "bypass_dirty"
            freshness = "dirty_rebuild"
        if not hasattr(value, "capsule"):
            raise RuntimeError("warm context capsule has an invalid type")

        receipt = self._observer.record(
            "context",
            subject_id=workspace_id,
            reason="context_bootstrap",
            metadata={
                "working_tree_id": working_tree_id,
                "source_revision": source_revision,
                "cache_status": cache_status,
                "freshness": freshness,
                "used_bytes": value.used_bytes,
            },
        )
        return {
            "workspace_id": workspace_id,
            "working_tree_id": working_tree_id,
            "source_revision": source_revision,
            "schema_revision": CONTEXT_SCHEMA_REVISION,
            "capsule": value.capsule.as_dict(),
            "decision_revision": value.decision_revision,
            "decision_conflict": value.decision_conflict,
            "conflict_ids": list(value.conflict_ids),
            "delta": asdict(value.delta) if value.delta is not None else None,
            "used_bytes": value.used_bytes,
            "max_bytes": value.max_bytes,
            "instructions_status": instructions.status,
            "instructions_hash": instructions.source_hash or None,
            "cache_status": cache_status,
            "freshness": freshness,
            "receipt_id": receipt["receipt_id"],
            "external_execution": False,
        }

    def context_focus(
        self,
        root: Path,
        *,
        workspace_id: str,
        working_tree_id: str,
        source_revision: str,
        state: WorkspaceStateEvidence,
        task_id: str,
        query: str,
        target_paths: Sequence[str] = (),
        diff_paths: Sequence[str] = (),
        decisions: Sequence[DecisionRecord] = (),
        max_bytes: int = 8192,
        safe_reader: Callable[[str], str],
        diff_reader: Callable[[str], str],
        updated_at: str,
    ) -> dict[str, object]:
        """Return task-focused semantic context; dirty evidence is always rebuilt."""

        targets = tuple(target_paths)
        diffs = tuple(diff_paths)
        decision_records = tuple(decisions)
        if any(record.workspace_id != workspace_id for record in decision_records):
            raise ValueError("decision memory does not match the current workspace")
        index = self.semantic_index(
            root,
            workspace_id=workspace_id,
            working_tree_id=working_tree_id,
            source_revision=source_revision,
            state=state,
            refresh_paths=tuple(dict.fromkeys((*targets, *diffs))),
            updated_at=updated_at,
        )
        snapshot = index.refresh(())
        pack = DevelopmentContextBuilder(index, safe_reader=safe_reader, diff_reader=diff_reader).build(
            task_id=task_id,
            query=query,
            target_paths=targets,
            diff_paths=diffs,
            max_bytes=max_bytes,
        )
        repo_map = build_repo_map(
            snapshot,
            query=query,
            target_paths=targets,
            changed_paths=tuple(dict.fromkeys((*targets, *diffs))),
            max_items=64,
            max_bytes=max(512, min(8192, max_bytes // 2)),
        )
        focused = ContextEngine().focus(
            query,
            context_pack=pack,
            decisions=decision_records,
            repo_map=repo_map,
            max_bytes=max_bytes,
        )
        freshness = "clean_warm" if state.clean else "dirty_rebuild"
        receipt = self._observer.record(
            "context",
            subject_id=task_id,
            reason="context_focus",
            metadata={
                "workspace_id": workspace_id,
                "working_tree_id": working_tree_id,
                "source_revision": source_revision,
                "freshness": freshness,
                "used_bytes": focused.used_bytes,
                "item_count": len(focused.items),
                "repo_entry_count": len(focused.repo_entries),
            },
        )
        return {
            "workspace_id": workspace_id,
            "working_tree_id": working_tree_id,
            "source_revision": source_revision,
            "schema_revision": CONTEXT_SCHEMA_REVISION,
            "query": focused.query,
            "items": [item.as_dict() for item in focused.items],
            "decisions": [record.as_dict() for record in focused.decisions],
            "repo_entries": [entry.as_dict() for entry in focused.repo_entries],
            "decision_conflict": focused.decision_conflict,
            "used_bytes": focused.used_bytes,
            "max_bytes": focused.max_bytes,
            "truncated": focused.truncated,
            "freshness": freshness,
            "receipt_id": receipt["receipt_id"],
            "external_execution": False,
        }

    def external_capability_status(self) -> dict[str, object]:
        catalog = self._catalog.status()
        gateway = self._gateway.status()
        return {
            "catalog": catalog,
            "gateway": gateway,
            "process_started": False,
            "network_used": False,
            "external_execution": False,
        }

    def director_next_action(
        self,
        *,
        loop_id: str,
        owner_id: str,
        task_id: str,
        session_id: str,
        worktree_id: str,
        now: float,
        create: bool = False,
        event: Mapping[str, object] | None = None,
        delivery_action: str = "",
    ) -> dict[str, object]:
        """Advance one bounded loop event and persist the resulting decision."""

        loader = getattr(self._persistence, "load_development_loop", None)
        saver = getattr(self._persistence, "save_development_loop", None)
        if not callable(loader) or not callable(saver):
            raise RuntimeError("development loop persistence is unavailable")
        loaded = loader(loop_id)
        state = loaded.get("state") if isinstance(loaded, Mapping) else None
        if state is None:
            if not create:
                raise ValueError("development loop does not exist; create=true is required")
            state = DevelopmentLoopState.create(
                loop_id=loop_id,
                owner_id=owner_id,
                task_id=task_id,
                session_id=session_id,
                worktree_id=worktree_id,
                started_at=float(now),
            )
        if not isinstance(state, DevelopmentLoopState):
            raise RuntimeError("stored development loop state is invalid")
        identity_matches = (owner_id, task_id, session_id, worktree_id) == (
            state.owner_id,
            state.task_id,
            state.session_id,
            state.worktree_id,
        )
        if event is not None and identity_matches:
            state = advance(
                state,
                LoopEvent(
                    event_id=str(event.get("event_id", "")),
                    kind=str(event.get("kind", "")),
                    at=float(event.get("at", now)),
                    failure_fingerprint=str(event.get("failure_fingerprint", "")),
                    progress_token=str(event.get("progress_token", "")),
                    changed_files=int(event.get("changed_files", 0)),
                    diff_bytes=int(event.get("diff_bytes", 0)),
                ),
            )
        decision = DirectorNextAction.resolve(
            state,
            owner_id=owner_id,
            task_id=task_id,
            session_id=session_id,
            worktree_id=worktree_id,
            delivery_action=delivery_action,
        )
        saver(state, pending_action=decision.action)
        receipt = self._observer.record(
            "loop",
            subject_id=loop_id,
            reason="next_action",
            refs=(decision.receipt_id,),
            metadata={
                "phase": state.phase,
                "action": decision.action,
                "status": decision.status,
                "identity_matches": identity_matches,
                "event_applied": event is not None and identity_matches,
            },
        )
        return {
            "state": {
                "loop_id": state.loop_id,
                "phase": state.phase,
                "history_count": len(state.history),
                "stop_reason": state.stop_reason,
            },
            "decision": decision.as_dict(),
            "receipt_id": receipt["receipt_id"],
            "external_execution": False,
        }


__all__ = [
    "AccelerationRuntimeServices",
    "WorkspaceStateEvidence",
    "workspace_state_evidence",
]
