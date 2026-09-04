"""Bounded host filesystem mutations with explicit two-phase receipts.

This module intentionally does not expose arbitrary command execution. It
supports a small generic operation set, validates every target against a
policy, fingerprints metadata without reading file contents, and requires a
fresh persisted preflight receipt before performing a mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat as stat_module
import time
from typing import Iterable, Mapping


class HostFileError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class HostFilePolicy:
    home: Path | None = None
    applications_root: Path = Path("/Applications")
    receipt_ttl_seconds: float = 3600.0
    max_paths: int = 32
    max_entries: int = 250_000

    def __post_init__(self) -> None:
        home = Path.home() if self.home is None else Path(self.home)
        object.__setattr__(self, "home", home.resolve(strict=False))
        object.__setattr__(self, "applications_root", Path(self.applications_root).resolve(strict=False))
        if self.receipt_ttl_seconds <= 0:
            raise ValueError("receipt_ttl_seconds must be positive")
        if not 1 <= self.max_paths <= 128:
            raise ValueError("max_paths must be between 1 and 128")
        if not 1 <= self.max_entries <= 1_000_000:
            raise ValueError("max_entries must be between 1 and 1,000,000")

    @property
    def trash_root(self) -> Path:
        assert self.home is not None
        return self.home / ".Trash"

    @property
    def receipt_root(self) -> Path:
        assert self.home is not None
        return self.home / ".cache" / "local-dev-mcp" / "host-file-preflights"

    @property
    def permanent_delete_roots(self) -> tuple[Path, ...]:
        assert self.home is not None
        return (
            self.home / "Library" / "Caches",
            self.home / "Library" / "Logs",
            self.home / ".cache",
            self.home / ".codex" / ".tmp",
            self.home / ".codex" / "plugins" / "cache",
        )

    @property
    def sensitive_roots(self) -> tuple[Path, ...]:
        assert self.home is not None
        return (
            self.home / ".ssh",
            self.home / ".gnupg",
            self.home / "Library" / "Keychains",
            self.home / "Library" / "Mail",
            self.home / "Library" / "Messages",
            self.home / "Library" / "Safari",
            self.home / "Library" / "Mobile Documents",
            self.home / "Library" / "CloudStorage",
            self.trash_root,
        )


def _is_within(path: Path, root: Path, *, include_root: bool = True) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    return include_root or bool(relative.parts)


def _expand_home(raw: str, home: Path) -> Path:
    if raw == "~":
        return home
    if raw.startswith("~/"):
        return home / raw[2:]
    return Path(raw)


class HostFileController:
    _OPERATIONS = {"trash", "delete"}
    _APPLICATION_SUPPORT_DISPOSABLE_NAMES = {
        "cache",
        "code cache",
        "cacheddata",
        "cachedextensionvsixs",
        "crx_cache",
        "staging",
    }

    def __init__(
        self,
        *,
        policy: HostFilePolicy | None = None,
        capability_epoch: str | None = None,
    ) -> None:
        self._policy = policy or HostFilePolicy()
        if capability_epoch is None:
            capability_epoch = secrets.token_hex(16)
        if not isinstance(capability_epoch, str) or not capability_epoch or len(capability_epoch) > 256:
            raise ValueError("capability_epoch must be non-empty bounded text")
        self._capability_epoch = capability_epoch

    def _is_disposable_application_support_target(self, resolved: Path) -> bool:
        assert self._policy.home is not None
        root = (self._policy.home / "Library" / "Application Support").resolve(strict=False)
        try:
            relative = resolved.relative_to(root)
        except ValueError:
            return False
        # Require an application/container component before the disposable
        # subtree name. This keeps Application Support and a misleading
        # top-level `Application Support/Cache` outside permanent-delete scope.
        if len(relative.parts) < 2:
            return False
        return relative.parts[-1].casefold() in self._APPLICATION_SUPPORT_DISPOSABLE_NAMES

    def _is_disposable_codex_plugin_target(self, resolved: Path) -> bool:
        assert self._policy.home is not None
        root = (self._policy.home / ".codex" / "plugins").resolve(strict=False)
        try:
            relative = resolved.relative_to(root)
        except ValueError:
            return False
        # Staging is disposable only below a concrete plugin/marketplace
        # subtree; the plugins root itself is never eligible.
        return len(relative.parts) >= 2 and relative.parts[-1].casefold() == "staging"

    def _resolve_target(self, raw: object, *, operation: str) -> Path:
        if not isinstance(raw, str) or not raw.strip() or "\x00" in raw:
            raise HostFileError("HOST_FILE_PATH_INVALID", "path must be non-empty text")
        assert self._policy.home is not None
        candidate = _expand_home(raw.strip(), self._policy.home)
        if not candidate.is_absolute():
            raise HostFileError("HOST_FILE_PATH_INVALID", "path must be absolute or home-relative")
        candidate = Path(os.path.abspath(candidate))
        if not os.path.lexists(candidate):
            raise HostFileError("HOST_FILE_PATH_MISSING", "mutation target does not exist")
        if candidate.is_symlink():
            raise HostFileError("HOST_FILE_SYMLINK_DENIED", "top-level symlink mutation is not allowed")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise HostFileError("HOST_FILE_PATH_INVALID", "mutation target could not be resolved") from exc

        home = self._policy.home
        apps = self._policy.applications_root
        if resolved == home:
            raise HostFileError("HOST_FILE_PATH_DENIED", "the user home root cannot be mutated")
        if _is_within(resolved, home):
            protected_roots = (*self._policy.sensitive_roots, self._policy.receipt_root)
            for denied in protected_roots:
                denied_resolved = denied.resolve(strict=False)
                if (
                    resolved == denied_resolved
                    or _is_within(resolved, denied_resolved)
                    or _is_within(denied_resolved, resolved)
                ):
                    raise HostFileError("HOST_FILE_PATH_DENIED", "sensitive user data is outside host mutation policy")
        elif _is_within(resolved, apps):
            relative = resolved.relative_to(apps)
            if operation != "trash" or len(relative.parts) != 1 or resolved.suffix.lower() != ".app":
                raise HostFileError("HOST_FILE_PATH_DENIED", "only top-level application bundles may be trashed")
        else:
            raise HostFileError("HOST_FILE_PATH_DENIED", "path is outside the host mutation roots")

        if operation == "delete":
            allowed = False
            for root in self._policy.permanent_delete_roots:
                resolved_root = root.resolve(strict=False)
                if resolved == resolved_root or _is_within(resolved, resolved_root):
                    allowed = True
                    break
            if not allowed:
                allowed = self._is_disposable_application_support_target(resolved)
            if not allowed:
                allowed = self._is_disposable_codex_plugin_target(resolved)
            if not allowed:
                raise HostFileError(
                    "HOST_FILE_PERMANENT_DELETE_DENIED",
                    "permanent deletion is restricted to disposable cache/log/temp roots",
                )
        return resolved

    def _metadata_fingerprint(self, target: Path) -> tuple[str, int, int]:
        digest = hashlib.sha256()
        total_bytes = 0
        count = 0
        stack: list[tuple[Path, str]] = [(target, ".")]
        while stack:
            current, relative = stack.pop()
            count += 1
            if count > self._policy.max_entries:
                raise HostFileError("HOST_FILE_SCOPE_TOO_LARGE", "target exceeds the bounded traversal limit")
            try:
                info = current.lstat()
            except OSError as exc:
                raise HostFileError("HOST_FILE_INSPECTION_FAILED", "target metadata could not be read") from exc
            record = (
                relative,
                int(info.st_mode),
                int(info.st_size),
                int(info.st_mtime_ns),
                int(info.st_ino),
                int(info.st_dev),
            )
            digest.update(json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
            digest.update(b"\n")
            if stat_module.S_ISREG(info.st_mode) or stat_module.S_ISLNK(info.st_mode):
                total_bytes += int(info.st_size)
            if stat_module.S_ISLNK(info.st_mode):
                try:
                    digest.update(os.readlink(current).encode("utf-8", errors="surrogateescape"))
                except OSError as exc:
                    raise HostFileError("HOST_FILE_INSPECTION_FAILED", "symlink metadata could not be read") from exc
                digest.update(b"\n")
                continue
            if not stat_module.S_ISDIR(info.st_mode):
                continue
            try:
                entries = sorted(os.scandir(current), key=lambda entry: entry.name)
            except OSError as exc:
                raise HostFileError("HOST_FILE_INSPECTION_FAILED", "directory metadata could not be enumerated") from exc
            for entry in reversed(entries):
                child_relative = entry.name if relative == "." else f"{relative}/{entry.name}"
                stack.append((Path(entry.path), child_relative))
        return digest.hexdigest(), total_bytes, count

    def _receipt_path(self, preflight_id: str) -> Path:
        if not isinstance(preflight_id, str) or len(preflight_id) != 32 or any(
            character not in "0123456789abcdef" for character in preflight_id
        ):
            raise HostFileError("HOST_FILE_PREFLIGHT_UNKNOWN", "preflight receipt is unknown")
        return self._policy.receipt_root / f"{preflight_id}.json"

    def _write_receipt(self, receipt: Mapping[str, object]) -> None:
        root = self._policy.receipt_root
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(root, 0o700)
        except OSError:
            pass
        path = self._receipt_path(str(receipt["preflight_id"]))
        try:
            with path.open("x", encoding="utf-8") as handle:
                json.dump(dict(receipt), handle, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except FileExistsError as exc:
            raise HostFileError("HOST_FILE_PREFLIGHT_COLLISION", "preflight receipt collision") from exc

    def _read_receipt(self, preflight_id: str) -> tuple[Path, dict[str, object]]:
        path = self._receipt_path(preflight_id)
        try:
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except FileNotFoundError as exc:
            raise HostFileError("HOST_FILE_PREFLIGHT_UNKNOWN", "preflight receipt is unknown") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise HostFileError("HOST_FILE_PREFLIGHT_INVALID", "preflight receipt is unreadable") from exc
        if not isinstance(payload, dict) or payload.get("preflight_id") != preflight_id:
            raise HostFileError("HOST_FILE_PREFLIGHT_INVALID", "preflight receipt is invalid")
        return path, payload

    @staticmethod
    def _unlink_receipt(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def preflight(self, *, operation: str, paths: Iterable[str]) -> dict[str, object]:
        if operation not in self._OPERATIONS:
            raise HostFileError("HOST_FILE_OPERATION_INVALID", "operation must be trash or delete")
        raw_paths = list(paths)
        if not 1 <= len(raw_paths) <= self._policy.max_paths:
            raise HostFileError("HOST_FILE_ARGUMENT_INVALID", "paths exceed the bounded target count")

        items: list[dict[str, object]] = []
        seen: set[str] = set()
        estimated_bytes = 0
        for raw in raw_paths:
            target = self._resolve_target(raw, operation=operation)
            target_text = str(target)
            if target_text in seen:
                raise HostFileError("HOST_FILE_ARGUMENT_INVALID", "duplicate mutation targets are not allowed")
            seen.add(target_text)
            fingerprint, size_bytes, entry_count = self._metadata_fingerprint(target)
            estimated_bytes += size_bytes
            items.append(
                {
                    "path": target_text,
                    "fingerprint": fingerprint,
                    "estimated_bytes": size_bytes,
                    "entry_count": entry_count,
                }
            )

        preflight_id = secrets.token_hex(16)
        confirmation = f"APPLY HOST FILE {operation.upper()} {preflight_id}"
        created_at = time.time()
        receipt: dict[str, object] = {
            "schema_version": 2,
            "preflight_id": preflight_id,
            "operation": operation,
            "items": items,
            "created_at": created_at,
            "expires_at": created_at + self._policy.receipt_ttl_seconds,
            "confirmation": confirmation,
            "capability_epoch": self._capability_epoch,
        }
        self._write_receipt(receipt)
        return {
            "preflight_id": preflight_id,
            "operation": operation,
            "items": items,
            "estimated_bytes": estimated_bytes,
            "expires_at": receipt["expires_at"],
            "confirmation": confirmation,
            "destructive": True,
            "reversible": operation == "trash",
        }

    def _trash_destination(self, target: Path) -> Path:
        trash = self._policy.trash_root
        trash.mkdir(mode=0o700, parents=True, exist_ok=True)
        for _ in range(16):
            candidate = trash / f"{target.name}.{secrets.token_hex(8)}"
            if not os.path.lexists(candidate):
                return candidate
        raise HostFileError("HOST_FILE_TRASH_COLLISION", "could not allocate a unique Trash destination")

    def _trash(self, target: Path) -> Path:
        destination = self._trash_destination(target)
        try:
            target.rename(destination)
        except OSError as exc:
            if exc.errno == errno.EXDEV:
                raise HostFileError(
                    "HOST_FILE_TRASH_CROSS_DEVICE",
                    "target cannot be moved to the current user's Trash without crossing filesystems",
                ) from exc
            raise HostFileError("HOST_FILE_MUTATION_FAILED", "target could not be moved to Trash") from exc
        return destination

    @staticmethod
    def _delete(target: Path) -> None:
        try:
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
        except OSError as exc:
            raise HostFileError("HOST_FILE_MUTATION_FAILED", "target could not be permanently deleted") from exc

    def apply(self, *, preflight_id: str, confirmation: str) -> dict[str, object]:
        receipt_path, receipt = self._read_receipt(preflight_id)
        if receipt.get("schema_version") != 2 or receipt.get("capability_epoch") != self._capability_epoch:
            # Without a product-side supersession signal this process can
            # reject cross-child reuse but cannot invalidate the creator.
            raise HostFileError(
                "HOST_FILE_PREFLIGHT_CAPABILITY_MISMATCH",
                "preflight receipt belongs to a different runtime capability epoch",
            )
        expires_at = receipt.get("expires_at")
        if not isinstance(expires_at, (int, float)) or time.time() > float(expires_at):
            self._unlink_receipt(receipt_path)
            raise HostFileError("HOST_FILE_PREFLIGHT_EXPIRED", "preflight receipt has expired")
        expected_confirmation = receipt.get("confirmation")
        if not isinstance(confirmation, str) or confirmation != expected_confirmation:
            raise HostFileError("HOST_FILE_CONFIRMATION_MISMATCH", "confirmation does not match the preflight")
        operation = receipt.get("operation")
        if operation not in self._OPERATIONS:
            self._unlink_receipt(receipt_path)
            raise HostFileError("HOST_FILE_PREFLIGHT_INVALID", "preflight operation is invalid")
        raw_items = receipt.get("items")
        if not isinstance(raw_items, list) or not raw_items:
            self._unlink_receipt(receipt_path)
            raise HostFileError("HOST_FILE_PREFLIGHT_INVALID", "preflight target list is invalid")

        validated: list[tuple[Path, dict[str, object]]] = []
        try:
            for raw_item in raw_items:
                if not isinstance(raw_item, dict) or not isinstance(raw_item.get("path"), str):
                    raise HostFileError("HOST_FILE_PREFLIGHT_INVALID", "preflight target is invalid")
                target = self._resolve_target(raw_item["path"], operation=str(operation))
                fingerprint, _, _ = self._metadata_fingerprint(target)
                if fingerprint != raw_item.get("fingerprint"):
                    raise HostFileError("HOST_FILE_TARGET_STALE", "target changed after preflight")
                validated.append((target, raw_item))
        except HostFileError:
            self._unlink_receipt(receipt_path)
            raise

        self._unlink_receipt(receipt_path)
        results: list[dict[str, object]] = []
        for target, raw_item in validated:
            if operation == "trash":
                destination = self._trash(target)
                results.append(
                    {
                        "path": str(target),
                        "destination": str(destination),
                        "estimated_bytes": raw_item.get("estimated_bytes", 0),
                    }
                )
            else:
                self._delete(target)
                results.append(
                    {
                        "path": str(target),
                        "estimated_bytes": raw_item.get("estimated_bytes", 0),
                    }
                )
        return {
            "preflight_id": preflight_id,
            "operation": operation,
            "items": results,
            "reversible": operation == "trash",
            "applied": True,
        }
