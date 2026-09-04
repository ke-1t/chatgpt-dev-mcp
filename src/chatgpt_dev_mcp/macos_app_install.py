"""Bounded, shell-free replacement of an existing signed macOS app bundle.

This module is deliberately replace-only: it cannot install a new app, execute
pkg installers, elevate privileges, or remove application support/user data.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from typing import Callable, Protocol
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


CODESIGN = "/usr/bin/codesign"
SPCTL = "/usr/sbin/spctl"
HDITUIL = "/usr/bin/hdiutil"
DITTO = "/usr/bin/ditto"
MAX_DOWNLOAD_BYTES = 1_500_000_000

_BUNDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$")
_APP_NAME_RE = re.compile(r"^[^/\\\x00-\x1f\x7f]{1,200}\.app$")
_TEAM_RE = re.compile(r"^TeamIdentifier=([A-Za-z0-9]+)$", re.MULTILINE)


class MacOSAppInstallError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class _RunResult(Protocol):
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[tuple[str, ...], float], _RunResult]


def _default_runner(argv: tuple[str, ...], timeout: float = 30.0) -> _RunResult:
    return subprocess.run(
        argv,
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@dataclass(frozen=True)
class MacOSAppInstallPlan:
    source_url: str
    artifact_kind: str
    app_name: str
    bundle_id: str
    destination: Path
    installed_version: str
    expected_team_id: str


@dataclass(frozen=True)
class MacOSAppInstallResult:
    ok: bool
    bundle_id: str
    previous_version: str
    installed_version: str
    destination: str
    team_id: str
    user_data_removed: bool = False
    privilege_escalation_used: bool = False


class MacOSAppInstallController:
    """Replace one existing /Applications app with a same-identity signed app."""

    def __init__(
        self,
        *,
        applications_root: Path = Path("/Applications"),
        runner: Runner | None = None,
        max_download_bytes: int = MAX_DOWNLOAD_BYTES,
    ) -> None:
        self._applications_root = Path(applications_root)
        self._runner = runner or _default_runner
        self._max_download_bytes = max_download_bytes

    def prepare(self, *, source_url: object, app_name: object, bundle_id: object) -> MacOSAppInstallPlan:
        url, artifact_kind = self._validate_source_url(source_url)
        name = self._validate_app_name(app_name)
        expected_bundle = self._validate_bundle_id(bundle_id)
        destination = self._applications_root / name
        if destination.is_symlink():
            raise MacOSAppInstallError("MACOS_APP_PATH_DENIED", "existing app path must not be a symlink")
        if not destination.is_dir():
            raise MacOSAppInstallError("MACOS_APP_EXISTING_REQUIRED", "replace-only install requires an existing app bundle")
        current_bundle, current_version = self._bundle_metadata(destination)
        if current_bundle != expected_bundle:
            raise MacOSAppInstallError("MACOS_APP_BUNDLE_MISMATCH", "existing app bundle identifier does not match the requested identity")
        team_id = self._read_team_id(destination)
        return MacOSAppInstallPlan(
            source_url=url,
            artifact_kind=artifact_kind,
            app_name=name,
            bundle_id=expected_bundle,
            destination=destination,
            installed_version=current_version,
            expected_team_id=team_id,
        )

    def execute(self, plan: MacOSAppInstallPlan) -> MacOSAppInstallResult:
        if not isinstance(plan, MacOSAppInstallPlan):
            raise MacOSAppInstallError("MACOS_APP_PLAN_INVALID", "only a prepared app-install plan may be executed")
        with tempfile.TemporaryDirectory(prefix="devmcp-app-install-") as temporary:
            scratch = Path(temporary)
            artifact = scratch / "download.artifact"
            final_url = self._download_https(plan.source_url, artifact)
            artifact_kind = self._resolve_artifact_kind(plan.artifact_kind, final_url, artifact)
            cleanup: Callable[[], None] = lambda: None
            try:
                staged, cleanup = self._stage_artifact(plan, artifact, scratch, artifact_kind=artifact_kind)
                return self.replace_from_staged_app(plan, staged)
            finally:
                cleanup()

    def replace_from_staged_app(self, plan: MacOSAppInstallPlan, staged_app: Path) -> MacOSAppInstallResult:
        """Validate and atomically replace from an already-staged app bundle."""

        if not isinstance(plan, MacOSAppInstallPlan):
            raise MacOSAppInstallError("MACOS_APP_PLAN_INVALID", "only a prepared app-install plan may be executed")
        staged = Path(staged_app)
        if staged.is_symlink() or not staged.is_dir() or staged.suffix.casefold() != ".app":
            raise MacOSAppInstallError("MACOS_APP_STAGED_INVALID", "staged target must be a non-symlink app bundle")

        new_bundle, new_version = self._bundle_metadata(staged)
        if new_bundle != plan.bundle_id:
            raise MacOSAppInstallError("MACOS_APP_BUNDLE_MISMATCH", "downloaded app bundle identifier does not match the installed app")
        self._verify_platform_trust(staged)
        new_team = self._read_team_id(staged)
        if new_team != plan.expected_team_id:
            raise MacOSAppInstallError("MACOS_APP_SIGNER_MISMATCH", "downloaded app is signed by a different developer team")

        destination = plan.destination
        if destination.is_symlink() or not destination.is_dir():
            raise MacOSAppInstallError("MACOS_APP_EXISTING_CHANGED", "installed app changed after preflight")
        current_bundle, current_version = self._bundle_metadata(destination)
        current_team = self._read_team_id(destination)
        if (
            current_bundle != plan.bundle_id
            or current_version != plan.installed_version
            or current_team != plan.expected_team_id
        ):
            raise MacOSAppInstallError("MACOS_APP_EXISTING_CHANGED", "installed app identity changed after preflight")

        backup = destination.with_name(f".{destination.name}.devmcp-backup-{secrets.token_hex(8)}")
        if backup.exists() or backup.is_symlink():
            raise MacOSAppInstallError("MACOS_APP_BACKUP_COLLISION", "temporary app backup path already exists")

        moved_existing = False
        try:
            os.replace(destination, backup)
            moved_existing = True
            copy_result = self._run((DITTO, str(staged), str(destination)), timeout=120.0)
            if copy_result.returncode != 0:
                raise MacOSAppInstallError("MACOS_APP_COPY_FAILED", self._bounded_error(copy_result, "app copy failed"))
            final_bundle, final_version = self._bundle_metadata(destination)
            if final_bundle != plan.bundle_id or final_version != new_version:
                raise MacOSAppInstallError("MACOS_APP_FINAL_IDENTITY_INVALID", "installed app identity differs from the validated staged app")
            self._verify_platform_trust(destination)
            final_team = self._read_team_id(destination)
            if final_team != plan.expected_team_id:
                raise MacOSAppInstallError("MACOS_APP_SIGNER_MISMATCH", "installed app signer differs after replacement")
        except Exception:
            if moved_existing:
                self._remove_bundle_if_present(destination)
                try:
                    os.replace(backup, destination)
                except OSError as exc:
                    raise MacOSAppInstallError(
                        "MACOS_APP_ROLLBACK_FAILED",
                        f"app replacement failed and rollback could not restore the previous bundle: {exc}",
                    ) from exc
            raise
        else:
            self._remove_bundle_if_present(backup)

        return MacOSAppInstallResult(
            ok=True,
            bundle_id=plan.bundle_id,
            previous_version=plan.installed_version,
            installed_version=new_version,
            destination=str(destination),
            team_id=plan.expected_team_id,
        )

    def _validate_source_url(self, value: object) -> tuple[str, str]:
        if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise MacOSAppInstallError("MACOS_APP_SOURCE_INVALID", "source URL must be a bounded HTTPS URL")
        try:
            parsed = urlsplit(value)
        except ValueError:
            raise MacOSAppInstallError("MACOS_APP_SOURCE_INVALID", "source URL is malformed") from None
        if parsed.scheme.casefold() != "https" or not parsed.netloc or "@" in parsed.netloc:
            raise MacOSAppInstallError("MACOS_APP_SOURCE_INVALID", "source URL must use HTTPS without embedded credentials")
        return value, self._artifact_kind_from_url(value)

    @staticmethod
    def _artifact_kind_from_url(value: str) -> str:
        path = urlsplit(value).path.casefold()
        if path.endswith(".tar.gz") or path.endswith(".tgz"):
            return "tar_gz"
        if path.endswith(".dmg"):
            return "dmg"
        if path.endswith(".zip"):
            return "zip"
        return "auto"

    def _resolve_artifact_kind(self, planned: str, final_url: str, artifact: Path) -> str:
        if planned != "auto":
            return planned
        redirected = self._artifact_kind_from_url(final_url)
        if redirected != "auto":
            return redirected
        if zipfile.is_zipfile(artifact):
            return "zip"
        try:
            with artifact.open("rb") as handle:
                gzip_magic = handle.read(2) == b"\x1f\x8b"
        except OSError as exc:
            raise MacOSAppInstallError("MACOS_APP_ARTIFACT_INVALID", f"downloaded artifact could not be inspected: {exc}") from exc
        if gzip_magic and tarfile.is_tarfile(artifact):
            return "tar_gz"
        image_info = self._run((HDITUIL, "imageinfo", "-plist", str(artifact)), timeout=60.0)
        if image_info.returncode == 0:
            return "dmg"
        raise MacOSAppInstallError(
            "MACOS_APP_ARTIFACT_UNSUPPORTED",
            "downloaded artifact is not a supported DMG, ZIP, TAR.GZ, or TGZ distribution",
        )

    @staticmethod
    def _validate_app_name(value: object) -> str:
        if not isinstance(value, str) or _APP_NAME_RE.fullmatch(value) is None or value in {".", ".."}:
            raise MacOSAppInstallError("MACOS_APP_NAME_INVALID", "app name must be one plain .app bundle name")
        return value

    @staticmethod
    def _validate_bundle_id(value: object) -> str:
        if not isinstance(value, str) or len(value) > 255 or _BUNDLE_RE.fullmatch(value) is None:
            raise MacOSAppInstallError("MACOS_APP_BUNDLE_INVALID", "bundle identifier is invalid")
        return value

    @staticmethod
    def _bundle_metadata(app: Path) -> tuple[str, str]:
        info = app / "Contents" / "Info.plist"
        try:
            with info.open("rb") as handle:
                payload = plistlib.load(handle)
        except (OSError, plistlib.InvalidFileException, ValueError) as exc:
            raise MacOSAppInstallError("MACOS_APP_INFO_INVALID", "app Info.plist is unavailable or invalid") from exc
        bundle_id = payload.get("CFBundleIdentifier")
        version = payload.get("CFBundleShortVersionString") or payload.get("CFBundleVersion")
        if not isinstance(bundle_id, str) or not isinstance(version, str) or not bundle_id or not version:
            raise MacOSAppInstallError("MACOS_APP_INFO_INVALID", "app identity metadata is incomplete")
        return bundle_id, version

    def _read_team_id(self, app: Path) -> str:
        result = self._run((CODESIGN, "-dv", "--verbose=4", str(app)), timeout=30.0)
        if result.returncode != 0:
            raise MacOSAppInstallError("MACOS_APP_SIGNATURE_INVALID", self._bounded_error(result, "code signature metadata is unavailable"))
        combined = f"{getattr(result, 'stdout', '')}\n{getattr(result, 'stderr', '')}"
        match = _TEAM_RE.search(combined)
        if match is None:
            raise MacOSAppInstallError("MACOS_APP_SIGNATURE_INVALID", "code signature has no TeamIdentifier")
        return match.group(1)

    def _verify_platform_trust(self, app: Path) -> None:
        signature = self._run((CODESIGN, "--verify", "--deep", "--strict", "--verbose=2", str(app)), timeout=60.0)
        if signature.returncode != 0:
            raise MacOSAppInstallError("MACOS_APP_SIGNATURE_INVALID", self._bounded_error(signature, "code signature verification failed"))
        assessment = self._run((SPCTL, "--assess", "--type", "execute", "--verbose=4", str(app)), timeout=60.0)
        if assessment.returncode != 0:
            raise MacOSAppInstallError("MACOS_APP_GATEKEEPER_REJECTED", self._bounded_error(assessment, "Gatekeeper rejected the app"))

    def _download_https(self, source_url: str, destination: Path) -> str:
        request = Request(source_url, headers={"User-Agent": "ChatGPT-DevMCP/0.41"})
        try:
            with urlopen(request, timeout=30) as response, destination.open("wb") as output:
                final = urlsplit(response.geturl())
                if final.scheme.casefold() != "https" or not final.netloc or "@" in final.netloc:
                    raise MacOSAppInstallError("MACOS_APP_DOWNLOAD_REDIRECT_DENIED", "download redirected outside HTTPS")
                declared = response.headers.get("Content-Length")
                if declared is not None:
                    try:
                        declared_bytes = int(declared)
                    except ValueError:
                        declared_bytes = -1
                    if declared_bytes > self._max_download_bytes:
                        raise MacOSAppInstallError("MACOS_APP_DOWNLOAD_TOO_LARGE", "download exceeds the bounded artifact size")
                total = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self._max_download_bytes:
                        raise MacOSAppInstallError("MACOS_APP_DOWNLOAD_TOO_LARGE", "download exceeds the bounded artifact size")
                    output.write(chunk)
                return response.geturl()
        except MacOSAppInstallError:
            raise
        except OSError as exc:
            raise MacOSAppInstallError("MACOS_APP_DOWNLOAD_FAILED", f"HTTPS download failed: {exc}") from exc

    def _stage_artifact(
        self,
        plan: MacOSAppInstallPlan,
        artifact: Path,
        scratch: Path,
        *,
        artifact_kind: str | None = None,
    ) -> tuple[Path, Callable[[], None]]:
        kind = artifact_kind or plan.artifact_kind
        if kind == "zip":
            extracted = scratch / "extracted"
            extracted.mkdir()
            result = self._run((DITTO, "-x", "-k", str(artifact), str(extracted)), timeout=120.0)
            if result.returncode != 0:
                raise MacOSAppInstallError("MACOS_APP_ARCHIVE_INVALID", self._bounded_error(result, "ZIP extraction failed"))
            return self._find_matching_app(extracted, plan.bundle_id), lambda: None

        if kind == "tar_gz":
            extracted = scratch / "extracted"
            extracted.mkdir()
            self._extract_tar_gz_safely(artifact, extracted)
            embedded_dmg = self._find_single_embedded_dmg(extracted)
            return self._stage_artifact(
                plan,
                embedded_dmg,
                scratch,
                artifact_kind="dmg",
            )

        if kind != "dmg":
            raise MacOSAppInstallError("MACOS_APP_ARTIFACT_UNSUPPORTED", "artifact type is unsupported")

        attach = self._run((HDITUIL, "attach", "-readonly", "-nobrowse", "-plist", str(artifact)), timeout=120.0)
        if attach.returncode != 0:
            raise MacOSAppInstallError("MACOS_APP_DMG_MOUNT_FAILED", self._bounded_error(attach, "DMG mount failed"))
        try:
            payload = plistlib.loads(getattr(attach, "stdout", "").encode("utf-8"))
            entities = payload.get("system-entities", [])
            mount_points = [entry.get("mount-point") for entry in entities if isinstance(entry, dict) and isinstance(entry.get("mount-point"), str)]
            if len(mount_points) != 1:
                raise MacOSAppInstallError("MACOS_APP_DMG_INVALID", "DMG must expose exactly one mount point")
            mount = Path(mount_points[0])
            staged = self._find_matching_app(mount, plan.bundle_id)
        except Exception:
            self._run((HDITUIL, "detach", "-force", *(mount_points[:1] if 'mount_points' in locals() else [])), timeout=60.0)
            raise

        def cleanup() -> None:
            self._run((HDITUIL, "detach", "-force", str(mount)), timeout=60.0)

        return staged, cleanup

    @staticmethod
    def _find_single_embedded_dmg(root: Path) -> Path:
        matches = [
            candidate
            for candidate in root.rglob("*.dmg")
            if candidate.is_file() and not candidate.is_symlink()
        ]
        if len(matches) != 1:
            raise MacOSAppInstallError(
                "MACOS_APP_ARTIFACT_INVALID",
                "TAR.GZ distribution must contain exactly one non-symlink DMG",
            )
        return matches[0]

    def _extract_tar_gz_safely(self, artifact: Path, destination: Path) -> None:
        root = destination.resolve()
        try:
            with tarfile.open(artifact, mode="r:gz") as archive:
                members = archive.getmembers()
                if len(members) > 100_000:
                    raise MacOSAppInstallError("MACOS_APP_ARCHIVE_INVALID", "TAR.GZ contains too many entries")
                expanded_bytes = 0
                for member in members:
                    expanded_bytes += max(0, int(member.size))
                    if expanded_bytes > self._max_download_bytes * 4:
                        raise MacOSAppInstallError("MACOS_APP_ARCHIVE_TOO_LARGE", "TAR.GZ expands beyond the bounded extraction size")
                    member_path = PurePosixPath(member.name)
                    if member_path.is_absolute() or ".." in member_path.parts:
                        raise MacOSAppInstallError("MACOS_APP_ARCHIVE_INVALID", "TAR.GZ contains an unsafe member path")
                    target = root.joinpath(*member_path.parts).resolve(strict=False)
                    if target != root and root not in target.parents:
                        raise MacOSAppInstallError("MACOS_APP_ARCHIVE_INVALID", "TAR.GZ member escapes the extraction root")
                    if member.isdev() or member.isfifo():
                        raise MacOSAppInstallError("MACOS_APP_ARCHIVE_INVALID", "TAR.GZ contains a special device entry")
                    if member.issym() or member.islnk():
                        link = PurePosixPath(member.linkname)
                        if link.is_absolute():
                            raise MacOSAppInstallError("MACOS_APP_ARCHIVE_INVALID", "TAR.GZ contains an absolute link")
                        base = target.parent if member.issym() else root
                        link_target = base.joinpath(*link.parts).resolve(strict=False)
                        if link_target != root and root not in link_target.parents:
                            raise MacOSAppInstallError("MACOS_APP_ARCHIVE_INVALID", "TAR.GZ link escapes the extraction root")
                try:
                    archive.extractall(root, members=members, filter="data")
                except TypeError:
                    archive.extractall(root, members=members)
        except MacOSAppInstallError:
            raise
        except (OSError, tarfile.TarError) as exc:
            raise MacOSAppInstallError("MACOS_APP_ARCHIVE_INVALID", f"TAR.GZ extraction failed: {exc}") from exc

    def _find_matching_app(self, root: Path, bundle_id: str) -> Path:
        matches: list[Path] = []
        try:
            candidates = root.rglob("*.app")
            for candidate in candidates:
                if candidate.is_symlink() or not candidate.is_dir():
                    continue
                try:
                    candidate_bundle, _version = self._bundle_metadata(candidate)
                except MacOSAppInstallError:
                    continue
                if candidate_bundle == bundle_id:
                    matches.append(candidate)
                    if len(matches) > 1:
                        break
        except OSError as exc:
            raise MacOSAppInstallError("MACOS_APP_ARTIFACT_INVALID", f"could not inspect staged app: {exc}") from exc
        if len(matches) != 1:
            raise MacOSAppInstallError("MACOS_APP_ARTIFACT_INVALID", "artifact must contain exactly one app with the expected bundle identifier")
        return matches[0]

    def _run(self, argv: tuple[str, ...], *, timeout: float) -> _RunResult:
        try:
            return self._runner(argv, timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            raise MacOSAppInstallError("MACOS_APP_SYSTEM_COMMAND_FAILED", f"validated system command failed: {exc}") from exc

    @staticmethod
    def _bounded_error(result: _RunResult, fallback: str) -> str:
        message = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or fallback).strip()
        return message[:2000] or fallback

    @staticmethod
    def _remove_bundle_if_present(path: Path) -> None:
        try:
            if path.is_symlink():
                path.unlink()
            elif path.exists():
                shutil.rmtree(path)
        except OSError as exc:
            raise MacOSAppInstallError("MACOS_APP_CLEANUP_FAILED", f"could not clean temporary app bundle: {exc}") from exc


__all__ = [
    "MacOSAppInstallController",
    "MacOSAppInstallError",
    "MacOSAppInstallPlan",
    "MacOSAppInstallResult",
]
