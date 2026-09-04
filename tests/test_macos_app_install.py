from __future__ import annotations

import io
import plistlib
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
import unittest

from chatgpt_dev_mcp.macos_app_install import (
    MacOSAppInstallController,
    MacOSAppInstallError,
    MacOSAppInstallPlan,
)


class _Result:
    def __init__(self, returncode: int = 0, *, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _app(root: Path, name: str, *, bundle_id: str, version: str) -> Path:
    app = root / name
    contents = app / "Contents"
    contents.mkdir(parents=True)
    with (contents / "Info.plist").open("wb") as handle:
        plistlib.dump(
            {
                "CFBundleIdentifier": bundle_id,
                "CFBundleShortVersionString": version,
            },
            handle,
        )
    return app


class MacOSAppInstallControllerTests(unittest.TestCase):
    def test_prepare_is_replace_only_https_and_pins_existing_identity(self) -> None:
        with TemporaryDirectory() as temp:
            applications = Path(temp) / "Applications"
            applications.mkdir()
            current = _app(
                applications,
                "Demo.app",
                bundle_id="com.example.demo",
                version="1.2.3",
            )
            seen: list[tuple[str, ...]] = []

            def runner(argv: tuple[str, ...], timeout: float = 30.0) -> _Result:
                del timeout
                seen.append(argv)
                if argv[:3] == ("/usr/bin/codesign", "-dv", "--verbose=4"):
                    return _Result(stderr="Identifier=com.example.demo\nTeamIdentifier=TEAM12345\n")
                raise AssertionError(argv)

            controller = MacOSAppInstallController(applications_root=applications, runner=runner)
            plan = controller.prepare(
                source_url="https://downloads.example.com/Demo.dmg",
                app_name="Demo.app",
                bundle_id="com.example.demo",
            )

            self.assertEqual(plan.destination, current)
            self.assertEqual(plan.installed_version, "1.2.3")
            self.assertEqual(plan.expected_team_id, "TEAM12345")
            self.assertEqual(plan.bundle_id, "com.example.demo")
            self.assertEqual(seen[0][-1], str(current))

            for bad_url in (
                "http://downloads.example.com/Demo.dmg",
                "https://user:pass@downloads.example.com/Demo.dmg",
                "file:///tmp/Demo.dmg",
            ):
                with self.assertRaises(MacOSAppInstallError):
                    controller.prepare(
                        source_url=bad_url,
                        app_name="Demo.app",
                        bundle_id="com.example.demo",
                    )

            with self.assertRaises(MacOSAppInstallError):
                controller.prepare(
                    source_url="https://downloads.example.com/Demo.dmg",
                    app_name="../Demo.app",
                    bundle_id="com.example.demo",
                )

    def test_prepare_rejects_missing_symlink_and_bundle_mismatch(self) -> None:
        with TemporaryDirectory() as temp:
            applications = Path(temp) / "Applications"
            applications.mkdir()
            controller = MacOSAppInstallController(applications_root=applications)
            with self.assertRaises(MacOSAppInstallError) as missing:
                controller.prepare(
                    source_url="https://downloads.example.com/Demo.dmg",
                    app_name="Demo.app",
                    bundle_id="com.example.demo",
                )
            self.assertEqual(missing.exception.code, "MACOS_APP_EXISTING_REQUIRED")

            target = _app(
                applications,
                "Real.app",
                bundle_id="com.example.real",
                version="1",
            )
            (applications / "Demo.app").symlink_to(target, target_is_directory=True)
            with self.assertRaises(MacOSAppInstallError) as symlink:
                controller.prepare(
                    source_url="https://downloads.example.com/Demo.dmg",
                    app_name="Demo.app",
                    bundle_id="com.example.real",
                )
            self.assertEqual(symlink.exception.code, "MACOS_APP_PATH_DENIED")

        with TemporaryDirectory() as temp:
            applications = Path(temp) / "Applications"
            applications.mkdir()
            _app(applications, "Demo.app", bundle_id="com.example.other", version="1")
            controller = MacOSAppInstallController(applications_root=applications)
            with self.assertRaises(MacOSAppInstallError) as mismatch:
                controller.prepare(
                    source_url="https://downloads.example.com/Demo.dmg",
                    app_name="Demo.app",
                    bundle_id="com.example.demo",
                )
            self.assertEqual(mismatch.exception.code, "MACOS_APP_BUNDLE_MISMATCH")

    def test_prepare_accepts_tar_gz_tgz_and_extensionless_https_redirect(self) -> None:
        with TemporaryDirectory() as temp:
            applications = Path(temp) / "Applications"
            applications.mkdir()
            _app(applications, "Demo.app", bundle_id="com.example.demo", version="1.0")

            def runner(argv: tuple[str, ...], timeout: float = 30.0) -> _Result:
                del timeout
                if argv[:3] == ("/usr/bin/codesign", "-dv", "--verbose=4"):
                    return _Result(stderr="Identifier=com.example.demo\nTeamIdentifier=TEAM12345\n")
                raise AssertionError(argv)

            controller = MacOSAppInstallController(applications_root=applications, runner=runner)
            for source_url, expected_kind in (
                ("https://downloads.example.com/Demo.tar.gz", "tar_gz"),
                ("https://downloads.example.com/Demo.tgz", "tar_gz"),
                ("https://downloads.example.com/fetch-latest?name=demo", "auto"),
            ):
                plan = controller.prepare(
                    source_url=source_url,
                    app_name="Demo.app",
                    bundle_id="com.example.demo",
                )
                self.assertEqual(plan.artifact_kind, expected_kind)

    def test_safe_tar_gz_extraction_finds_expected_app_and_rejects_traversal(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            controller = MacOSAppInstallController(applications_root=root)
            good_archive = root / "good.tar.gz"
            payload = plistlib.dumps(
                {
                    "CFBundleIdentifier": "com.example.demo",
                    "CFBundleShortVersionString": "2.0",
                }
            )
            with tarfile.open(good_archive, "w:gz") as archive:
                directory = tarfile.TarInfo("Demo.app/Contents")
                directory.type = tarfile.DIRTYPE
                archive.addfile(directory)
                info = tarfile.TarInfo("Demo.app/Contents/Info.plist")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            extracted = root / "good-extracted"
            extracted.mkdir()
            controller._extract_tar_gz_safely(good_archive, extracted)
            self.assertEqual(controller._find_matching_app(extracted, "com.example.demo").name, "Demo.app")

            bad_archive = root / "bad.tar.gz"
            with tarfile.open(bad_archive, "w:gz") as archive:
                info = tarfile.TarInfo("../escape.txt")
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
            bad_extracted = root / "bad-extracted"
            bad_extracted.mkdir()
            with self.assertRaises(MacOSAppInstallError) as traversal:
                controller._extract_tar_gz_safely(bad_archive, bad_extracted)
            self.assertEqual(traversal.exception.code, "MACOS_APP_ARCHIVE_INVALID")
            self.assertFalse((root / "escape.txt").exists())

    def test_tar_gz_staging_uses_embedded_dmg_instead_of_direct_cli_app(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            scratch = root / "scratch"
            scratch.mkdir()
            artifact = root / "OpenD.tar.gz"
            cli_info = plistlib.dumps(
                {
                    "CFBundleIdentifier": "com.moomoo.opend",
                    "CFBundleShortVersionString": "10.9.6908-cli",
                }
            )
            with tarfile.open(artifact, "w:gz") as archive:
                cli_dir = tarfile.TarInfo("FutuOpenD.app/Contents")
                cli_dir.type = tarfile.DIRTYPE
                archive.addfile(cli_dir)
                info = tarfile.TarInfo("FutuOpenD.app/Contents/Info.plist")
                info.size = len(cli_info)
                archive.addfile(info, io.BytesIO(cli_info))
                dmg = tarfile.TarInfo("OpenD-GUI.dmg")
                dmg.size = 4
                archive.addfile(dmg, io.BytesIO(b"DMG!"))

            mounted = root / "mounted"
            mounted.mkdir()
            gui_app = _app(
                mounted,
                "moomoo_OpenD.app",
                bundle_id="com.moomoo.opend",
                version="10.9.6908",
            )
            calls: list[tuple[str, ...]] = []

            def runner(argv: tuple[str, ...], timeout: float = 30.0) -> _Result:
                del timeout
                calls.append(argv)
                if argv[:4] == ("/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse"):
                    return _Result(
                        stdout=plistlib.dumps(
                            {"system-entities": [{"mount-point": str(mounted)}]}
                        ).decode("utf-8")
                    )
                if argv[:3] == ("/usr/bin/hdiutil", "detach", "-force"):
                    return _Result()
                raise AssertionError(argv)

            controller = MacOSAppInstallController(applications_root=root / "Applications", runner=runner)
            plan = MacOSAppInstallPlan(
                source_url="https://downloads.example.com/OpenD.tar.gz",
                artifact_kind="tar_gz",
                app_name="moomoo_OpenD.app",
                bundle_id="com.moomoo.opend",
                destination=root / "Applications" / "moomoo_OpenD.app",
                installed_version="10.7.6718",
                expected_team_id="TEAM12345",
            )

            staged, cleanup = controller._stage_artifact(
                plan,
                artifact,
                scratch,
                artifact_kind="tar_gz",
            )
            try:
                self.assertEqual(staged, gui_app)
                attach_calls = [argv for argv in calls if argv[:2] == ("/usr/bin/hdiutil", "attach")]
                self.assertEqual(len(attach_calls), 1)
                self.assertTrue(attach_calls[0][-1].endswith("OpenD-GUI.dmg"))
            finally:
                cleanup()

    def test_auto_artifact_detection_uses_redirect_suffix_or_content_probe(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            controller = MacOSAppInstallController(applications_root=root)
            artifact = root / "download.artifact"
            with tarfile.open(artifact, "w:gz") as archive:
                info = tarfile.TarInfo("payload.txt")
                info.size = 1
                archive.addfile(info, io.BytesIO(b"x"))
            self.assertEqual(
                controller._resolve_artifact_kind("auto", "https://cdn.example.com/OpenD.tar.gz", artifact),
                "tar_gz",
            )
            self.assertEqual(
                controller._resolve_artifact_kind("auto", "https://cdn.example.com/download", artifact),
                "tar_gz",
            )

    def test_execute_requires_same_bundle_signer_and_gatekeeper_acceptance(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            applications = root / "Applications"
            applications.mkdir()
            _app(applications, "Demo.app", bundle_id="com.example.demo", version="1.0")
            staged = _app(root, "Staged.app", bundle_id="com.example.demo", version="2.0")
            calls: list[tuple[str, ...]] = []

            def runner(argv: tuple[str, ...], timeout: float = 30.0) -> _Result:
                del timeout
                calls.append(argv)
                if argv[:3] == ("/usr/bin/codesign", "-dv", "--verbose=4"):
                    return _Result(stderr="Identifier=com.example.demo\nTeamIdentifier=TEAM12345\n")
                if argv[:3] == ("/usr/bin/codesign", "--verify", "--deep"):
                    return _Result()
                if argv[:3] == ("/usr/sbin/spctl", "--assess", "--type"):
                    return _Result()
                if argv[:2] == ("/usr/bin/osascript", "-e"):
                    return _Result()
                if argv[0] == "/usr/bin/ditto":
                    source, destination = Path(argv[1]), Path(argv[2])
                    import shutil

                    shutil.copytree(source, destination, symlinks=True)
                    return _Result()
                raise AssertionError(argv)

            controller = MacOSAppInstallController(applications_root=applications, runner=runner)
            plan = controller.prepare(
                source_url="https://downloads.example.com/Demo.dmg",
                app_name="Demo.app",
                bundle_id="com.example.demo",
            )
            result = controller.replace_from_staged_app(plan, staged)

            self.assertTrue(result.ok)
            self.assertEqual(result.previous_version, "1.0")
            self.assertEqual(result.installed_version, "2.0")
            self.assertEqual(result.bundle_id, "com.example.demo")
            self.assertEqual(
                plistlib.loads((applications / "Demo.app" / "Contents" / "Info.plist").read_bytes())[
                    "CFBundleShortVersionString"
                ],
                "2.0",
            )
            self.assertTrue(any(argv[0] == "/usr/sbin/spctl" for argv in calls))
            self.assertTrue(any(argv[0] == "/usr/bin/ditto" for argv in calls))

    def test_replace_rolls_back_when_final_validation_fails(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            applications = root / "Applications"
            applications.mkdir()
            _app(applications, "Demo.app", bundle_id="com.example.demo", version="1.0")
            staged = _app(root, "Staged.app", bundle_id="com.example.demo", version="2.0")
            verify_count = 0

            def runner(argv: tuple[str, ...], timeout: float = 30.0) -> _Result:
                nonlocal verify_count
                del timeout
                if argv[:3] == ("/usr/bin/codesign", "-dv", "--verbose=4"):
                    return _Result(stderr="Identifier=com.example.demo\nTeamIdentifier=TEAM12345\n")
                if argv[:3] == ("/usr/bin/codesign", "--verify", "--deep"):
                    verify_count += 1
                    return _Result(returncode=1 if verify_count >= 2 else 0, stderr="bad signature")
                if argv[:3] == ("/usr/sbin/spctl", "--assess", "--type"):
                    return _Result()
                if argv[:2] == ("/usr/bin/osascript", "-e"):
                    return _Result()
                if argv[0] == "/usr/bin/ditto":
                    import shutil

                    shutil.copytree(Path(argv[1]), Path(argv[2]), symlinks=True)
                    return _Result()
                raise AssertionError(argv)

            controller = MacOSAppInstallController(applications_root=applications, runner=runner)
            plan = controller.prepare(
                source_url="https://downloads.example.com/Demo.dmg",
                app_name="Demo.app",
                bundle_id="com.example.demo",
            )
            with self.assertRaises(MacOSAppInstallError) as failed:
                controller.replace_from_staged_app(plan, staged)
            self.assertEqual(failed.exception.code, "MACOS_APP_SIGNATURE_INVALID")
            info = plistlib.loads((applications / "Demo.app" / "Contents" / "Info.plist").read_bytes())
            self.assertEqual(info["CFBundleShortVersionString"], "1.0")

    def test_replace_rejects_signer_change_before_mutating_destination(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            applications = root / "Applications"
            applications.mkdir()
            _app(applications, "Demo.app", bundle_id="com.example.demo", version="1.0")
            staged = _app(root, "Staged.app", bundle_id="com.example.demo", version="2.0")
            signature_reads = 0

            def runner(argv: tuple[str, ...], timeout: float = 30.0) -> _Result:
                nonlocal signature_reads
                del timeout
                if argv[:3] == ("/usr/bin/codesign", "-dv", "--verbose=4"):
                    signature_reads += 1
                    team = "TEAM12345" if signature_reads == 1 else "EVILTEAM"
                    return _Result(stderr=f"Identifier=com.example.demo\nTeamIdentifier={team}\n")
                if argv[:3] == ("/usr/bin/codesign", "--verify", "--deep"):
                    return _Result()
                if argv[:3] == ("/usr/sbin/spctl", "--assess", "--type"):
                    return _Result()
                raise AssertionError(argv)

            controller = MacOSAppInstallController(applications_root=applications, runner=runner)
            plan = controller.prepare(
                source_url="https://downloads.example.com/Demo.dmg",
                app_name="Demo.app",
                bundle_id="com.example.demo",
            )
            with self.assertRaises(MacOSAppInstallError) as failed:
                controller.replace_from_staged_app(plan, staged)
            self.assertEqual(failed.exception.code, "MACOS_APP_SIGNER_MISMATCH")
            info = plistlib.loads((applications / "Demo.app" / "Contents" / "Info.plist").read_bytes())
            self.assertEqual(info["CFBundleShortVersionString"], "1.0")


if __name__ == "__main__":
    unittest.main()
