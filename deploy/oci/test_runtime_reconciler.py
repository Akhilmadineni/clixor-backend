from __future__ import annotations

import fcntl
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_ROOT))
import runtime_bundle  # noqa: E402


RECONCILER_PATH = SCRIPT_ROOT / "runtime-reconciler.py"
SPEC = importlib.util.spec_from_file_location("clixor_runtime_reconciler", RECONCILER_PATH)
assert SPEC is not None and SPEC.loader is not None
RECONCILER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECONCILER)

SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
IMAGE_ID = "sha256:" + "a" * 64
TEMP_ROOT = "/private/tmp" if Path("/private/tmp").is_dir() else None


def _compose() -> str:
    services = []
    for index in range(11):
        services.append(f"  service-{index}:\n    image: example.invalid/{index}\n    restart: \"no\"\n")
    return "services:\n" + "".join(services)


class FakeRunner(RECONCILER.CommandRunner):
    def __init__(self, outputs: dict[tuple[str, ...], tuple[int, bytes]] | None = None):
        self.outputs = outputs or {}
        self.calls: list[tuple[str, ...]] = []

    def run(self, arguments, *, check=True, capture=False, environment=None):
        del capture, environment
        key = tuple(arguments)
        self.calls.append(key)
        returncode, stdout = self.outputs.get(key, (0, b""))
        result = subprocess.CompletedProcess(list(arguments), returncode, stdout, b"")
        if check and returncode:
            raise RECONCILER.ReconcileError("fake command failed")
        return result


class RuntimeFixture:
    def __init__(self, root: Path):
        self.root = root
        self.root.chmod(0o700)
        self.releases = root / "releases"
        self.pending = self.releases / "pending"
        self.pending.mkdir(parents=True, mode=0o700)
        self.runtime = root / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.pki = root / "secrets" / "pki"
        self.pki.mkdir(parents=True, mode=0o700)
        self.source = root / "approved-source"
        (self.source / "deploy" / "oci").mkdir(parents=True)
        (self.source / "go.mod").write_text("module example.invalid/runtime\n", encoding="ascii")
        (self.source / "deploy" / "oci" / "compose.yaml").write_text(
            _compose(), encoding="ascii"
        )
        for relative in runtime_bundle.HOST_TOOL_SOURCE_MODES:
            _, name = relative.split("/", 1)
            path = self.source / "deploy" / "oci" / name
            path.write_text(f"fixture {name}\n", encoding="ascii")
        self.cloudflared = root / "cloudflared"
        self.cloudflared.write_text("fixture cloudflared binary\n", encoding="ascii")
        self.cloudflared.chmod(0o500)
        for artifact in runtime_bundle.RUNTIME_ARTIFACTS:
            base = self.runtime if artifact.source_kind == "runtime" else self.pki
            path = base / artifact.source_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"fixture {artifact.bundle_path}\n", encoding="ascii")
        self.state = root / "state"
        self.state.write_text(
            "cloudflared_enabled=false\n"
            "cloudflared_active=false\n"
            "prometheus_active=false\n"
            "grafana_active=false\n"
            "offsite_timer_enabled=true\n"
            "restore_timer_enabled=true\n"
            "health_timer_enabled=true\n",
            encoding="ascii",
        )

    def finalized_release(self, name: str = "oci-0123456789ab-test") -> Path:
        release = self.pending / name
        release.mkdir(mode=0o700)
        runtime_bundle.stage_source(release, self.source, SOURCE_SHA)
        runtime_bundle.stage_host_tools(
            release, self.source, self.cloudflared
        )
        runtime_bundle.finalize_bundle(
            release,
            self.runtime,
            self.pki,
            SOURCE_SHA,
            f"clixor-api:{name}",
            IMAGE_ID,
            self.state,
        )
        return release


class RuntimeBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="clixor-runtime-", dir=TEMP_ROOT
        )
        self.addCleanup(self.temporary.cleanup)
        self.fixture = RuntimeFixture(Path(self.temporary.name))

    def test_complete_bundle_is_exact_and_rejects_restart_or_tampering(self) -> None:
        release = self.fixture.finalized_release()
        uid = self.fixture.root.stat().st_uid
        gid = self.fixture.root.stat().st_gid
        manifest = runtime_bundle.validate_runtime_bundle(
            release, expected_uid=uid, expected_gid=gid
        )
        self.assertEqual(manifest["schema"], 2)
        self.assertEqual(manifest["image"]["id"], IMAGE_ID)
        compose = release / "runtime-bundle" / "compose.yaml"
        compose.chmod(0o600)
        compose.write_text(
            _compose().replace('restart: "no"', "restart: on-failure", 1)
        )
        compose.chmod(0o400)
        with self.assertRaises(runtime_bundle.BundleError):
            runtime_bundle.validate_runtime_bundle(
                release, expected_uid=uid, expected_gid=gid
            )

    def test_source_tree_rejects_symlinks_and_manifest_rejects_extra_files(self) -> None:
        linked = self.fixture.source / "linked"
        linked.symlink_to(self.fixture.source / "go.mod")
        release = self.fixture.pending / "oci-0123456789ab-linked"
        release.mkdir(mode=0o700)
        with self.assertRaisesRegex(runtime_bundle.BundleError, "symbolic link"):
            runtime_bundle.stage_source(release, self.fixture.source, SOURCE_SHA)


class JournalRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="clixor-journal-", dir=TEMP_ROOT
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        (self.root / "runtime").mkdir(mode=0o700)
        (self.root / "releases" / "pending").mkdir(parents=True, mode=0o700)
        self.old = self.root / "releases" / "oci-aaaaaaaaaaaa-old"
        self.old.mkdir(mode=0o700)
        self.current = self.root / "releases" / "current"
        self.current.symlink_to(self.old)

    def _candidate(self) -> Path:
        candidate = self.root / "releases" / "pending" / "oci-0123456789ab-new"
        candidate.mkdir(mode=0o700)
        return candidate

    def _advance(self, target: str, *, select_new: bool = False) -> tuple[Path, Path]:
        candidate = self._candidate()
        final = self.root / "releases" / candidate.name
        previous_manifest = {
            "image": {"ref": "clixor-api:oci-aaaaaaaaaaaa-old", "id": IMAGE_ID}
        }
        with mock.patch.object(
            RECONCILER, "_validate_bundle", return_value=previous_manifest
        ):
            RECONCILER.create_journal(
                self.root,
                candidate,
                SOURCE_SHA,
                str(self.old),
                "clixor-api:oci-aaaaaaaaaaaa-old",
            )
        for phase in RECONCILER.PHASES[1:]:
            if phase == "release-published":
                os.replace(candidate, final)
            if phase == "pointer-committed" and select_new:
                replacement = self.root / "releases" / ".current.test"
                replacement.symlink_to(final)
                os.replace(replacement, self.current)
            RECONCILER.update_journal_phase(self.root, phase)
            if phase == target:
                break
        return candidate, final

    def test_every_pre_pointer_power_loss_recovers_only_old_current(self) -> None:
        phases = RECONCILER.PHASES[:-2]
        for phase in phases:
            with self.subTest(phase=phase):
                if (self.root / "runtime" / "deploy-transaction.json").exists():
                    self.fail("previous subtest left an active journal")
                candidate, final = self._advance(phase)
                selected: list[Path] = []

                def reconcile(project_root, runner, *, boot, stop_first=True):
                    del runner, boot, stop_first
                    current = RECONCILER._resolve_current(project_root)
                    assert current is not None
                    selected.append(current)
                    return current

                with mock.patch.object(RECONCILER, "reconcile_current", side_effect=reconcile):
                    self.assertEqual(RECONCILER.watchdog(self.root, FakeRunner()), "recovered")
                self.assertEqual(selected, [self.old])
                self.assertFalse(candidate.exists())
                self.assertFalse(final.exists())
                self.assertTrue(any((self.root / "releases" / "quarantine").iterdir()))
                for item in (self.root / "releases" / "quarantine").iterdir():
                    if item.is_dir():
                        for child in item.iterdir():
                            self.assertNotEqual(child.name, "database")
                # Keep quarantines, but use a fresh candidate name target.
                for path in (self.root / "runtime" / "deploy-transactions").iterdir():
                    path.unlink()

    def test_pointer_is_the_commit_record_after_sigkill(self) -> None:
        _, final = self._advance("pointer-committed", select_new=True)
        selected: list[Path] = []

        def reconcile(project_root, runner, *, boot, stop_first=True):
            del runner, boot, stop_first
            current = RECONCILER._resolve_current(project_root)
            assert current is not None
            selected.append(current)
            return current

        with mock.patch.object(RECONCILER, "reconcile_current", side_effect=reconcile):
            self.assertEqual(RECONCILER.watchdog(self.root, FakeRunner()), "recovered")
        self.assertEqual(selected, [final])
        self.assertTrue(final.is_dir())

    def test_first_deploy_abort_is_quarantined_and_retryable(self) -> None:
        self.current.unlink()
        candidate = self._candidate()
        RECONCILER.create_journal(self.root, candidate, SOURCE_SHA, "none", "none")
        runner = FakeRunner()
        with mock.patch.object(RECONCILER, "_stop_ingress_and_containers") as stop:
            self.assertEqual(
                RECONCILER.watchdog(self.root, runner), "recovered-no-current"
            )
            stop.assert_called_once()
        self.assertFalse(candidate.exists())
        retry = self._candidate()
        self.assertTrue(retry.is_dir())
        # A GitHub rerun can use the same release tag. Its transaction identity
        # must be distinct so a second interrupted attempt can also be archived
        # without colliding with the first audit record.
        RECONCILER.create_journal(self.root, retry, SOURCE_SHA, "none", "none")
        with mock.patch.object(RECONCILER, "_stop_ingress_and_containers"):
            self.assertEqual(
                RECONCILER.watchdog(self.root, runner), "recovered-no-current"
            )
        self.assertEqual(
            len(list((self.root / "runtime" / "deploy-transactions").iterdir())),
            2,
        )

    def test_journal_rejects_previous_state_not_selected_by_current(self) -> None:
        candidate = self._candidate()
        with self.assertRaisesRegex(
            RECONCILER.ReconcileError, "previous release is not current"
        ):
            RECONCILER.create_journal(
                self.root,
                candidate,
                SOURCE_SHA,
                str(self.root / "releases" / "oci-bbbbbbbbbbbb-other"),
                "clixor-api:oci-bbbbbbbbbbbb-other",
            )

    def test_pre_journal_leftover_is_quarantined_without_delete(self) -> None:
        candidate = self._candidate()
        sentinel = candidate / "audit-sentinel"
        sentinel.write_text("keep\n", encoding="ascii")
        destination = RECONCILER.quarantine_pending_candidate(self.root, candidate)
        assert destination is not None
        self.assertFalse(candidate.exists())
        self.assertEqual((destination / "audit-sentinel").read_text(), "keep\n")

    def test_watchdog_skips_held_deploy_lock(self) -> None:
        lock = self.root / "runtime" / "deploy.lock"
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT, 0o600)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual(RECONCILER.watchdog(self.root, FakeRunner()), "deploy-active")

    def test_corrupt_journal_fails_closed_and_is_retained(self) -> None:
        journal = self.root / "runtime" / "deploy-transaction.json"
        journal.write_text("{not-json\n", encoding="ascii")
        journal.chmod(0o600)
        with mock.patch.object(RECONCILER, "_stop_ingress_and_containers") as stop:
            with self.assertRaises(RECONCILER.ReconcileError):
                RECONCILER.watchdog(self.root, FakeRunner())
            stop.assert_called_once()
        self.assertTrue(journal.is_file())

    def test_recovery_is_idempotent_after_journal_archive(self) -> None:
        self._advance("runtime-mutated")
        with mock.patch.object(
            RECONCILER, "reconcile_current", return_value=self.old
        ):
            self.assertEqual(RECONCILER.watchdog(self.root, FakeRunner()), "recovered")
        with mock.patch.object(RECONCILER, "_runtime_matches_current", return_value=True):
            self.assertEqual(RECONCILER.watchdog(self.root, FakeRunner()), "healthy")

    def test_power_loss_between_quarantine_and_journal_archive_recovers(self) -> None:
        candidate, _ = self._advance("runtime-mutated")
        document = RECONCILER.load_journal(self.root, require_candidate=True)
        quarantine = RECONCILER._quarantine_journal_artifact(
            self.root, document, "recovered"
        )
        assert quarantine is not None
        self.assertFalse(candidate.exists())
        self.assertTrue(quarantine.is_dir())
        # Simulate power loss after the candidate rename was made durable but
        # before the journal itself was archived. Recovery must accept the
        # already-quarantined artifact, select only current, and finish once.
        with mock.patch.object(
            RECONCILER, "reconcile_current", return_value=self.old
        ):
            self.assertEqual(RECONCILER.watchdog(self.root, FakeRunner()), "recovered")
        self.assertFalse(
            (self.root / "runtime" / "deploy-transaction.json").exists()
        )
        self.assertEqual(
            len(list((self.root / "runtime" / "deploy-transactions").iterdir())),
            1,
        )


class PublicationTests(unittest.TestCase):
    def test_publication_moves_bundle_and_marker_before_pointer(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="clixor-publish-", dir=TEMP_ROOT
        ) as temporary:
            fixture = RuntimeFixture(Path(temporary))
            candidate = fixture.finalized_release()
            RECONCILER.create_journal(fixture.root, candidate, SOURCE_SHA, "none", "none")
            for phase in RECONCILER.PHASES[1:]:
                RECONCILER.update_journal_phase(fixture.root, phase)
                if phase == "publishing":
                    break
            marker = fixture.root / "ready"
            marker.write_text(str(candidate) + "\n", encoding="ascii")
            with mock.patch.object(RECONCILER, "READY_MARKER", marker), mock.patch.object(
                RECONCILER, "_boot_bundle_validate"
            ):
                final = RECONCILER.publish_pending_release(
                    fixture.root, candidate, FakeRunner()
                )
            self.assertEqual(final, fixture.releases / candidate.name)
            self.assertFalse(candidate.exists())
            self.assertEqual(marker.read_text(encoding="ascii"), str(final) + "\n")
            self.assertFalse((fixture.releases / "current").exists())


class HostToolSelectionTests(unittest.TestCase):
    def test_reconciler_restores_release_local_cloudflared_and_host_tools(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="clixor-host-tools-", dir=TEMP_ROOT
        ) as temporary:
            fixture = RuntimeFixture(Path(temporary))
            release = fixture.finalized_release()
            installed: list[tuple[Path, Path, int, int, int]] = []

            def capture(source, target, uid, gid, mode):
                installed.append((source, target, uid, gid, mode))

            runner = FakeRunner()
            host_root = fixture.root / "installed-host-tools"
            systemd_root = fixture.root / "installed-systemd"
            cloudflared_target = fixture.root / "installed-cloudflared"
            with mock.patch.object(
                RECONCILER, "_atomic_install", side_effect=capture
            ), mock.patch.object(
                RECONCILER, "HOST_TOOL_ROOT", host_root
            ), mock.patch.object(
                RECONCILER, "SYSTEMD_ROOT", systemd_root
            ), mock.patch.object(
                RECONCILER, "CLOUDFLARED_BINARY", cloudflared_target
            ):
                RECONCILER._restore_host_tools(release, runner)
            cloudflared = release / "runtime-bundle" / "host-tools" / "bin" / "cloudflared"
            self.assertIn(
                (
                    cloudflared,
                    cloudflared_target,
                    0,
                    0,
                    0o555,
                ),
                installed,
            )
            self.assertIn(
                ("/usr/bin/systemctl", "daemon-reload"), runner.calls
            )


class LegacyBaselineTests(unittest.TestCase):
    def test_9e41_staging_transition_is_exact_idempotent_and_preserves_database(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="clixor-legacy-", dir=TEMP_ROOT
        ) as temporary:
            fixture = RuntimeFixture(Path(temporary))
            legacy = fixture.releases / "oci-0123456789ab-legacy"
            legacy.mkdir(mode=0o700)
            mode = legacy / "secret-mode"
            mode.write_text("staging\n", encoding="ascii")
            mode.chmod(0o400)
            current = fixture.releases / "current"
            current.symlink_to(legacy)
            shutil.copytree(fixture.source, fixture.root / "repo")
            database = fixture.root / "data" / "postgres" / "database-sentinel"
            database.parent.mkdir(parents=True)
            database.write_text("never restore or delete me\n", encoding="ascii")
            image_ref = f"clixor-api:{legacy.name}"
            outputs = {
                (
                    "/usr/bin/docker",
                    "inspect",
                    "clixor-oci-api-a",
                    "--format",
                    "{{.Config.Image}}",
                ): (0, (image_ref + "\n").encode()),
                (
                    "/usr/bin/docker",
                    "inspect",
                    "clixor-oci-api-b",
                    "--format",
                    "{{.Config.Image}}",
                ): (0, (image_ref + "\n").encode()),
                (
                    "/usr/bin/docker",
                    "image",
                    "inspect",
                    image_ref,
                    "--format",
                    "{{.Id}}",
                ): (0, (IMAGE_ID + "\n").encode()),
                (
                    "/usr/bin/docker",
                    "image",
                    "inspect",
                    image_ref,
                    "--format",
                    '{{index .Config.Labels "org.opencontainers.image.revision"}}',
                ): (0, (SOURCE_SHA + "\n").encode()),
            }
            runner = FakeRunner(outputs)
            selected = RECONCILER.establish_legacy_baseline(
                fixture.root, fixture.source, runner, fixture.cloudflared
            )
            self.assertEqual(selected, legacy)
            self.assertEqual(os.readlink(current), str(legacy))
            manifest = RECONCILER._validate_bundle(legacy, fixture.root)
            self.assertEqual(manifest["source_sha"], SOURCE_SHA)
            self.assertEqual(database.read_text(), "never restore or delete me\n")
            # An interrupted/retried explicit transition validates and returns
            # the same committed bundle instead of constructing a second state.
            self.assertEqual(
                RECONCILER.establish_legacy_baseline(
                    fixture.root, fixture.source, runner, fixture.cloudflared
                ),
                legacy,
            )

    def test_legacy_transition_fails_closed_on_live_image_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="clixor-legacy-bad-", dir=TEMP_ROOT
        ) as temporary:
            fixture = RuntimeFixture(Path(temporary))
            legacy = fixture.releases / "oci-0123456789ab-legacy"
            legacy.mkdir(mode=0o700)
            mode = legacy / "secret-mode"
            mode.write_text("staging\n", encoding="ascii")
            mode.chmod(0o400)
            (fixture.releases / "current").symlink_to(legacy)
            shutil.copytree(fixture.source, fixture.root / "repo")
            outputs = {
                (
                    "/usr/bin/docker",
                    "inspect",
                    "clixor-oci-api-a",
                    "--format",
                    "{{.Config.Image}}",
                ): (0, b"clixor-api:oci-deadbeefdead-wrong\n"),
                (
                    "/usr/bin/docker",
                    "inspect",
                    "clixor-oci-api-b",
                    "--format",
                    "{{.Config.Image}}",
                ): (0, b"clixor-api:oci-deadbeefdead-wrong\n"),
            }
            with self.assertRaisesRegex(RECONCILER.ReconcileError, "do not match"):
                RECONCILER.establish_legacy_baseline(
                    fixture.root,
                    fixture.source,
                    FakeRunner(outputs),
                    fixture.cloudflared,
                )
            self.assertFalse((legacy / "runtime-bundle").exists())


class BootSelectionContractTests(unittest.TestCase):
    def test_reconcile_removes_inactive_observability_container_metadata(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="clixor-observability-", dir=TEMP_ROOT
        ) as temporary:
            release = Path(temporary) / "oci-0123456789ab-runtime"
            compose = release / runtime_bundle.BUNDLE_DIRECTORY / "compose.yaml"
            compose.parent.mkdir(parents=True)
            compose.write_text(_compose(), encoding="ascii")
            runner = FakeRunner()
            manifest = {
                "state": {
                    "observability": {"prometheus": False, "grafana": False}
                }
            }
            RECONCILER._compose_up(
                release,
                manifest,
                f"clixor-api:{release.name}",
                runner,
            )
            self.assertIn(
                ("/usr/bin/docker", "rm", "clixor-oci-prometheus"), runner.calls
            )
            self.assertIn(
                ("/usr/bin/docker", "rm", "clixor-oci-grafana"), runner.calls
            )

    def test_reconcile_uses_only_current_never_pending_candidate(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="clixor-selection-", dir=TEMP_ROOT
        ) as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            releases = root / "releases"
            pending_root = releases / "pending"
            pending_root.mkdir(parents=True, mode=0o700)
            old = releases / "oci-aaaaaaaaaaaa-old"
            old.mkdir(mode=0o700)
            candidate = pending_root / "oci-bbbbbbbbbbbb-new"
            candidate.mkdir(mode=0o700)
            current = releases / "current"
            current.symlink_to(old)
            manifest = {
                "source_sha": "a" * 40,
                "state": {
                    "cloudflared": {"enabled": False, "active": False},
                    "observability": {"prometheus": False, "grafana": False},
                    "timers": {
                        "clixor-offsite-backup.timer": False,
                        "clixor-restore-drill.timer": False,
                        "clixor-backup-health.timer": False,
                    },
                },
            }
            restored: list[Path] = []

            def restore_source(release, project_root, runner):
                del project_root, runner
                restored.append(release)

            patches = (
                mock.patch.object(RECONCILER, "_stop_ingress_and_containers"),
                mock.patch.object(RECONCILER, "_validate_bundle", return_value=manifest),
                mock.patch.object(RECONCILER, "_boot_bundle_validate"),
                mock.patch.object(
                    RECONCILER,
                    "_validate_image",
                    return_value=(f"clixor-api:{old.name}", IMAGE_ID),
                ),
                mock.patch.object(RECONCILER, "_restore_source", side_effect=restore_source),
                mock.patch.object(RECONCILER, "_restore_runtime"),
                mock.patch.object(RECONCILER, "_restore_host_tools"),
                mock.patch.object(RECONCILER, "_set_service_selection"),
                mock.patch.object(RECONCILER, "_compose_up"),
                mock.patch.object(RECONCILER, "_wait_ready"),
                mock.patch.object(RECONCILER, "_publish_ready_marker"),
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8], patches[9], patches[10]:
                self.assertEqual(
                    RECONCILER.reconcile_current(root, FakeRunner(), boot=True), old
                )
            self.assertEqual(restored, [old])
            self.assertNotIn(candidate, restored)

    def test_static_boot_restart_and_transaction_contract(self) -> None:
        compose = (SCRIPT_ROOT / "compose.yaml").read_text(encoding="utf-8")
        deploy = (SCRIPT_ROOT / "deploy.sh").read_text(encoding="utf-8")
        bootstrap = (SCRIPT_ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        reconcile_unit = (SCRIPT_ROOT / "clixor-runtime-reconcile.service").read_text(
            encoding="utf-8"
        )
        cloud_unit = (SCRIPT_ROOT / "cloudflared.service").read_text(
            encoding="utf-8"
        )
        watchdog_unit = (SCRIPT_ROOT / "clixor-runtime-watchdog.service").read_text(
            encoding="utf-8"
        )
        self.assertEqual(compose.count('restart: "no"'), 11)
        self.assertNotIn("restart: unless-stopped", compose)
        self.assertNotIn("restart: always", compose)
        self.assertIn("After=clixor-runtime-secrets.service docker.service", reconcile_unit)
        self.assertIn("Before=cloudflared.service", reconcile_unit)
        self.assertIn("ConditionPathExists=/run/clixor/runtime-ready", cloud_unit)
        self.assertIn("runtime-reconciler.py watchdog", watchdog_unit)
        self.assertIn("flock -n 9", deploy)
        self.assertIn("journal-create", deploy)
        self.assertIn("stage-host-tools", deploy)
        self.assertIn("--name clixor-oci-migrate", deploy)
        self.assertIn('"clixor-oci-migrate"', RECONCILER_PATH.read_text())
        self.assertIn("publish-release", deploy)
        self.assertIn("quarantine-pending", deploy)
        self.assertIn("establish-legacy-baseline", bootstrap)
        ordered = [
            "journal_phase secrets-hydrating",
            "journal_phase secrets-hydrated",
            "journal_phase runtime-mutating",
            "journal_phase runtime-mutated",
            "journal_phase migrating",
            "journal_phase migrated",
            "journal_phase candidate-ready",
            "journal_phase publishing",
            "journal_phase release-published",
            "journal_phase pointer-committing",
            "journal_phase pointer-committed",
        ]
        positions = [deploy.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))


if __name__ == "__main__":
    unittest.main()
