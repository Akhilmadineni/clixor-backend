from __future__ import annotations

import json
import hashlib
import os
import re
import socket
import struct
import subprocess
import sys
import unittest
import urllib.error
import zipfile
from contextlib import redirect_stderr
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory


sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke  # noqa: E402
import backup_manifest  # noqa: E402


def server_frame(opcode: int, payload: bytes, *, final: bool = True) -> bytes:
    first = opcode | (0x80 if final else 0)
    if len(payload) < 126:
        return bytes((first, len(payload))) + payload
    if len(payload) <= 0xFFFF:
        return bytes((first, 126)) + struct.pack("!H", len(payload)) + payload
    return bytes((first, 127)) + struct.pack("!Q", len(payload)) + payload


class FailingOpener:
    def __init__(self, secret: str) -> None:
        self.secret = secret

    def open(self, request: object, timeout: float) -> object:
        del request, timeout
        raise urllib.error.URLError(f"upstream rejected {self.secret}")


class FakeAPI:
    def __init__(self) -> None:
        self.roles: list[str] = []
        self.current_role = ""
        self.attempts: dict[str, int] = {}

    def raw(self, method: str, path: str, **kwargs: object) -> smoke.HTTPResult:
        del kwargs
        if method != "DELETE" or path != "/v1/me":
            raise AssertionError("unexpected fake request")
        role = self.current_role
        self.roles.append(role)
        count = self.attempts.get(role, 0)
        self.attempts[role] = count + 1
        return smoke.HTTPResult(
            status=401 if count == 0 else 204,
            headers={},
            body=b"",
        )


class ValidationTests(unittest.TestCase):
    def test_https_origin_validation(self) -> None:
        self.assertEqual(
            smoke.validate_origin("https://API.Example.com/", "test"),
            "https://api.example.com",
        )
        for invalid in (
            "http://api.example.com",
            "https://user@api.example.com",
            "https://api.example.com:8443",
            "https://api.example.com/path",
            "https://api.example.com?secret=yes",
            "https://api.example.com/#fragment",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(smoke.SmokeFailure):
                smoke.validate_origin(invalid, "test")

    def test_par_url_is_pinned_to_expected_https_host(self) -> None:
        valid = "https://objectstorage.us-phoenix-1.oraclecloud.com/p/opaque/n/x"
        smoke.validate_par_url(
            valid, "objectstorage.us-phoenix-1.oraclecloud.com"
        )
        for invalid in (
            "http://objectstorage.us-phoenix-1.oraclecloud.com/p/opaque/n/x",
            "https://evil.example/p/opaque/n/x",
            "https://user@objectstorage.us-phoenix-1.oraclecloud.com/p/opaque/n/x",
            "https://objectstorage.us-phoenix-1.oraclecloud.com/not-a-par/x",
            "https://objectstorage.us-phoenix-1.oraclecloud.com/p/x?redirect=evil",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(smoke.SmokeFailure):
                smoke.validate_par_url(
                    invalid, "objectstorage.us-phoenix-1.oraclecloud.com"
                )

    def test_transport_error_redacts_par_url_and_secret(self) -> None:
        secret = "PAR-SECRET-MUST-NOT-LEAK"
        transport = smoke.HTTPTransport(opener=FailingOpener(secret))
        with self.assertRaises(smoke.SmokeFailure) as caught:
            smoke.download_par(
                transport,
                f"https://objectstorage.example/p/{secret}/n/namespace/b/bucket/o/object",
            )
        message = str(caught.exception)
        self.assertNotIn(secret, message)
        self.assertNotIn("objectstorage.example", message)

    def test_confirmation_is_mandatory(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            smoke.parse_args(
                [
                    "--base-url",
                    "https://api.example.com",
                    "--legal-base-url",
                    "https://legal.example.com",
                    "--expected-media-host",
                    "objectstorage.example.com",
                    "--confirm-disposable-writes",
                    "NO",
                ]
            )


class WebSocketTests(unittest.TestCase):
    def test_fragmented_json_and_ping_are_supported(self) -> None:
        client_socket, server_socket = socket.socketpair()
        self.addCleanup(client_socket.close)
        self.addCleanup(server_socket.close)
        client = smoke.WebSocketClient._from_connected_socket(client_socket)
        payload = json.dumps({"type": "session.ready", "payload": {"ok": True}}).encode()
        server_socket.sendall(
            server_frame(0x9, b"heartbeat")
            + server_frame(0x1, payload[:8], final=False)
            + server_frame(0x0, payload[8:], final=True)
        )
        self.assertEqual(client.receive_json(1.0)["type"], "session.ready")

        pong = server_socket.recv(128)
        self.assertEqual(pong[0] & 0x0F, 0xA)
        self.assertTrue(pong[1] & 0x80)
        length = pong[1] & 0x7F
        self.assertEqual(length, len(b"heartbeat"))
        mask = pong[2:6]
        masked_payload = pong[6 : 6 + length]
        unmasked = bytes(
            value ^ mask[index % 4] for index, value in enumerate(masked_payload)
        )
        self.assertEqual(unmasked, b"heartbeat")


class CleanupTests(unittest.TestCase):
    def test_cleanup_uses_all_sessions_and_preserves_account_order(self) -> None:
        suite = smoke.SmokeSuite(
            "https://api.example.com",
            "https://legal.example.com",
            "objectstorage.example.com",
        )
        fake = FakeAPI()
        suite.api = fake  # type: ignore[assignment]
        for role in ("owner", "member"):
            account = smoke.DisposableAccount(
                role=role,
                email=f"test-{role}@example.com",
                password="not-printed-password",
                sessions=[
                    smoke.Session("expired-access", "expired-refresh"),
                    smoke.Session("active-access", "active-refresh"),
                ],
            )
            suite.accounts.append(account)

        failures: list[str] = []
        for account in suite.accounts:
            fake.current_role = account.role
            failure = suite._delete_account(account)
            if failure:
                failures.append(failure)
        self.assertEqual(failures, [])
        self.assertEqual(fake.roles, ["owner", "owner", "member", "member"])
        self.assertTrue(all(account.deleted for account in suite.accounts))


class ReleaseHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.oci_root = Path(__file__).resolve().parent

    def test_snapshot_and_rollback_are_armed_before_runtime_mutation(self) -> None:
        script = (self.oci_root / "deploy.sh").read_text(encoding="utf-8")
        snapshot = script.index('log "capturing a pre-change PostgreSQL snapshot"')
        rollback_arm = script.index("\nrollback_needed=1\n")
        bootstrap = script.index(
            "CLIXOR_SKIP_PACKAGES=true CLIXOR_SKIP_SECRET_PREPARATION=true"
        )
        sync = script.index('log "syncing the approved revision')
        dependency_reconcile = script.index(
            'if [ "${legacy_dependency_scope}" = "true" ]'
        )
        migration = script.index('log "applying transactional forward migrations"')

        self.assertLess(snapshot, rollback_arm)
        self.assertLess(rollback_arm, bootstrap)
        self.assertLess(rollback_arm, sync)
        self.assertLess(rollback_arm, dependency_reconcile)
        self.assertLess(rollback_arm, migration)
        self.assertEqual(
            script.count(
                "CLIXOR_SKIP_PACKAGES=true CLIXOR_SKIP_SECRET_PREPARATION=true"
            ),
            1,
        )
        self.assertEqual(
            script.count("CLIXOR_DEFER_HOST_TOOL_ACTIVATION=true"), 1
        )
        self.assertIn('printf \'first-deploy\\n\'', script)
        self.assertIn("database migrations were not reversed", script)
        self.assertIn("pg_restore --list", script)
        self.assertIn("sha256sum --check", script)
        self.assertNotIn("pg_restore --clean", script)
        self.assertIn("scoped_runtime_ready", script)
        self.assertIn(
            '[ "${previous_compose_uses_scoped}" = "false" ] && scoped_runtime_ready',
            script,
        )
        self.assertIn('cmp -s "${selected_rollback_compose}" "${compose_file}"', script)
        self.assertIn('if [ "${actual_image}" != "${previous_image}" ]', script)
        self.assertNotIn('rm -f -- "${compose_file}"', script)
        self.assertIn('--file "${deployment_compose_file}" down --remove-orphans', script)
        self.assertIn('"${stable_runtime_controller}" reconcile', script)
        release_pointer = script.index("release_pointer_committed || fail")
        release_complete = script.rindex("\ndisarm_committed_release_rollback\n")
        self.assertLess(release_pointer, release_complete)

    def test_vault_rotation_rejects_single_node_credential_changes(self) -> None:
        deploy = (self.oci_root / "deploy.sh").read_text(encoding="utf-8")
        bootstrap = (self.oci_root / "bootstrap.sh").read_text(encoding="utf-8")
        exit_trap = deploy.index("trap rollback 0")
        hydrate = deploy.index(
            'hydration_status=0\n  /usr/bin/python3 "${source_root}/deploy/oci/hydrate-vault-secrets.py"'
        )
        bootstrap_call = deploy.index(
            "CLIXOR_SKIP_PACKAGES=true CLIXOR_SKIP_SECRET_PREPARATION=true"
        )
        self.assertLess(exit_trap, hydrate)
        self.assertLess(hydrate, bootstrap_call)
        self.assertIn('hydration_status=$?', deploy)
        self.assertIn(
            'current_vault_target="$(readlink -- "${runtime_secret_root}/active" 2>/dev/null || true)"',
            deploy,
        )
        self.assertIn("CLIXOR_SKIP_SECRET_PREPARATION", bootstrap)
        self.assertIn(
            "Vault-backed deployments require CLUSTER_ENV=production", deploy
        )
        self.assertIn(
            "Vault-backed deployments require the Telnyx verification provider",
            deploy,
        )
        self.assertIn(
            "Vault-backed deployments require durable SMTP password-reset delivery",
            deploy,
        )
        self.assertIn("vault_postgres_secret_activated=true", deploy)
        self.assertIn(
            "credential changes require an explicit single-node maintenance operation",
            deploy,
        )
        self.assertIn("reject_live_dependency_credential_change", deploy)
        self.assertIn("/run/secrets/redis.acl", deploy)
        self.assertIn("/run/secrets/nats.conf", deploy)
        self.assertIn('docker exec "${dependency_container}"', deploy)
        self.assertIn('sha256sum "${mounted_secret}"', deploy)
        redis_reject = deploy.index(
            "reject_live_dependency_credential_change \\\n  Redis"
        )
        nats_reject = deploy.index(
            "reject_live_dependency_credential_change \\\n  NATS"
        )
        image_build = deploy.index('log "building ARM64 release')
        self.assertLess(redis_reject, image_build)
        self.assertLess(nats_reject, image_build)
        self.assertIn("rollback secret consumers did not restart", deploy)

        release_pointer = deploy.index("release_pointer_committed || fail")
        rollback_disarm = deploy.rindex("\ndisarm_committed_release_rollback\n")
        self.assertLess(release_pointer, rollback_disarm)
        self.assertNotIn("retire_persistent_staging_secrets", deploy)
        self.assertNotIn("quarantine-staging-secrets.sh", deploy)

        quarantine = (
            self.oci_root / "quarantine-staging-secrets.sh"
        ).read_text(encoding="utf-8")
        self.assertIn('action=${1:-}', quarantine)
        self.assertIn('[ "${action}" = "quarantine" ]', quarantine)
        self.assertIn("pre_reboot_boot_id", quarantine)
        self.assertIn("pre-retirement-boot-id", quarantine)
        self.assertIn("approved_mapping_sha256", quarantine)
        self.assertIn("approved_cohort_sha256", quarantine)
        self.assertIn('[ "${approval_schema}" = "3" ]', quarantine)
        self.assertIn("retired_cloudflare_token_revoked_at", quarantine)
        self.assertIn('release_secret_mode="${current_release}/secret-mode"', quarantine)
        self.assertIn('approved_mapping="${current_release}/vault-secrets.map"', quarantine)
        self.assertIn(
            'approved_manifest="${current_release}/vault-approved-cohort.json"',
            quarantine,
        )
        self.assertIn("--verify-candidate-manifest", quarantine)
        self.assertIn('marker_value release_cohort', quarantine)
        self.assertIn('marker_value cohort_sha256', quarantine)
        self.assertNotIn("mapping_file=/etc/clixor/vault-secrets.map", quarantine)
        self.assertNotIn("secret_mode_file=/etc/clixor/secret-mode", quarantine)
        self.assertIn(
            'provider_canaries}" = "apns,cloudflare,oci-media,smtp,telnyx"',
            quarantine,
        )
        self.assertIn("RESTORE_DRILL_LAST_SUCCESS", quarantine)
        self.assertIn("staging-secret-maintenance.log", quarantine)
        self.assertIn("no quarantined data was deleted", quarantine)
        self.assertNotRegex(quarantine, r"(?m)^\s*rm(?:\s|$)")
        ci = (
            self.oci_root.parent.parent / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("quarantine-staging-secrets.sh", ci)

    def test_cloudflared_requires_token_file_release_and_unix_canary_route(self) -> None:
        installer = (self.oci_root / "install-cloudflared-service.sh").read_text(
            encoding="utf-8"
        )
        unit = (self.oci_root / "cloudflared.service").read_text(encoding="utf-8")
        local_config = (self.oci_root / "cloudflared-config.yml.example").read_text(
            encoding="utf-8"
        )
        self.assertIn("reviewed_cloudflared_version=2026.7.3", installer)
        self.assertIn(
            'cloudflared_version}" = "${reviewed_cloudflared_version}', installer
        )
        self.assertIn("--protocol auto", unit)
        self.assertNotIn("--protocol quic", unit)
        self.assertIn("service: unix:/run/clixor-origin/gateway.sock", local_config)
        self.assertNotIn("credentials-file:", local_config)
        self.assertNotIn("/etc/cloudflared/token", installer)
        self.assertIn(
            "LoadCredential=cloudflare-token:/run/clixor/secrets/active/cloudflare-token",
            unit,
        )

    def test_cloudflared_package_install_is_pinned_and_release_transactional(self) -> None:
        canonical = (
            self.oci_root / "terraform" / "install-cloudflared-package.sh"
        ).read_text(encoding="utf-8")
        wrapper = (self.oci_root / "install-cloudflared-package.sh").read_text(
            encoding="utf-8"
        )
        bootstrap = (self.oci_root / "bootstrap.sh").read_text(encoding="utf-8")
        deploy = (self.oci_root / "deploy.sh").read_text(encoding="utf-8")
        cloud_init = (
            self.oci_root / "terraform" / "cloud-init.yaml.tftpl"
        ).read_text(encoding="utf-8")
        compute = (self.oci_root / "terraform" / "compute.tf").read_text(
            encoding="utf-8"
        )
        package = (
            self.oci_root / "terraform" / "package-stack.sh"
        ).read_text(encoding="utf-8")

        self.assertIn("reviewed_cloudflared_version=2026.7.3", canonical)
        self.assertIn(
            "releases/download/2026.7.3/cloudflared-linux-arm64.deb", canonical
        )
        self.assertIn(
            "d3ea7d22dd337b465da33d6bc1c4b3cfd381407447a2a7d29542c19783430db3",
            canonical,
        )
        self.assertNotIn("releases/latest", canonical)
        self.assertNotIn("2026.8.0/cloudflared", canonical)
        verify = canonical.index("sha256sum --check --strict")
        inspect_package = canonical.index("dpkg-deb --field", verify)
        extract = canonical.index("dpkg-deb --extract", inspect_package)
        publish = canonical.index("publish_binary", extract)
        self.assertLess(verify, inspect_package)
        self.assertLess(inspect_package, extract)
        self.assertLess(extract, publish)
        self.assertNotIn("dpkg -i", canonical)
        self.assertIn('[ ! -L "${binary_path}" ]', canonical)
        self.assertIn("candidate path must be canonical", canonical)
        self.assertIn("target parent path must be canonical", canonical)
        self.assertIn("must not be group/world writable", canonical)
        self.assertIn("terraform/install-cloudflared-package.sh", wrapper)

        # Fresh bootstrap may install directly. An existing host never changes
        # the executable in this operator path; the release deploy owns it.
        fresh_guard = bootstrap.index(
            'if [ ! -e "${project_root}/releases/current" ]'
        )
        bootstrap_install = bootstrap.index(
            'sh "${script_root}/install-cloudflared-package.sh" install', fresh_guard
        )
        self.assertLess(fresh_guard, bootstrap_install)
        self.assertIn(
            "existing host deliberately does not\n# mutate /usr/bin/cloudflared here",
            bootstrap,
        )

        # Download/authentication is pre-mutation; publication occurs only after
        # the journal and rollback boundary. Both prior-present and prior-absent
        # states are captured and restored by the exit path.
        staged = deploy.index('stage "${cloudflared_candidate}"')
        capture = deploy.index("capture_cloudflared_state", staged)
        armed = deploy.index("rollback_needed=1", capture)
        publish_deploy = deploy.index(
            'install-from "${host_tool_stage}/bin/cloudflared"', armed
        )
        self.assertLess(staged, capture)
        self.assertLess(capture, armed)
        self.assertLess(armed, publish_deploy)
        self.assertIn("printf 'present\\n'", deploy)
        self.assertIn("printf 'absent\\n'", deploy)
        restore = deploy[deploy.index("restore_cloudflared() {"):
                         deploy.index("activate_host_tooling() {")]
        self.assertIn('case "${saved_binary}"', restore)
        self.assertIn("rm -f -- /usr/bin/cloudflared", restore)
        self.assertIn("cloudflared.sha256", restore)
        self.assertIn("/usr/bin/cloudflared.pending.${release_tag}", restore)
        self.assertIn('[ "${cloudflare_binary_changed}" = "true" ]', deploy)

        self.assertIn("cloudflared_package_installer", cloud_init)
        self.assertIn(
            "[sh, /usr/local/sbin/clixor-install-cloudflared-package, install]",
            cloud_init,
        )
        self.assertIn(
            'file("${path.module}/install-cloudflared-package.sh")', compute
        )
        self.assertIn("install-cloudflared-package.sh", package)

    def test_resource_manager_archive_contains_cloudflared_installer(self) -> None:
        package_script = self.oci_root / "terraform" / "package-stack.sh"
        with TemporaryDirectory() as directory:
            archive = Path(directory) / "stack.zip"
            subprocess.run(
                ["bash", str(package_script), str(archive)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            with zipfile.ZipFile(archive) as bundle:
                self.assertIn("install-cloudflared-package.sh", bundle.namelist())
                installer = bundle.read("install-cloudflared-package.sh")
                self.assertIn(b"reviewed_cloudflared_version=2026.7.3", installer)
                self.assertIn(
                    b"d3ea7d22dd337b465da33d6bc1c4b3cfd381407447a2a7d29542c19783430db3",
                    installer,
                )

    def test_cloudflared_unit_and_state_are_release_transactional(self) -> None:
        deploy = (self.oci_root / "deploy.sh").read_text(encoding="utf-8")
        self.assertIn("systemd-analyze verify", deploy)
        self.assertIn("sha256sum systemd/cloudflared.service", deploy)
        self.assertIn("capture_cloudflared_state", deploy)
        self.assertIn("cloudflared.service.sha256", deploy)
        self.assertIn("enabled-state", deploy)
        self.assertIn("active-state", deploy)
        self.assertIn("restore_cloudflared", deploy)
        self.assertIn("restored_checksum", deploy)
        self.assertIn("cloudflare_attempt", deploy)
        self.assertIn('[ "${cloudflare_attempt}" -lt 45 ]', deploy)
        self.assertIn("systemctl restart --no-block cloudflared.service", deploy)
        self.assertIn(
            "systemctl start --no-block cloudflared.service", deploy
        )
        self.assertIn(
            "starting the reviewed but currently inactive cloudflared service",
            deploy,
        )
        restart_guard = deploy.index(
            'if [ "${cloudflare_binary_changed}" = "true" ] ||'
        )
        restart = deploy.index(
            "systemctl restart --no-block cloudflared.service", restart_guard
        )
        self.assertLess(restart_guard, restart)
        inactive_start = deploy.index(
            "systemctl start --no-block cloudflared.service", restart
        )
        inactive_guard = deploy.index(
            "elif ! systemctl is-active --quiet cloudflared.service; then",
            restart,
        )
        self.assertLess(restart, inactive_start)
        self.assertLess(inactive_guard, inactive_start)
        self.assertLess(inactive_start, deploy.index("restore_cloudflared()"))
        self.assertIn("cloudflared=${cloudflare_rollback_failed}", deploy)
        self.assertIn("host-tools=${host_tool_rollback_failed}", deploy)

        rollback = deploy.index("rollback() {")
        restore_vault = deploy.index("if restore_previous_vault_target; then", rollback)
        restore_connector = deploy.index("if restore_cloudflared; then", rollback)
        restore_tools = deploy.index("if ! restore_host_tooling; then", rollback)
        restore_application = deploy.index(
            "deployment failed; attempting application rollback", rollback
        )
        self.assertLess(restore_vault, restore_connector)
        self.assertLess(restore_connector, restore_tools)
        self.assertLess(restore_tools, restore_application)

        rollback_arm = deploy.index("\nrollback_needed=1\n")
        activate = deploy.rindex("\n  activate_cloudflared\n")
        public_gate = deploy.index(
            'if [ "${public_smoke_required}" = "true" ]; then', activate
        )
        release_pointer = deploy.index("release_pointer_committed || fail")
        self.assertLess(rollback_arm, activate)
        self.assertLess(activate, public_gate)
        self.assertLess(public_gate, release_pointer)

    def test_committed_pointer_disarms_every_rollback_domain(self) -> None:
        deploy = (self.oci_root / "deploy.sh").read_text(encoding="utf-8")
        helper_start = deploy.index("disarm_committed_release_rollback() {")
        helper_end = deploy.index("\n}\n\nrelease_pointer_committed()", helper_start)
        helper = deploy[helper_start:helper_end]
        for assignment in (
            "rollback_needed=0",
            "vault_generation_changed=false",
            "cloudflare_state_activated=false",
            "host_tools_activated=false",
        ):
            self.assertIn(assignment, helper)

        rollback_start = deploy.index("rollback() {")
        committed_guard = deploy.index(
            'if [ "${status}" -ne 0 ] && release_pointer_committed; then',
            rollback_start,
        )
        rollback_disarm = deploy.index(
            "disarm_committed_release_rollback", committed_guard
        )
        first_restore = deploy.index("if restore_previous_vault_target; then", rollback_start)
        self.assertLess(committed_guard, rollback_disarm)
        self.assertLess(rollback_disarm, first_restore)

        pointer_observation = deploy.index("release_pointer_committed || fail")
        pointer_journal = deploy.index("journal_phase pointer-committed", pointer_observation)
        journal_archive = deploy.index("journal-archive", pointer_journal)
        success_disarm = deploy.index(
            "disarm_committed_release_rollback", journal_archive
        )
        self.assertLess(pointer_observation, pointer_journal)
        self.assertLess(pointer_journal, journal_archive)
        self.assertLess(journal_archive, success_disarm)

    def test_promotion_journal_interlocks_deploy_and_explicit_bootstrap(self) -> None:
        deploy = (self.oci_root / "deploy.sh").read_text(encoding="utf-8")
        bootstrap = (self.oci_root / "bootstrap.sh").read_text(encoding="utf-8")
        journal_path = "/var/lib/clixor/cloudflare-promotion.json"

        deploy_lock = deploy.index("flock -n 9")
        deploy_guard = deploy.index(
            "an active Cloudflare promotion journal must be resumed and archived",
            deploy_lock,
        )
        topology_read = deploy.index("topology-mode", deploy_guard)
        self.assertIn(journal_path, deploy)
        self.assertLess(deploy_lock, deploy_guard)
        self.assertLess(deploy_guard, topology_read)

        bootstrap_lock = bootstrap.index("flock -n 8")
        bootstrap_guard = bootstrap.index(
            "An active Cloudflare promotion journal must be resumed and archived",
            bootstrap_lock,
        )
        extension_install = bootstrap.index(
            "install-promotion-extension", bootstrap_guard
        )
        stable_promoter_install = bootstrap.index(
            "/usr/local/libexec/clixor/cloudflare-promote.py", extension_install
        )
        self.assertIn(journal_path, bootstrap)
        self.assertEqual(bootstrap.count("flock -n 8"), 1)
        self.assertLess(bootstrap_lock, bootstrap_guard)
        self.assertLess(bootstrap_guard, extension_install)
        self.assertLess(extension_install, stable_promoter_install)

        existing_preflight = bootstrap.index(
            "# A deployed host already has at least one of these durable authority objects."
        )
        early_acquire = bootstrap.index(
            "  acquire_bootstrap_interlock", existing_preflight
        )
        early_guard = bootstrap.index(
            "  reject_active_promotion_journal", early_acquire
        )
        for mutable_boundary in (
            bootstrap.index("apt-get update"),
            bootstrap.index("systemctl enable --now docker"),
            bootstrap.index('sh "${script_root}/install-oci-cli.sh"'),
            bootstrap.index("OCI_CLI_AUTH=instance_principal oci os ns get"),
        ):
            self.assertLess(early_acquire, mutable_boundary)
            self.assertLess(early_guard, mutable_boundary)
        definitive_comment = bootstrap.index(
            "# Keep this definitive check immediately before stable-authority setup"
        )
        definitive_guard = bootstrap.index(
            "  reject_active_promotion_journal", definitive_comment
        )
        self.assertLess(definitive_guard, extension_install)
        self.assertEqual(bootstrap.count("  reject_active_promotion_journal"), 2)

    def test_existing_host_bootstrap_preflight_aborts_before_side_effect(self) -> None:
        bootstrap = (self.oci_root / "bootstrap.sh").read_text(encoding="utf-8")
        helper_start = bootstrap.index("bootstrap_interlock_held=false")
        helper_end = bootstrap.index('\ncpu_count="', helper_start)
        helpers = bootstrap[helper_start:helper_end]
        harness = f"""set -eu
runtime_root=$1
shared_deploy_lock=$2
cloudflare_promotion_journal=$3
side_effect=$4
{helpers}
acquire_bootstrap_interlock
reject_active_promotion_journal
: > "${{side_effect}}"
"""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)
            lock = runtime / "deploy.lock"
            lock.write_bytes(b"")
            lock.chmod(0o600)
            journal = root / "cloudflare-promotion.json"
            journal.write_text("terminal journal remains active\n", encoding="utf-8")
            marker = root / "side-effect"
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_stat = fake_bin / "stat"
            fake_stat.write_text(
                "#!/bin/sh\nprintf '%s\\n' '0:0:600'\n", encoding="utf-8"
            )
            fake_stat.chmod(0o755)
            fake_flock = fake_bin / "flock"
            fake_flock.write_text(
                '#!/bin/sh\nexit "${FAKE_FLOCK_STATUS:-0}"\n', encoding="utf-8"
            )
            fake_flock.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"
            environment["FAKE_FLOCK_STATUS"] = "0"
            arguments = [
                "/bin/sh",
                "-c",
                harness,
                "bootstrap-interlock-test",
                str(runtime),
                str(lock),
                str(journal),
                str(marker),
            ]

            journal_block = subprocess.run(
                arguments,
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertNotEqual(journal_block.returncode, 0)
            self.assertIn("must be resumed and archived", journal_block.stderr)
            self.assertFalse(marker.exists())

            journal.unlink()
            environment["FAKE_FLOCK_STATUS"] = "1"
            lock_block = subprocess.run(
                arguments,
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertNotEqual(lock_block.returncode, 0)
            self.assertIn("deployment or promotion is active", lock_block.stderr)
            self.assertFalse(marker.exists())

    def test_boot_secret_tooling_is_release_local_and_bootstrap_is_deferred(self) -> None:
        deploy = (self.oci_root / "deploy.sh").read_text(encoding="utf-8")
        bootstrap = (self.oci_root / "bootstrap.sh").read_text(encoding="utf-8")
        worker = (self.oci_root / "prepare-runtime-secrets.sh").read_text(
            encoding="utf-8"
        )
        launcher = (
            self.oci_root / "prepare-runtime-secrets-launcher.py"
        ).read_text(encoding="utf-8")
        unit = (self.oci_root / "clixor-runtime-secrets.service").read_text(
            encoding="utf-8"
        )

        boot_stage = deploy.index("\nstage_release_boot_tooling\n")
        host_stage = deploy.index("\nstage_host_tooling\n")
        bootstrap_call = deploy.index("CLIXOR_DEFER_HOST_TOOL_ACTIVATION=true")
        commit_verify = deploy.index("--verify-release-bundle")
        pointer_commit = deploy.index('--commit-candidate-release "${candidate_manifest}"')
        self.assertLess(boot_stage, host_stage)
        self.assertLess(host_stage, bootstrap_call)
        self.assertLess(bootstrap_call, commit_verify)
        self.assertLess(commit_verify, pointer_commit)
        self.assertIn('boot_secret_stage="${release_dir}/boot-secrets"', deploy)
        self.assertIn("sha256sum --check SHA256SUMS", deploy)
        self.assertIn("--commit-staging-release", deploy)

        guarded_install = bootstrap.index(
            'if [ "${defer_host_tool_activation}" = "false" ]; then'
        )
        launcher_install = bootstrap.index(
            "/usr/local/libexec/clixor/prepare-runtime-secrets-launcher.py",
            guarded_install,
        )
        unit_install = bootstrap.index(
            "/etc/systemd/system/clixor-runtime-secrets.service",
            guarded_install,
        )
        self.assertLess(guarded_install, launcher_install)
        self.assertLess(guarded_install, unit_install)
        self.assertIn(
            "Initial stable-launcher transition requires a current staging release",
            bootstrap,
        )
        self.assertIn('stable_launcher_installed=false', bootstrap)
        self.assertNotIn(
            "/usr/local/libexec/clixor/hydrate-vault-secrets.py", bootstrap
        )
        self.assertNotIn(
            "/usr/local/libexec/clixor/prepare-runtime-secrets.sh", bootstrap
        )
        self.assertIn("--approved-release-manifest", worker)
        self.assertIn('hydrator="${boot_root}/hydrate-vault-secrets.py"', worker)
        self.assertNotIn("/etc/clixor/secret-mode", worker)
        self.assertIn("Candidate and orphan directories are never boot authority", launcher)
        self.assertIn("boot checksum manifest is incomplete", launcher)
        self.assertIn(
            "ExecStart=/usr/bin/python3 /usr/local/libexec/clixor/prepare-runtime-secrets-launcher.py",
            unit,
        )

    def test_gateway_logs_never_persist_invite_query_tokens(self) -> None:
        raw = (self.oci_root / "api-gateway-nginx.conf").read_text(encoding="utf-8")
        config = "\n".join(line.split("#", 1)[0] for line in raw.splitlines())
        self.assertIn('"path":"$uri"', config)
        self.assertIn("access_log /dev/stdout clixor_json;", config)
        self.assertIn("error_log /dev/stderr crit;", config)
        self.assertNotIn("$request_uri", config)
        self.assertNotRegex(config, r"\$request(?:\s|;|\")")

    def test_terraform_uses_the_deployed_image_ocid_not_latest_lookup(self) -> None:
        terraform_root = self.oci_root / "terraform"
        compute = (terraform_root / "compute.tf").read_text(encoding="utf-8")
        locals_file = (terraform_root / "locals.tf").read_text(encoding="utf-8")
        self.assertNotIn('data "oci_core_images"', compute)
        self.assertIn(
            "ocid1.image.oc1.phx.aaaaaaaa2xgl5y6skitgkee2aiprxzydi3nnxlqojrxtcifdb5d6a3djexuq",
            locals_file,
        )

    def test_actions_and_resource_manager_manifest_are_immutable_and_complete(self) -> None:
        repository_root = self.oci_root.parent.parent
        workflow_paths = sorted(
            list((repository_root / ".github" / "workflows").glob("*.yml"))
            + list((repository_root / ".github" / "workflows").glob("*.yaml"))
        )
        workflow_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in workflow_paths
        )
        uses = re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", workflow_text, re.MULTILINE)
        self.assertTrue(uses)
        for action in uses:
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")

        deploy_workflow = (
            repository_root / ".github" / "workflows" / "deploy-oci.yml"
        ).read_text(encoding="utf-8")
        wrapper = (self.oci_root / "actions-deploy.sh").read_text(encoding="utf-8")
        self.assertIn("github.event.workflow_run.head_sha", deploy_workflow)
        self.assertIn("github.event.workflow_run.event == 'push'", deploy_workflow)
        self.assertIn("github.event.workflow_run.head_branch == 'main'", deploy_workflow)
        self.assertIn("clixor-oci-production", deploy_workflow)
        self.assertIn("cancel-in-progress: false", deploy_workflow)
        self.assertIn("timeout-minutes: 90", deploy_workflow)
        self.assertIn("id-token: write", deploy_workflow)
        self.assertIn("ACTIONS_ID_TOKEN_REQUEST_URL", deploy_workflow)
        self.assertNotIn("actions/checkout@", deploy_workflow)
        self.assertIn('[ "${#source_sha}" -eq 40 ]', wrapper)
        self.assertIn("/usr/local/libexec/clixor/verify-github-deploy", wrapper)
        self.assertIn("https://github.com/Akhilmadineni/clixor-backend.git", wrapper)
        self.assertIn("refs/remotes/origin/main", wrapper)
        self.assertIn('[ "${trusted_main}" = "${source_sha}" ]', wrapper)
        self.assertIn("archive", wrapper)
        self.assertIn("approved_source", wrapper)
        self.assertIn('/usr/bin/env -i PATH="${PATH}" HOME="${HOME}"', wrapper)
        self.assertIn("trusted_env CLIXOR_REQUIRE_PUBLIC_SMOKE=true", wrapper)
        self.assertNotIn("GITHUB_WORKSPACE", wrapper)
        self.assertNotIn("canonical_source_root", wrapper)
        self.assertIn("CLUSTER_ENV=production", wrapper)
        self.assertIn("CLUSTER_VERIFICATION_PROVIDER=telnyx", wrapper)
        self.assertIn("CLUSTER_MAIL_PROVIDER=smtp", wrapper)

        dockerfile = (repository_root / "Dockerfile").read_text(encoding="utf-8")
        syntax = dockerfile.splitlines()[0]
        self.assertRegex(
            syntax,
            r"^# syntax=docker/dockerfile:[^@]+@sha256:[0-9a-f]{64}$",
        )

        compose = (self.oci_root / "compose.yaml").read_text(encoding="utf-8")
        dependency_images = re.findall(r"^\s+image:\s+([^\s]+)", compose, re.MULTILINE)
        self.assertTrue(dependency_images)
        for image in dependency_images:
            if image.startswith("clixor-api:"):
                continue
            with self.subTest(image=image):
                self.assertRegex(image, r"^[^@]+@sha256:[0-9a-f]{64}$")

        ci_workflow = (
            repository_root / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        ci_service_images = re.findall(
            r"^\s{8}image:\s+([^\s]+)", ci_workflow, re.MULTILINE
        )
        self.assertTrue(ci_service_images)
        for image in ci_service_images:
            with self.subTest(ci_image=image):
                self.assertRegex(image, r"^[^@]+@sha256:[0-9a-f]{64}$")

        terraform_root = self.oci_root / "terraform"
        package_script = (terraform_root / "package-stack.sh").read_text(
            encoding="utf-8"
        )
        required = {
            path.name for path in terraform_root.glob("*.tf")
        } | {
            ".terraform.lock.hcl",
            "schema.yaml",
            "cloud-init.yaml.tftpl",
            "clixor-mount-data.sh",
            "clixor-data-volume.service",
        }
        for filename in sorted(required):
            with self.subTest(filename=filename):
                self.assertIn(filename, package_script)
        self.assertNotIn("terraform.tfstate", package_script)

    def test_bootstrap_preserves_the_durable_backup_target(self) -> None:
        bootstrap = (self.oci_root / "bootstrap.sh").read_text(encoding="utf-8")
        self.assertIn("existing_backup_bucket", bootstrap)
        self.assertIn("existing_backup_prefix", bootstrap)
        self.assertIn(
            "CLIXOR_OCI_BACKUP_BUCKET conflicts with the durable backup configuration",
            bootstrap,
        )
        self.assertIn(
            "CLIXOR_OCI_BACKUP_PREFIX conflicts with the durable backup configuration",
            bootstrap,
        )
        self.assertIn('if [ ! -f "${backup_config}" ]; then', bootstrap)

    def test_email_delivery_foundation_excludes_credentials_and_private_keys(self) -> None:
        terraform_root = self.oci_root / "terraform"
        email = (terraform_root / "email.tf").read_text(encoding="utf-8")
        all_terraform = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(terraform_root.glob("*.tf"))
        )

        self.assertIn('mail_domain        = "mail.atlanteanz.com"', email)
        self.assertIn('mail_sender        = "no-reply@${local.mail_domain}"', email)
        self.assertIn('mail_smtp_endpoint = "smtp.email.${var.region}.oci.oraclecloud.com:465"', email)
        self.assertNotIn("oraclecloud.com:587", email)
        for resource_type in (
            "oci_email_email_domain",
            "oci_email_dkim",
            "oci_email_sender",
            "oci_identity_user",
            "oci_identity_user_capabilities_management",
            "oci_identity_group",
            "oci_identity_user_group_membership",
            "oci_identity_policy",
        ):
            with self.subTest(resource_type=resource_type):
                self.assertIn(f'resource "{resource_type}"', email)

        self.assertIn("count = var.create_mail_approved_sender ? 1 : 0", email)
        self.assertIn(
            'oci_email_dkim.transactional_mail.state == "ACTIVE"', email
        )
        self.assertIn("can_use_smtp_credentials     = true", email)
        for disabled_capability in (
            "can_use_api_keys             = false",
            "can_use_auth_tokens          = false",
            "can_use_console_password     = false",
            "can_use_customer_secret_keys = false",
        ):
            self.assertIn(disabled_capability, email)
        self.assertIn("to use approved-senders", email)
        self.assertIn(
            "where target.approved-sender.emailaddress = '${local.mail_sender}'",
            email,
        )
        self.assertNotIn("to use email-family", email)

        for forbidden_resource in (
            "oci_identity_smtp_credential",
            "oci_identity_domains_smtp_credential",
            "oci_identity_domains_my_smtp_credential",
        ):
            with self.subTest(forbidden_resource=forbidden_resource):
                self.assertNotIn(f'resource "{forbidden_resource}"', all_terraform)
        self.assertNotRegex(email, r"(?m)^\s*private_key\s*=")

        outputs = (terraform_root / "outputs.tf").read_text(encoding="utf-8")
        expected_mail_outputs = {
            "mail_dkim_cname_name",
            "mail_dkim_cname_value",
            "mail_spf_txt_name",
            "mail_spf_txt_value",
            "mail_smtp_endpoint",
            "mail_smtp_user_id",
        }
        actual_mail_outputs = set(
            re.findall(r'^output "(mail_[^"]+)"', outputs, re.MULTILINE)
        )
        self.assertEqual(actual_mail_outputs, expected_mail_outputs)

    def test_backup_units_are_installed_and_use_only_instance_principal(self) -> None:
        bootstrap = (self.oci_root / "bootstrap.sh").read_text(encoding="utf-8")
        offsite = (self.oci_root / "offsite-backup.sh").read_text(encoding="utf-8")
        service = (self.oci_root / "clixor-offsite-backup.service").read_text(
            encoding="utf-8"
        )
        backup_timer = (self.oci_root / "clixor-offsite-backup.timer").read_text(
            encoding="utf-8"
        )
        health_timer = (self.oci_root / "clixor-backup-health.timer").read_text(
            encoding="utf-8"
        )
        health = (self.oci_root / "backup-health.sh").read_text(encoding="utf-8")
        restore_service = (self.oci_root / "clixor-restore-drill.service").read_text(
            encoding="utf-8"
        )
        restore_timer = (self.oci_root / "clixor-restore-drill.timer").read_text(
            encoding="utf-8"
        )
        identity = (self.oci_root / "terraform" / "identity.tf").read_text(
            encoding="utf-8"
        )

        for installed_name in (
            "offsite-backup.sh",
            "backup-health.sh",
            "restore-drill.sh",
            "backup_manifest.py",
            "clixor-offsite-backup.service",
            "clixor-offsite-backup.timer",
            "clixor-backup-health.service",
            "clixor-backup-health.timer",
            "clixor-restore-drill.service",
            "clixor-restore-drill.timer",
        ):
            with self.subTest(installed_name=installed_name):
                self.assertIn(installed_name, bootstrap)
        self.assertIn("systemctl enable --now clixor-offsite-backup.timer", bootstrap)
        self.assertIn("OCI_CLI_AUTH=instance_principal", offsite)
        self.assertIn("--no-multipart", offsite)
        self.assertIn("--no-overwrite", offsite)
        self.assertIn("--verify-checksum", offsite)
        self.assertNotIn("--force", offsite)
        self.assertLess(
            offsite.index(
                'upload_immutable "${latest_dump}.sha256" "${object_prefix}.sha256"'
            ),
            offsite.index('upload_immutable "${latest_dump}" "${object_prefix}"'),
        )
        self.assertIn("User=root", service)
        self.assertIn("Environment=OCI_CLI_AUTH=instance_principal", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("CapabilityBoundingSet=", service)
        self.assertIn("OnUnitActiveSec=6h", backup_timer)
        self.assertIn("OnUnitActiveSec=1h", health_timer)
        self.assertIn("TimeoutStartSec=15m", service)
        self.assertIn("TimeoutStartSec=30m", restore_service)
        self.assertIn(
            "clixor-offsite-backup.service clixor-restore-drill.service", health
        )
        self.assertIn("OnCalendar=Sun *-*-* 04:30:00 UTC", restore_timer)
        self.assertIn("User=root", restore_service)
        self.assertIn("Environment=OCI_CLI_AUTH=instance_principal", restore_service)
        self.assertIn("ProtectSystem=strict", restore_service)
        self.assertIn("clixor-restore-drill.timer clixor-backup-health.timer", bootstrap)
        self.assertLess(
            bootstrap.index('if [ -s "${project_root}/backups/RESTORE_DRILL_LAST_SUCCESS" ]'),
            bootstrap.index("systemctl enable --now clixor-restore-drill.timer"),
        )
        self.assertIn("request.permission = 'OBJECT_READ'", identity)

        backup_policy = next(
            line for line in identity.splitlines() if "backups.name" in line and "OBJECT_CREATE" in line
        )
        self.assertNotIn("OBJECT_OVERWRITE", backup_policy)
        self.assertNotIn("OBJECT_DELETE", backup_policy)
        for forbidden_credential in (
            "OCI_CLI_KEY",
            "OCI_CLI_USER",
            "AWS_ACCESS_KEY",
            "AWS_SECRET_ACCESS_KEY",
        ):
            self.assertNotIn(forbidden_credential, service + offsite)

    def test_restore_drill_is_ephemeral_and_never_mounts_production_data(self) -> None:
        restore = (self.oci_root / "restore-drill.sh").read_text(encoding="utf-8")
        self.assertIn(
            "postgres_image=postgres:17.5-alpine@sha256:6567bca8d7bc8c82c5922425a0baee57be8402df92bae5eacad5f01ae9544daa",
            restore,
        )
        self.assertIn("--pull=never", restore)
        self.assertIn("--network none", restore)
        self.assertNotIn("--publish", restore)
        self.assertNotIn("/srv/clixor/data/postgres", restore)
        self.assertNotIn("/srv/clixor/secrets/runtime.env", restore)
        self.assertIn("trap cleanup EXIT", restore)
        self.assertIn("docker rm --force", restore)
        self.assertIn("rm -rf -- \"${work_dir}\"", restore)
        self.assertIn("pg_restore --username restore_admin", restore)
        self.assertIn("--no-owner --no-privileges --exit-on-error", restore)
        self.assertIn("pg_amcheck --username restore_admin", restore)
        self.assertIn("schema_migrations", restore)
        self.assertIn("RESTORE_DRILL_LAST_SUCCESS", restore)
        self.assertNotIn("docker exec -e PGPASSWORD", restore)
        self.assertNotIn("docker exec -i -e PGPASSWORD", restore)
        self.assertIn('PGPASSWORD="$POSTGRES_PASSWORD"', restore)

        deploy = (self.oci_root / "deploy.sh").read_text(encoding="utf-8")
        restore_gate = deploy.index("systemctl start clixor-restore-drill.service")
        fresh_gate = deploy.index(
            'backup_gate_start="${release_dir}/post-migration-backup-gate-start"'
        )
        restart_backup = deploy.index("--force-recreate postgres-backup")
        offsite_gate = deploy.index("systemctl start clixor-offsite-backup.service")
        activate_tools = deploy.rindex("\nactivate_host_tooling\n")
        newer_proof = deploy.index(
            '-newer "${backup_gate_start}"', restart_backup
        )
        health_enable = deploy.index(
            "systemctl enable --now \\\n  clixor-offsite-backup.timer"
        )
        release_complete = deploy.rindex("\ndisarm_committed_release_rollback\n")
        self.assertLess(activate_tools, fresh_gate)
        self.assertLess(fresh_gate, restart_backup)
        self.assertLess(restart_backup, newer_proof)
        self.assertLess(newer_proof, offsite_gate)
        self.assertLess(offsite_gate, restore_gate)
        self.assertLess(restore_gate, health_enable)
        self.assertLess(health_enable, release_complete)
        self.assertIn(
            'find "${project_root}/backups/OFFSITE_LAST_SUCCESS"', deploy
        )
        self.assertIn(
            'find "${project_root}/backups/RESTORE_DRILL_LAST_SUCCESS"', deploy
        )
        self.assertNotIn(
            'if [ ! -s "${project_root}/backups/RESTORE_DRILL_LAST_SUCCESS" ]',
            deploy,
        )

    def test_runtime_config_consumers_reload_and_public_smoke_is_transactional(self) -> None:
        deploy = (self.oci_root / "deploy.sh").read_text(encoding="utf-8")
        for service in ("dependency-tls", "postgres-backup"):
            with self.subTest(service=service):
                self.assertRegex(
                    deploy,
                    rf"--force-recreate\s+{re.escape(service)}",
                )
        self.assertIn("docker exec clixor-oci-api-gateway nginx -t", deploy)
        self.assertIn("docker exec clixor-oci-api-gateway nginx -s reload", deploy)
        self.assertIn("prometheus_was_running", deploy)
        self.assertIn("grafana_was_running", deploy)
        self.assertIn('previous_runtime_root="${release_dir}/previous-runtime"', deploy)
        capture = deploy.index("for runtime_config in")
        restore = deploy.index(
            '"${previous_runtime_root}/api-gateway/nginx.conf"'
        )
        rollback_reconcile = deploy.index(
            'log "ERROR: rollback configuration consumers did not restart"'
        )
        self.assertLess(capture, restore)
        self.assertLess(restore, rollback_reconcile)
        public_smoke = deploy.index('verify_public_ingress "${source_sha}"')
        activate_connector = deploy.rindex("\n  activate_cloudflared\n")
        activate_tools = deploy.index("\nactivate_host_tooling\n", public_smoke)
        offsite_gate = deploy.index(
            "systemctl start clixor-offsite-backup.service", activate_tools
        )
        restore_gate = deploy.index(
            "systemctl start clixor-restore-drill.service", offsite_gate
        )
        vault_commit = deploy.index(
            '--commit-candidate-release "${candidate_manifest}"', restore_gate
        )
        rollback_disarm = deploy.rindex("\ndisarm_committed_release_rollback\n")
        self.assertLess(activate_connector, public_smoke)
        self.assertLess(public_smoke, activate_tools)
        self.assertLess(activate_tools, offsite_gate)
        self.assertLess(offsite_gate, restore_gate)
        self.assertLess(restore_gate, vault_commit)
        self.assertLess(vault_commit, rollback_disarm)
        self.assertLess(public_smoke, rollback_disarm)
        self.assertIn('verify_public_ingress "${previous_revision}"', deploy)
        rollback_public_smoke = deploy.index(
            'if verify_public_ingress "${previous_revision}"'
        )
        rollback_public_guard = deploy.rfind(
            'if [ "${rollback_failed}" -eq 0 ]', 0, rollback_public_smoke
        )
        self.assertGreaterEqual(rollback_public_guard, 0)
        guard_text = deploy[rollback_public_guard:rollback_public_smoke]
        self.assertIn('previous_cloudflare_active', guard_text)
        self.assertIn('public_smoke_required', guard_text)
        self.assertNotIn('cloudflare_rollback_attempted', guard_text)
        self.assertIn('validate-public-smoke.py', deploy)
        self.assertIn('public readiness came from a different release', (
            self.oci_root / "validate-public-smoke.py"
        ).read_text(encoding="utf-8"))
        self.assertIn('clixor-oci-canary.atlanteanz.com/health/ready', deploy)
        self.assertIn('[ "${#source_sha}" -eq 40 ]', deploy)
        dockerfile = (self.oci_root.parent.parent / "Dockerfile").read_text(
            encoding="utf-8"
        )
        self.assertIn("ARG CLIXOR_REVISION=development", dockerfile)
        self.assertIn("internal/httpapi.buildRevision=${CLIXOR_REVISION}", dockerfile)

        workflow = (
            self.oci_root.parent.parent / ".github" / "workflows" / "deploy-oci.yml"
        ).read_text(encoding="utf-8")
        wrapper = (self.oci_root / "actions-deploy.sh").read_text(encoding="utf-8")
        self.assertIn("CLIXOR_REQUIRE_PUBLIC_SMOKE=true", wrapper)
        self.assertNotIn("Verify public OCI ingress", workflow)

    def test_host_backup_tooling_activation_is_release_transactional(self) -> None:
        deploy = (self.oci_root / "deploy.sh").read_text(encoding="utf-8")
        bootstrap = (self.oci_root / "bootstrap.sh").read_text(encoding="utf-8")

        self.assertIn("CLIXOR_DEFER_HOST_TOOL_ACTIVATION", bootstrap)
        self.assertIn(
            "CLIXOR_DEFER_HOST_TOOL_ACTIVATION=true", deploy
        )
        self.assertIn('host_tool_stage="${runtime_bundle_root}/host-tools"', deploy)
        self.assertIn(
            'previous_host_tool_root="${release_dir}/previous-host-tools"',
            deploy,
        )
        self.assertIn("sha256sum --check SHA256SUMS", deploy)
        self.assertIn('host_tools_activated=true', deploy)
        self.assertIn("restore_host_tooling", deploy)
        self.assertIn('systemctl is-enabled --quiet "${timer_name}"', deploy)
        self.assertIn('systemctl is-active --quiet "${timer_name}"', deploy)

        stage_call = deploy.index("\nstage_host_tooling\n")
        capture_call = deploy.index("\ncapture_host_tooling\n")
        bootstrap_call = deploy.index("CLIXOR_DEFER_HOST_TOOL_ACTIVATION=true")
        restore_gate = deploy.index("systemctl start clixor-restore-drill.service")
        activate_call = deploy.rindex("\nactivate_host_tooling\n")
        offsite_gate = deploy.index("systemctl start clixor-offsite-backup.service")
        freeze_timers = deploy.index("for host_gate_timer in")
        reject_old_job = deploy.index("for host_gate_service in")
        publish_tool = deploy.index(
            '"${host_tool_stage}/bin/${tool_name}"', freeze_timers
        )
        health_gate = deploy.index("systemctl start clixor-backup-health.service")
        release_pointer = deploy.index("release_pointer_committed || fail")
        self.assertLess(stage_call, capture_call)
        self.assertLess(capture_call, bootstrap_call)
        self.assertLess(freeze_timers, reject_old_job)
        self.assertLess(reject_old_job, publish_tool)
        self.assertLess(activate_call, offsite_gate)
        self.assertLess(activate_call, restore_gate)
        self.assertLess(activate_call, health_gate)
        self.assertLess(health_gate, release_pointer)

        rollback_start = deploy.index("rollback() {")
        rollback_restore = deploy.index(
            'if [ "${host_tools_activated}" = "true" ]; then', rollback_start
        )
        application_restore = deploy.index(
            "deployment failed; attempting application rollback", rollback_start
        )
        self.assertLess(rollback_restore, application_restore)

    def test_capacity_retention_and_rollback_boundaries_are_conservative(self) -> None:
        deploy = (self.oci_root / "deploy.sh").read_text(encoding="utf-8")
        retention = (self.oci_root / "release_retention.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("minimum_data_headroom_kb=8388608", deploy)
        self.assertIn("minimum_docker_headroom_kb=6291456", deploy)
        self.assertIn("postgres_size_kb * 3", deploy)
        self.assertIn('if [ "${data_device}" = "${docker_device}" ]; then', deploy)
        self.assertIn("data_required_kb + minimum_docker_headroom_kb", deploy)
        preflight_call = deploy.index("\npreflight_disk_capacity\n")
        release_create = deploy.index('mkdir "${release_dir}"')
        snapshot = deploy.index("capturing a pre-change PostgreSQL snapshot")
        image_build = deploy.index("building ARM64 release")
        self.assertLess(preflight_call, release_create)
        self.assertLess(preflight_call, snapshot)
        self.assertLess(preflight_call, image_build)

        self.assertIn("release_retention.py", deploy)
        self.assertIn("protected = {current}", retention)
        self.assertIn("protected.add(previous)", retention)
        self.assertIn("if candidate in protected", retention)
        self.assertIn("marker.stat().st_mtime_ns <= gate.stat().st_mtime_ns", retention)
        self.assertIn('"${image_ref}" = "${current_image}"', deploy)
        self.assertIn('"${image_ref}" = "${previous_boundary_image}"', deploy)
        self.assertNotIn("docker system prune", deploy)
        self.assertNotIn("docker image rm --force", deploy)
        offsite_proof = deploy.index(
            'find "${project_root}/backups/OFFSITE_LAST_SUCCESS"'
        )
        disarm = deploy.rindex("\ndisarm_committed_release_rollback\n")
        retention_call = deploy.rindex("\nif ! prune_release_history; then")
        self.assertLess(offsite_proof, disarm)
        self.assertLess(disarm, retention_call)

    def test_api_replicas_roll_sequentially_before_gateway_reload(self) -> None:
        deploy = (self.oci_root / "deploy.sh").read_text(encoding="utf-8")
        nginx = (self.oci_root / "api-gateway-nginx.conf").read_text(
            encoding="utf-8"
        )
        migration = deploy.index("applying transactional forward migrations")
        api_a = deploy.index("replacing api-a while api-b remains available")
        wait_a = deploy.index("wait_replica_ready api-a")
        api_b = deploy.index("replacing api-b only after api-a passed readiness")
        wait_b = deploy.index("wait_replica_ready api-b")
        gateway = deploy.index("reconciling the gateway after both API replicas are ready")
        validate = deploy.index("docker exec clixor-oci-api-gateway nginx -t")
        reload_gateway = deploy.index("docker exec clixor-oci-api-gateway nginx -s reload")
        self.assertLess(migration, api_a)
        self.assertLess(api_a, wait_a)
        self.assertLess(wait_a, api_b)
        self.assertLess(api_b, wait_b)
        self.assertLess(wait_b, gateway)
        self.assertLess(gateway, validate)
        self.assertLess(validate, reload_gateway)
        self.assertNotRegex(deploy, r"up -d --no-build\s+api-a api-b")
        self.assertIn("previous release is not ready after forward migration", deploy)
        self.assertIn("expand-compatible", deploy)
        self.assertIn("resolver 127.0.0.11", nginx)
        self.assertIn("server api-a:8080 resolve", nginx)
        self.assertIn("server api-b:8080 resolve", nginx)


class BackupManifestTests(unittest.TestCase):
    def test_selects_latest_complete_fresh_pair_and_ignores_incomplete_dump(self) -> None:
        prefix = "clixor"
        document = {
            "data": [
                {"name": f"{prefix}/postgres/clixor-20260830T100000Z.dump", "size": 10},
                {"name": f"{prefix}/postgres/clixor-20260830T100000Z.dump.sha256", "size": 90},
                {"name": f"{prefix}/postgres/clixor-20260830T120000Z.dump", "size": 20},
                {"name": f"{prefix}/postgres/clixor-20260830T120000Z.dump.sha256", "size": 90},
                {"name": f"{prefix}/postgres/clixor-20260830T130000Z.dump", "size": 30},
            ]
        }
        selected = backup_manifest.select_latest_complete_backup(
            document,
            prefix,
            480,
            now=datetime(2026, 8, 30, 13, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(
            selected.name, "clixor/postgres/clixor-20260830T120000Z.dump"
        )
        self.assertEqual(selected.size, 20)

    def test_rejects_stale_backup_and_invalid_prefix(self) -> None:
        document = {
            "data": [
                {"name": "clixor/postgres/clixor-20260829T120000Z.dump", "size": 20},
                {"name": "clixor/postgres/clixor-20260829T120000Z.dump.sha256", "size": 90},
            ]
        }
        with self.assertRaises(backup_manifest.BackupManifestError):
            backup_manifest.select_latest_complete_backup(
                document,
                "clixor",
                60,
                now=datetime(2026, 8, 30, 13, 0, tzinfo=timezone.utc),
            )
        with self.assertRaises(backup_manifest.BackupManifestError):
            backup_manifest.select_latest_complete_backup(
                document,
                "../escape",
                60,
                now=datetime(2026, 8, 30, 13, 0, tzinfo=timezone.utc),
            )

    def test_checksum_and_migration_contracts(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            dump = root / "clixor-20260830T120000Z.dump"
            dump.write_bytes(b"verified backup fixture")
            checksum = root / f"{dump.name}.sha256"
            checksum.write_text(
                f"{hashlib.sha256(dump.read_bytes()).hexdigest()}  {dump.name}\n",
                encoding="ascii",
            )
            backup_manifest.verify_checksum(dump, checksum)
            dump.write_bytes(b"corrupted backup fixture")
            with self.assertRaises(backup_manifest.BackupManifestError):
                backup_manifest.verify_checksum(dump, checksum)

            migrations = root / "migrations"
            migrations.mkdir()
            (migrations / "000001_initial.sql").write_text("SELECT 1;", encoding="utf-8")
            (migrations / "000002_next.sql").write_text("SELECT 2;", encoding="utf-8")
            self.assertEqual(
                backup_manifest.required_migration_versions(migrations), [1, 2]
            )


if __name__ == "__main__":
    unittest.main()
