from __future__ import annotations

import json
import hashlib
import re
import socket
import struct
import sys
import unittest
import urllib.error
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
        bootstrap = script.index('CLIXOR_SKIP_PACKAGES=true sh')
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
        self.assertEqual(script.count("CLIXOR_SKIP_PACKAGES=true sh"), 1)
        self.assertIn('printf \'first-deploy\\n\'', script)
        self.assertIn("database files and forward migrations were not restored", script)
        self.assertIn("pg_restore --list", script)
        self.assertIn("sha256sum --check", script)
        self.assertNotIn("pg_restore --clean", script)
        self.assertIn("scoped_runtime_ready", script)
        self.assertIn('cmp -s "${selected_rollback_compose}" "${compose_file}"', script)
        self.assertIn('if [ "${actual_image}" != "${previous_image}" ]', script)
        release_pointer = script.index('mv -Tf "${release_dir}/current-link.pending"')
        release_complete = script.rindex("rollback_needed=0")
        self.assertLess(release_pointer, release_complete)

    def test_cloudflared_requires_token_file_capable_release_and_fallback(self) -> None:
        installer = (self.oci_root / "install-cloudflared-service.sh").read_text(
            encoding="utf-8"
        )
        unit = (self.oci_root / "cloudflared.service").read_text(encoding="utf-8")
        local_config = (self.oci_root / "cloudflared-config.yml.example").read_text(
            encoding="utf-8"
        )
        self.assertIn("minimum_cloudflared_version=2025.4.0", installer)
        self.assertIn("dpkg --compare-versions", installer)
        self.assertIn("--protocol auto", unit)
        self.assertNotIn("--protocol quic", unit)
        self.assertIn("protocol: auto", local_config)
        self.assertNotIn("protocol: quic", local_config)
        self.assertIn("LoadCredential=cloudflare-token:/etc/cloudflared/token", unit)

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
        self.assertIn('[ "${#source_sha}" -eq 40 ]', wrapper)
        self.assertIn('[ "${actual_sha}" = "${source_sha}" ]', wrapper)
        self.assertIn("status --porcelain --untracked-files=all", wrapper)
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
        restart_backup = deploy.index("docker restart clixor-oci-postgres-backup")
        newer_proof = deploy.index('-newer "${backup_gate_start}"')
        offsite_gate = deploy.index("systemctl start clixor-offsite-backup.service")
        health_enable = deploy.index(
            "systemctl enable --now clixor-restore-drill.timer clixor-backup-health.timer"
        )
        release_complete = deploy.rindex("rollback_needed=0")
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
