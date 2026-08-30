from __future__ import annotations

import json
import re
import socket
import struct
import sys
import unittest
import urllib.error
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import smoke  # noqa: E402


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
            'docker compose --file "${compose_file}" up -d --no-build \\\n  postgres redis nats dependency-tls'
        )
        migration = script.index('log "applying transactional forward migrations"')

        self.assertLess(snapshot, rollback_arm)
        self.assertLess(rollback_arm, bootstrap)
        self.assertLess(rollback_arm, sync)
        self.assertLess(rollback_arm, dependency_reconcile)
        self.assertLess(rollback_arm, migration)
        self.assertIn('printf \'first-deploy\\n\'', script)
        self.assertIn("database files and forward migrations were not restored", script)
        self.assertNotIn("pg_restore", script)

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
        self.assertIn('[ "${#source_sha}" -eq 40 ]', wrapper)
        self.assertIn('[ "${actual_sha}" = "${source_sha}" ]', wrapper)
        self.assertIn("status --porcelain --untracked-files=all", wrapper)

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


if __name__ == "__main__":
    unittest.main()
