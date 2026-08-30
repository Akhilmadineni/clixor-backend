from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import quote


SCRIPT_ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "clixor_vault_hydrator", SCRIPT_ROOT / "hydrate-vault-secrets.py"
)
assert SPEC is not None and SPEC.loader is not None
HYDRATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HYDRATOR)


class VaultHydrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="clixor-vault-test-", dir="/private/tmp" if Path("/private/tmp").is_dir() else None
        )
        self.root = Path(self.temporary.name)
        self.config_root = self.root / "config"
        self.secret_root = self.root / "secrets"
        self.fixture_root = self.root / "fixtures"
        self.config_root.mkdir(mode=0o700)
        self.secret_root.mkdir(mode=0o700)
        self.fixture_root.mkdir(mode=0o700)
        self.mapping_path = self.config_root / "vault-secrets.map"
        self.fake_oci = self.root / "oci"
        self.fake_openssl = self.root / "openssl"
        self.oci_log = self.root / "oci.argv"
        self.fail_ocid = self.root / "fail.ocid"
        self.uid = self.config_root.stat().st_uid
        self.gid = self.config_root.stat().st_gid

        self.ocids = {
            name: f"ocid1.vaultsecret.oc1.us-phoenix-1.test{name}0123456789"
            for name in sorted(HYDRATOR.REQUIRED_MAPPING_NAMES)
        }
        self._write_mapping(self.ocids)
        self._write_fake_oci()
        self._write_fake_openssl()
        self.apns_key = self._new_apns_key()
        self.bundles = self._valid_bundles()
        self._write_bundles(self.bundles)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_mapping(self, mapping: dict[str, str]) -> None:
        content = "# OCIDs are identifiers, never values.\n" + "".join(
            f"{name}={ocid}\n" for name, ocid in sorted(mapping.items())
        )
        self.mapping_path.write_text(content, encoding="ascii")
        self.mapping_path.chmod(0o600)

    def _write_fake_oci(self) -> None:
        script = f"""#!/bin/sh
set -eu
[ "${{OCI_CLI_AUTH:-}}" = instance_principal ] || exit 71
[ "$1" = --auth ] && [ "$2" = instance_principal ] || exit 72
[ "$3" = secrets ] && [ "$4" = secret-bundle ] && [ "$5" = get ] || exit 73
shift 5
secret_id=
stage=
query=
raw=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --secret-id) secret_id=$2; shift 2 ;;
    --stage) stage=$2; shift 2 ;;
    --query) query=$2; shift 2 ;;
    --raw-output) raw=true; shift ;;
    *) exit 74 ;;
  esac
done
[ "$stage" = CURRENT ] || exit 75
[ "$query" = 'data."secret-bundle-content".content' ] || exit 76
[ "$raw" = true ] || exit 77
printf '%s\n' "$secret_id" >> {self.oci_log!s}
if [ -s {self.fail_ocid!s} ] && [ "$secret_id" = "$(sed -n '1p' {self.fail_ocid!s})" ]; then
  exit 78
fi
[ -f "{self.fixture_root!s}/$secret_id" ] || exit 79
cat "{self.fixture_root!s}/$secret_id"
"""
        self.fake_oci.write_text(script, encoding="utf-8")
        self.fake_oci.chmod(0o700)

    def _write_fake_openssl(self) -> None:
        self.fake_openssl.write_text(
            """#!/bin/sh
set -eu
[ "$1" = pkey ] && [ "$2" = -in ] && [ "$4" = -check ] && [ "$5" = -noout ] || exit 81
exec /usr/bin/openssl pkey -in "$3" -noout
""",
            encoding="ascii",
        )
        self.fake_openssl.chmod(0o700)

    def _new_apns_key(self) -> bytes:
        key_path = self.root / "test-apns.p8"
        subprocess.run(
            [
                "/usr/bin/openssl",
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                str(key_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return key_path.read_bytes()

    def _valid_bundles(self) -> dict[str, bytes]:
        postgres_password = "postgres-secret-0123456789abcdef"
        redis_password = "redis-secret-0123456789abcdefghij"
        nats_token = "nats-token-0123456789abcdefghijkl"
        database_url = (
            "postgres://clixor:"
            + quote(postgres_password, safe="")
            + "@postgres.clixor.internal:5432/clixor?sslmode=verify-full&sslrootcert=/run/pki/ca.crt"
        )
        redis_url = (
            "rediss://:" + quote(redis_password, safe="") + "@clixor-tls:6379/0"
        )
        nats_url = "tls://" + quote(nats_token, safe="") + "@nats.clixor.internal:4222"
        queue_key = base64.b64encode(b"q" * 32).decode("ascii")
        api_lines = {
            "CLUSTER_ENV": "production",
            "CLUSTER_HTTP_ADDR": ":8080",
            "CLUSTER_PUBLIC_BASE_URL": "https://clustr-api.atlanteanz.com",
            "CLUSTER_TLS_CA_FILE": "/run/pki/ca.crt",
            "CLUSTER_STORE": "postgres",
            "CLUSTER_AUTO_MIGRATE": "false",
            "CLUSTER_DATABASE_URL": database_url,
            "CLUSTER_DATABASE_MAX_CONNS": "12",
            "CLUSTER_DATABASE_MIN_CONNS": "2",
            "CLUSTER_REDIS_URL": redis_url,
            "CLUSTER_NATS_URL": nats_url,
            "CLUSTER_JWT_ACCESS_SECRET": "jwt-secret-0123456789abcdefghijklmnopqrstuvwxyz",
            "CLUSTER_METRICS_TOKEN": "metrics-secret-0123456789abcdefghijklmnopqrst",
            "CLUSTER_APPLE_CLIENT_ID": "com.Clustr.Clustr.Clustr",
            "CLUSTER_MEDIA_PROVIDER": "oci",
            "CLUSTER_OCI_OBJECT_STORAGE_NAMESPACE": "testnamespace",
            "CLUSTER_OCI_OBJECT_STORAGE_BUCKET": "clixor-prod-media",
            "CLUSTER_OCI_OBJECT_STORAGE_REGION": "us-phoenix-1",
            "CLUSTER_VERIFICATION_PROVIDER": "telnyx",
            "CLUSTER_OTP_HMAC_SECRET": "otp-secret-0123456789abcdefghijklmnopqrstuvw",
            "CLUSTER_TELNYX_API_KEY": "telnyx-key-0123456789abcdefghijklmnopqrstuv",
            "CLUSTER_TELNYX_FROM_NUMBER": "+13125550100",
            "CLUSTER_TELNYX_MESSAGING_PROFILE_ID": "profile-0123456789",
            "CLUSTER_TELNYX_PUBLIC_KEY": "dGVzdC1wdWJsaWMta2V5",
            "CLUSTER_MAIL_PROVIDER": "smtp",
            "CLUSTER_SMTP_TRANSPORT": "implicit_tls",
            "CLUSTER_SMTP_ADDRESS": "smtp.email.us-phoenix-1.oci.oraclecloud.com:465",
            "CLUSTER_SMTP_USERNAME": "smtp-user-0123456789",
            "CLUSTER_SMTP_PASSWORD": "smtp-password-0123456789abcdefghijklmnop",
            "CLUSTER_SMTP_SERVER_NAME": "smtp.email.us-phoenix-1.oci.oraclecloud.com",
            "CLUSTER_MAIL_FROM": "Clixor <no-reply@mail.atlanteanz.com>",
            "CLUSTER_PASSWORD_RESET_HMAC_SECRET": "reset-secret-0123456789abcdefghijklmnopqrst",
            "CLUSTER_MAIL_QUEUE_ENCRYPTION_KEY": queue_key,
            "CLUSTER_APNS_TEAM_ID": "TESTTEAM01",
            "CLUSTER_APNS_KEY_ID": "TESTKEY001",
            "CLUSTER_APNS_BUNDLE_ID": "com.Clustr.Clustr.Clustr",
            "CLUSTER_APNS_PRIVATE_KEY_FILE": "/run/secrets/apns/AuthKey.p8",
            "CLUSTER_APNS_ENVIRONMENT": "production",
        }
        api = "".join(f"{key}={value}\n" for key, value in api_lines.items()).encode()
        return {
            "api_env": api,
            "postgres_env": (
                "POSTGRES_DB=clixor\n"
                "POSTGRES_USER=clixor\n"
                f"POSTGRES_PASSWORD={postgres_password}\n"
            ).encode(),
            "redis_env": f"REDIS_PASSWORD={redis_password}\n".encode(),
            "nats_env": f"NATS_AUTH_TOKEN={nats_token}\n".encode(),
            "grafana_env": (
                "GF_SECURITY_ADMIN_USER=clixoradmin\n"
                "GF_SECURITY_ADMIN_PASSWORD=grafana-secret-0123456789abcdefghij\n"
            ).encode(),
            "apns_production_p8": self.apns_key,
            "cloudflare_token": (
                b"eyJjbG91ZGZsYXJlIjoidGVzdC1vbmx5In0."
                b"eyJ0dW5uZWwiOiJ0ZXN0LW9ubHkifQ.signature0123456789"
            ),
        }

    def _write_bundles(self, bundles: dict[str, bytes]) -> None:
        for name, content in bundles.items():
            encoded = base64.b64encode(content) + b"\n"
            (self.fixture_root / self.ocids[name]).write_bytes(encoded)

    def _hydrate(self) -> tuple[bool, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            changed = HYDRATOR.hydrate(
                mapping_path=self.mapping_path,
                secret_root=self.secret_root,
                oci_binary=self.fake_oci,
                openssl_binary=self.fake_openssl,
                expected_uid=self.uid,
                expected_gid=self.gid,
                validate_binary=False,
                require_tmpfs=False,
                require_root=False,
            )
        return changed, output.getvalue()

    def _active(self) -> Path:
        return (self.secret_root / "active").resolve(strict=True)

    def _selected_snapshot(self) -> dict[str, bytes]:
        active = self._active()
        return {
            str(path.relative_to(active)): path.read_bytes()
            for path in active.rglob("*")
            if path.is_file()
        }

    def test_happy_path_derives_scoped_files_without_leaking(self) -> None:
        changed, output = self._hydrate()
        self.assertTrue(changed)
        self.assertEqual(output, "")
        active_link = self.secret_root / "active"
        self.assertTrue(active_link.is_symlink())
        self.assertRegex(os.readlink(active_link), r"^vault-generations/gen-[0-9]+-[a-f0-9]{16}$")
        active = self._active()
        self.assertEqual(
            (active / "backup.env").read_bytes(),
            b"POSTGRES_DB=clixor\nPOSTGRES_USER=clixor\n"
            b"POSTGRES_PASSWORD=postgres-secret-0123456789abcdef\n",
        )
        self.assertEqual(
            (active / "migrate.env").read_bytes(),
            b"CLUSTER_DATABASE_URL=postgres://clixor:postgres-secret-0123456789abcdef@"
            b"postgres.clixor.internal:5432/clixor?sslmode=verify-full&sslrootcert=/run/pki/ca.crt\n"
            b"CLUSTER_DATABASE_MAX_CONNS=12\nCLUSTER_DATABASE_MIN_CONNS=2\n"
            b"CLUSTER_TLS_CA_FILE=/run/pki/ca.crt\n",
        )
        expected_modes = {
            "api.env": 0o440,
            "postgres.env": 0o400,
            "redis.env": 0o400,
            "nats.env": 0o400,
            "grafana.env": 0o400,
            "backup.env": 0o400,
            "migrate.env": 0o440,
            "postgres.password": 0o440,
            "postgres.pgpass": 0o400,
            "redis.password": 0o440,
            "redis.acl": 0o440,
            "nats.conf": 0o440,
            "grafana.ini": 0o440,
            "metrics.token": 0o440,
            "cloudflare-token": 0o600,
            ".vault-hydrated": 0o400,
            "apns/AuthKey.p8": 0o440,
        }
        for relative, expected_mode in expected_modes.items():
            mode = stat.S_IMODE((active / relative).stat().st_mode)
            self.assertEqual(mode, expected_mode, relative)
        argv_log = self.oci_log.read_text()
        for secret in (
            "postgres-secret",
            "smtp-password",
            "metrics-secret",
            "eyJjbG91ZGZsYXJl",
        ):
            self.assertNotIn(secret, argv_log)
            self.assertNotIn(secret, output)
        self.assertEqual(len(argv_log.splitlines()), len(HYDRATOR.REQUIRED_MAPPING_NAMES))

    def test_idempotent_run_keeps_same_generation(self) -> None:
        self._hydrate()
        first_target = os.readlink(self.secret_root / "active")
        first_generations = sorted((self.secret_root / "vault-generations").iterdir())
        changed, output = self._hydrate()
        self.assertFalse(changed)
        self.assertEqual(output, "")
        self.assertEqual(os.readlink(self.secret_root / "active"), first_target)
        self.assertEqual(
            sorted((self.secret_root / "vault-generations").iterdir()), first_generations
        )

    def test_rotation_switches_whole_generation(self) -> None:
        self._hydrate()
        old_target = os.readlink(self.secret_root / "active")
        rotated = dict(self.bundles)
        rotated["api_env"] = rotated["api_env"].replace(
            b"smtp-password-0123456789abcdefghijklmnop",
            b"smtp-rotated-0123456789abcdefghijklmnop",
        )
        self._write_bundles(rotated)
        changed, output = self._hydrate()
        self.assertTrue(changed)
        self.assertEqual(output, "")
        self.assertNotEqual(os.readlink(self.secret_root / "active"), old_target)
        self.assertIn(b"smtp-rotated", (self._active() / "api.env").read_bytes())
        self.assertTrue((self.secret_root / old_target).is_dir())

    def test_stateful_secret_rotation_requires_explicit_procedure(self) -> None:
        self._hydrate()
        old_target = os.readlink(self.secret_root / "active")
        old_snapshot = self._selected_snapshot()
        cases = {
            "mail queue key": (
                "api_env",
                base64.b64encode(b"q" * 32),
                base64.b64encode(b"r" * 32),
            ),
            "otp hmac": (
                "api_env",
                b"otp-secret-0123456789abcdefghijklmnopqrstuvw",
                b"otp-rotated-0123456789abcdefghijklmnopqrstuv",
            ),
            "password reset hmac": (
                "api_env",
                b"reset-secret-0123456789abcdefghijklmnopqrst",
                b"reset-rotated-0123456789abcdefghijklmnopqrs",
            ),
            "grafana password": (
                "grafana_env",
                b"grafana-secret-0123456789abcdefghij",
                b"grafana-rotated-0123456789abcdefgh",
            ),
        }
        for name, (artifact, old_value, new_value) in cases.items():
            with self.subTest(name=name):
                self._write_bundles(self.bundles)
                rotated = dict(self.bundles)
                rotated[artifact] = rotated[artifact].replace(old_value, new_value)
                self._write_bundles(rotated)
                with self.assertRaises(HYDRATOR.HydrationError):
                    self._hydrate()
                self.assertEqual(os.readlink(self.secret_root / "active"), old_target)
                self.assertEqual(self._selected_snapshot(), old_snapshot)

    def test_postgres_password_rotation_requires_explicit_database_procedure(self) -> None:
        self._hydrate()
        old_target = os.readlink(self.secret_root / "active")
        old_snapshot = self._selected_snapshot()
        old_password = b"postgres-secret-0123456789abcdef"
        new_password = b"postgres-rotated-0123456789abcdef"
        rotated = dict(self.bundles)
        rotated["api_env"] = rotated["api_env"].replace(old_password, new_password)
        rotated["postgres_env"] = rotated["postgres_env"].replace(
            old_password, new_password
        )
        self._write_bundles(rotated)
        with self.assertRaisesRegex(
            HYDRATOR.HydrationError,
            "PostgreSQL credential rotation requires the explicit database rotation procedure",
        ):
            self._hydrate()
        self.assertEqual(os.readlink(self.secret_root / "active"), old_target)
        self.assertEqual(self._selected_snapshot(), old_snapshot)

    def test_partial_fetch_failure_preserves_selected_generation(self) -> None:
        self._hydrate()
        old_target = os.readlink(self.secret_root / "active")
        old_snapshot = self._selected_snapshot()
        self.fail_ocid.write_text(self.ocids["redis_env"] + "\n")
        output = io.StringIO()
        with self.assertRaises(HYDRATOR.HydrationError), contextlib.redirect_stderr(output):
            self._hydrate()
        self.assertEqual(os.readlink(self.secret_root / "active"), old_target)
        self.assertEqual(self._selected_snapshot(), old_snapshot)
        for secret in ("postgres-secret", "smtp-password", "metrics-secret"):
            self.assertNotIn(secret, output.getvalue())

    def test_malformed_bundle_preserves_selected_generation(self) -> None:
        self._hydrate()
        old_target = os.readlink(self.secret_root / "active")
        old_snapshot = self._selected_snapshot()
        (self.fixture_root / self.ocids["api_env"]).write_bytes(b"not canonical base64\n")
        with self.assertRaises(HYDRATOR.HydrationError):
            self._hydrate()
        self.assertEqual(os.readlink(self.secret_root / "active"), old_target)
        self.assertEqual(self._selected_snapshot(), old_snapshot)

    def test_disallowed_or_duplicate_env_key_is_rejected(self) -> None:
        for suffix in (b"AWS_SECRET_ACCESS_KEY=forbidden\n", b"CLUSTER_ENV=production\n"):
            with self.subTest(suffix=suffix):
                self._write_bundles(self.bundles)
                path = self.fixture_root / self.ocids["api_env"]
                path.write_bytes(base64.b64encode(self.bundles["api_env"] + suffix) + b"\n")
                with self.assertRaises(HYDRATOR.HydrationError):
                    self._hydrate()
                self.assertFalse((self.secret_root / "active").exists())

    def test_mapping_rejects_unknown_duplicate_and_symlink_before_fetch(self) -> None:
        cases = (
            b"unknown_env=ocid1.vaultsecret.oc1.us-phoenix-1.unknown0123456789\n",
            (
                f"api_env={self.ocids['api_env']}\n"
                f"api_env={self.ocids['postgres_env']}\n"
            ).encode(),
        )
        original = self.mapping_path.read_bytes()
        for addition in cases:
            with self.subTest(addition=addition):
                self.mapping_path.write_bytes(original + addition)
                self.mapping_path.chmod(0o600)
                with self.assertRaises(HYDRATOR.HydrationError):
                    self._hydrate()
                self.assertFalse(self.oci_log.exists())
        self.mapping_path.unlink()
        (self.config_root / "mapping-source").write_bytes(original)
        (self.config_root / "mapping-source").chmod(0o600)
        self.mapping_path.symlink_to(self.config_root / "mapping-source")
        with self.assertRaises(HYDRATOR.HydrationError):
            self._hydrate()
        self.assertFalse(self.oci_log.exists())

    def test_invalid_mapping_mode_is_rejected_before_fetch(self) -> None:
        self.mapping_path.chmod(0o640)
        with self.assertRaises(HYDRATOR.HydrationError):
            self._hydrate()
        self.assertFalse(self.oci_log.exists())

    def test_non_tmpfs_runtime_root_is_rejected_before_fetch(self) -> None:
        with self.assertRaises(HYDRATOR.HydrationError):
            HYDRATOR.hydrate(
                mapping_path=self.mapping_path,
                secret_root=self.secret_root,
                oci_binary=self.fake_oci,
                openssl_binary=self.fake_openssl,
                expected_uid=self.uid,
                expected_gid=self.gid,
                validate_binary=False,
                require_tmpfs=True,
                require_root=False,
            )
        self.assertFalse(self.oci_log.exists())

    def test_pointer_swap_failure_preserves_last_known_good(self) -> None:
        self._hydrate()
        old_target = os.readlink(self.secret_root / "active")
        old_snapshot = self._selected_snapshot()
        rotated = dict(self.bundles)
        rotated["api_env"] = rotated["api_env"].replace(
            b"smtp-password-0123456789abcdefghijklmnop",
            b"smtp-pointer-test-0123456789abcdefghijklm",
        )
        self._write_bundles(rotated)
        real_replace = os.replace

        def fail_pointer_swap(source: object, destination: object) -> None:
            if Path(destination) == self.secret_root / "active":
                raise OSError("injected pointer failure")
            real_replace(source, destination)

        with mock.patch.object(HYDRATOR.os, "replace", side_effect=fail_pointer_swap):
            with self.assertRaises(HYDRATOR.HydrationError):
                self._hydrate()
        self.assertEqual(os.readlink(self.secret_root / "active"), old_target)
        self.assertEqual(self._selected_snapshot(), old_snapshot)

    def test_post_swap_fsync_failure_restores_last_known_good(self) -> None:
        self._hydrate()
        old_target = os.readlink(self.secret_root / "active")
        old_snapshot = self._selected_snapshot()
        old_generations = sorted(
            path.name for path in (self.secret_root / "vault-generations").iterdir()
        )
        rotated = dict(self.bundles)
        rotated["api_env"] = rotated["api_env"].replace(
            b"smtp-password-0123456789abcdefghijklmnop",
            b"smtp-post-swap-0123456789abcdefghijklmn",
        )
        self._write_bundles(rotated)
        real_fsync_directory = HYDRATOR._fsync_directory
        injected = False

        def fail_once_after_pointer_swap(path: Path) -> None:
            nonlocal injected
            active_link = self.secret_root / "active"
            if (
                path == self.secret_root
                and active_link.is_symlink()
                and os.readlink(active_link) != old_target
                and not injected
            ):
                injected = True
                raise OSError("injected post-swap fsync failure")
            real_fsync_directory(path)

        with mock.patch.object(
            HYDRATOR, "_fsync_directory", side_effect=fail_once_after_pointer_swap
        ):
            with self.assertRaises(HYDRATOR.HydrationError):
                self._hydrate()
        self.assertTrue(injected)
        self.assertEqual(os.readlink(self.secret_root / "active"), old_target)
        self.assertEqual(self._selected_snapshot(), old_snapshot)
        self.assertEqual(
            sorted(
                path.name
                for path in (self.secret_root / "vault-generations").iterdir()
            ),
            old_generations,
        )

    def test_sandbox_key_requires_matching_api_configuration(self) -> None:
        sandbox_ocid = "ocid1.vaultsecret.oc1.us-phoenix-1.testsandbox0123456789"
        mapping = dict(self.ocids)
        mapping["apns_sandbox_p8"] = sandbox_ocid
        self.ocids["apns_sandbox_p8"] = sandbox_ocid
        self._write_mapping(mapping)
        bundles = dict(self.bundles)
        bundles["apns_sandbox_p8"] = self.apns_key
        self._write_bundles(bundles)
        with self.assertRaises(HYDRATOR.HydrationError):
            self._hydrate()
        self.assertFalse((self.secret_root / "active").exists())


if __name__ == "__main__":
    unittest.main()
