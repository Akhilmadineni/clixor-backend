from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
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
        self.release_root = self.root / "releases"
        self.config_root.mkdir(mode=0o700)
        self.secret_root.mkdir(mode=0o700)
        self.fixture_root.mkdir(mode=0o700)
        self.release_root.mkdir(mode=0o700)
        self.mapping_path = self.config_root / "vault-secrets.map"
        self.fake_oci = self.root / "oci"
        self.fake_openssl = self.root / "openssl"
        self.oci_log = self.root / "oci.argv"
        self.fail_ocid = self.root / "fail.ocid"
        self.uid = self.config_root.stat().st_uid
        self.gid = self.config_root.stat().st_gid
        self.release_sequence = 0
        self.last_release: Path | None = None
        self.bundle_versions: dict[str, int] = {}
        self.bundle_content: dict[str, bytes] = {}

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
version_number=
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --secret-id) secret_id=$2; shift 2 ;;
    --stage) stage=$2; shift 2 ;;
    --version-number) version_number=$2; shift 2 ;;
    --output) output=$2; shift 2 ;;
    *) exit 74 ;;
  esac
done
[ "$output" = json ] || exit 75
if [ "$stage" = CURRENT ] && [ -z "$version_number" ]; then
  version_number="$(sed -n '1p' "{self.fixture_root!s}/$secret_id.current")"
elif [ -z "$stage" ] && [ -n "$version_number" ]; then
  :
else
  exit 76
fi
printf '%s %s %s\n' "$secret_id" "${{stage:---version-number}}" "$version_number" >> {self.oci_log!s}
if [ -s {self.fail_ocid!s} ] && [ "$secret_id" = "$(sed -n '1p' {self.fail_ocid!s})" ]; then
  exit 78
fi
[ -f "{self.fixture_root!s}/$secret_id.$version_number" ] || exit 79
content="$(cat "{self.fixture_root!s}/$secret_id.$version_number")"
printf '{{"data":{{"secret-id":"%s","version-number":%s,"secret-bundle-content":{{"content":"%s"}}}}}}\n' \
  "$secret_id" "$version_number" "$content"
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
            ocid = self.ocids[name]
            if self.bundle_content.get(ocid) != content:
                self.bundle_versions[ocid] = self.bundle_versions.get(ocid, 0) + 1
                self.bundle_content[ocid] = content
                version = self.bundle_versions[ocid]
                (self.fixture_root / f"{ocid}.{version}").write_bytes(
                    base64.b64encode(content)
                )
            (self.fixture_root / f"{ocid}.current").write_text(
                f"{self.bundle_versions[ocid]}\n", encoding="ascii"
            )

    def _new_release(self) -> Path:
        self.release_sequence += 1
        release = self.release_root / f"oci-0123456789ab-test{self.release_sequence}"
        release.mkdir(mode=0o700)
        mode_file = release / "secret-mode"
        mode_file.write_bytes(b"vault\n")
        mode_file.chmod(0o400)
        boot_root = release / HYDRATOR.BOOT_SECRET_DIRECTORY_NAME
        boot_root.mkdir(mode=0o700)
        checksums = []
        for name in sorted(HYDRATOR.BOOT_FILE_MODES):
            source = SCRIPT_ROOT / name
            destination = boot_root / name
            content = source.read_bytes()
            destination.write_bytes(content)
            destination.chmod(HYDRATOR.BOOT_FILE_MODES[name])
            checksums.append(
                f"{hashlib.sha256(content).hexdigest()}  {name}\n"
            )
        checksum_path = boot_root / HYDRATOR.BOOT_CHECKSUM_NAME
        checksum_path.write_text("".join(checksums), encoding="ascii")
        checksum_path.chmod(0o400)
        self.last_release = release
        return release

    def _hydrate(self) -> tuple[bool, str]:
        release = self._new_release()
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            changed = HYDRATOR.hydrate(
                mapping_path=self.mapping_path,
                candidate_manifest_path=(
                    release / HYDRATOR.APPROVED_MANIFEST_NAME
                ),
                release_cohort=release.name,
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

    def _approve(self, release: Path | None = None) -> Path:
        selected = release or self.last_release
        if selected is None:
            raise AssertionError("no candidate release")
        temporary = self.release_root / ".current.test"
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()
        temporary.symlink_to(selected)
        os.replace(temporary, self.release_root / "current")
        return selected

    def _boot(self) -> tuple[bool, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            changed = HYDRATOR.hydrate(
                approved_manifest_path=(
                    self.release_root
                    / "current"
                    / HYDRATOR.APPROVED_MANIFEST_NAME
                ),
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

    def _boot_release_local(self, release: Path) -> tuple[bool, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            changed = HYDRATOR.hydrate(
                approved_release_manifest_path=(
                    release / HYDRATOR.APPROVED_MANIFEST_NAME
                ),
                release_cohort=release.name,
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

    def _simulate_reboot(self) -> None:
        active = self.secret_root / "active"
        if active.exists() or active.is_symlink():
            active.unlink()
        generations = self.secret_root / HYDRATOR.GENERATION_ROOT_NAME
        if generations.exists():
            shutil.rmtree(generations)

    def _current_bundle_path(self, artifact: str) -> Path:
        ocid = self.ocids[artifact]
        return self.fixture_root / f"{ocid}.{self.bundle_versions[ocid]}"

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
            ".secret-integrity.json": 0o400,
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
        self._approve()
        first_target = os.readlink(self.secret_root / "active")
        first_generations = sorted((self.secret_root / "vault-generations").iterdir())
        changed, output = self._boot()
        self.assertFalse(changed)
        self.assertEqual(output, "")
        self.assertEqual(os.readlink(self.secret_root / "active"), first_target)
        self.assertEqual(
            sorted((self.secret_root / "vault-generations").iterdir()), first_generations
        )

    def test_deleted_materialized_secret_is_rejected_then_restored_from_pins(self) -> None:
        self._hydrate()
        approved = self._approve()
        (self._active() / "metrics.token").unlink()
        with self.assertRaisesRegex(HYDRATOR.HydrationError, "unavailable"):
            HYDRATOR.verify_candidate_selection(
                candidate_manifest_path=(
                    approved / HYDRATOR.APPROVED_MANIFEST_NAME
                ),
                release_cohort=approved.name,
                secret_root=self.secret_root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )
        self.oci_log.unlink(missing_ok=True)
        changed, output = self._boot_release_local(approved)
        self.assertTrue(changed)
        self.assertEqual(output, "")
        self.assertTrue((self._active() / "metrics.token").is_file())
        HYDRATOR.verify_candidate_selection(
            candidate_manifest_path=(
                approved / HYDRATOR.APPROVED_MANIFEST_NAME
            ),
            release_cohort=approved.name,
            secret_root=self.secret_root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        self.assertNotIn("CURRENT", self.oci_log.read_text())
        token = self._active() / "metrics.token"
        original = token.read_bytes()
        token.chmod(0o600)
        token.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        token.chmod(0o440)
        with self.assertRaisesRegex(HYDRATOR.HydrationError, "content changed"):
            HYDRATOR.verify_candidate_selection(
                candidate_manifest_path=(
                    approved / HYDRATOR.APPROVED_MANIFEST_NAME
                ),
                release_cohort=approved.name,
                secret_root=self.secret_root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )
        changed, output = self._boot_release_local(approved)
        self.assertTrue(changed)
        self.assertEqual(output, "")
        self.assertEqual((self._active() / "metrics.token").read_bytes(), original)

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
        self._current_bundle_path("api_env").write_bytes(b"not canonical base64\n")
        with self.assertRaises(HYDRATOR.HydrationError):
            self._hydrate()
        self.assertEqual(os.readlink(self.secret_root / "active"), old_target)
        self.assertEqual(self._selected_snapshot(), old_snapshot)

    def test_disallowed_or_duplicate_env_key_is_rejected(self) -> None:
        for suffix in (b"AWS_SECRET_ACCESS_KEY=forbidden\n", b"CLUSTER_ENV=production\n"):
            with self.subTest(suffix=suffix):
                self._write_bundles(self.bundles)
                path = self._current_bundle_path("api_env")
                path.write_bytes(base64.b64encode(self.bundles["api_env"] + suffix))
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
        release = self._new_release()
        with self.assertRaises(HYDRATOR.HydrationError):
            HYDRATOR.hydrate(
                mapping_path=self.mapping_path,
                candidate_manifest_path=(
                    release / HYDRATOR.APPROVED_MANIFEST_NAME
                ),
                release_cohort=release.name,
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

    def test_boot_fetches_only_manifest_pinned_versions(self) -> None:
        self._hydrate()
        approved = self._approve()
        manifest = json.loads(
            (approved / HYDRATOR.APPROVED_MANIFEST_NAME).read_text(encoding="ascii")
        )
        self.assertEqual(
            {record["name"]: record["version_number"] for record in manifest["artifacts"]},
            {
                name: self.bundle_versions[ocid]
                for name, ocid in self.ocids.items()
                if name in HYDRATOR.REQUIRED_MAPPING_NAMES
            },
        )
        rotated = dict(self.bundles)
        rotated["api_env"] = rotated["api_env"].replace(
            b"smtp-password-0123456789abcdefghijklmnop",
            b"smtp-future-0123456789abcdefghijklmnopqr",
        )
        self._write_bundles(rotated)
        self._simulate_reboot()
        self.oci_log.unlink(missing_ok=True)

        changed, output = self._boot()

        self.assertTrue(changed)
        self.assertEqual(output, "")
        self.assertIn(b"smtp-password-", (self._active() / "api.env").read_bytes())
        self.assertNotIn(b"smtp-future-", (self._active() / "api.env").read_bytes())
        selectors = [line.split()[1] for line in self.oci_log.read_text().splitlines()]
        self.assertEqual(selectors, ["--version-number"] * len(manifest["artifacts"]))
        self.assertNotIn("CURRENT", self.oci_log.read_text())

    def test_release_local_boot_remains_pinned_after_pointer_changes(self) -> None:
        self._hydrate()
        approved = self._approve()
        rotated = dict(self.bundles)
        rotated["api_env"] = rotated["api_env"].replace(
            b"smtp-password-0123456789abcdefghijklmnop",
            b"smtp-future-0123456789abcdefghijklmnopqr",
        )
        self._write_bundles(rotated)
        self._hydrate()
        replacement = self.last_release
        self.assertIsNotNone(replacement)
        assert replacement is not None
        self.assertNotEqual(replacement, approved)
        self._approve(replacement)
        self._simulate_reboot()
        self.oci_log.unlink(missing_ok=True)

        changed, output = self._boot_release_local(approved)

        self.assertTrue(changed)
        self.assertEqual(output, "")
        self.assertIn(b"smtp-password-", (self._active() / "api.env").read_bytes())
        self.assertNotIn("CURRENT", self.oci_log.read_text())
        self.assertTrue(
            all(
                line.split()[1] == "--version-number"
                for line in self.oci_log.read_text().splitlines()
            )
        )

    def test_release_commit_rejects_tampered_boot_bundle_before_pointer_swap(self) -> None:
        self._hydrate()
        candidate = self.last_release
        self.assertIsNotNone(candidate)
        assert candidate is not None
        worker = candidate / HYDRATOR.BOOT_SECRET_DIRECTORY_NAME / "prepare-runtime-secrets.sh"
        worker.chmod(0o600)
        worker.write_bytes(worker.read_bytes() + b"# tampered\n")
        worker.chmod(0o500)

        with self.assertRaisesRegex(HYDRATOR.HydrationError, "checksum mismatch"):
            HYDRATOR.commit_candidate_release(
                candidate_manifest_path=(
                    candidate / HYDRATOR.APPROVED_MANIFEST_NAME
                ),
                release_cohort=candidate.name,
                secret_root=self.secret_root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )
        self.assertFalse((self.release_root / "current").exists())

    def test_crash_before_release_pointer_commit_reboots_prior_cohort(self) -> None:
        self._hydrate()
        prior_release = self._approve()
        prior_target = os.readlink(self.release_root / "current")
        rotated = dict(self.bundles)
        rotated["api_env"] = rotated["api_env"].replace(
            b"smtp-password-0123456789abcdefghijklmnop",
            b"smtp-candidate-0123456789abcdefghijklmnop",
        )
        self._write_bundles(rotated)
        self._hydrate()
        candidate_release = self.last_release
        self.assertIsNotNone(candidate_release)
        self.assertNotEqual(candidate_release, prior_release)
        self.assertIn(b"smtp-candidate-", (self._active() / "api.env").read_bytes())
        self.assertEqual(os.readlink(self.release_root / "current"), prior_target)

        self._simulate_reboot()
        self.oci_log.unlink(missing_ok=True)
        self._boot()

        self.assertIn(b"smtp-password-", (self._active() / "api.env").read_bytes())
        self.assertNotIn(b"smtp-candidate-", (self._active() / "api.env").read_bytes())
        self.assertEqual(os.readlink(self.release_root / "current"), prior_target)

    def test_approved_mapping_snapshot_ignores_later_live_mapping_change(self) -> None:
        self._hydrate()
        approved = self._approve()
        approved_mapping = (approved / HYDRATOR.APPROVED_MAPPING_NAME).read_bytes()
        old_cloudflare_ocid = self.ocids["cloudflare_token"]
        new_cloudflare_ocid = (
            "ocid1.vaultsecret.oc1.us-phoenix-1.testcloudflarenew0123456789"
        )
        changed_mapping = dict(self.ocids)
        changed_mapping["cloudflare_token"] = new_cloudflare_ocid
        self._write_mapping(changed_mapping)
        self.ocids["cloudflare_token"] = new_cloudflare_ocid
        self._write_bundles(
            {"cloudflare_token": self.bundles["cloudflare_token"] + b"new"}
        )
        self._simulate_reboot()
        self.oci_log.unlink(missing_ok=True)

        self._boot()

        log = self.oci_log.read_text()
        self.assertIn(old_cloudflare_ocid, log)
        self.assertNotIn(new_cloudflare_ocid, log)
        self.assertEqual(
            (approved / HYDRATOR.APPROVED_MAPPING_NAME).read_bytes(), approved_mapping
        )

    def test_incomplete_manifest_is_rejected_before_any_vault_fetch(self) -> None:
        self._hydrate()
        approved = self._approve()
        manifest_path = approved / HYDRATOR.APPROVED_MANIFEST_NAME
        document = json.loads(manifest_path.read_text(encoding="ascii"))
        document["artifacts"].pop()
        manifest_path.chmod(0o600)
        manifest_path.write_text(json.dumps(document) + "\n", encoding="ascii")
        manifest_path.chmod(0o400)
        self._simulate_reboot()
        self.oci_log.unlink(missing_ok=True)

        with self.assertRaisesRegex(HYDRATOR.HydrationError, "incomplete"):
            self._boot()

        self.assertFalse(self.oci_log.exists())
        self.assertFalse((self.secret_root / "active").exists())

    def test_duplicate_manifest_key_is_rejected_before_any_vault_fetch(self) -> None:
        self._hydrate()
        approved = self._approve()
        manifest_path = approved / HYDRATOR.APPROVED_MANIFEST_NAME
        original = manifest_path.read_text(encoding="ascii")
        duplicate = original.replace("{\n", '{\n  "schema": 1,\n', 1)
        manifest_path.chmod(0o600)
        manifest_path.write_text(duplicate, encoding="ascii")
        manifest_path.chmod(0o400)
        self._simulate_reboot()
        self.oci_log.unlink(missing_ok=True)

        with self.assertRaisesRegex(HYDRATOR.HydrationError, "duplicate key"):
            self._boot()

        self.assertFalse(self.oci_log.exists())

    def test_mixed_manifest_secret_id_is_rejected_before_any_vault_fetch(self) -> None:
        self._hydrate()
        approved = self._approve()
        manifest_path = approved / HYDRATOR.APPROVED_MANIFEST_NAME
        document = json.loads(manifest_path.read_text(encoding="ascii"))
        document["artifacts"][0]["secret_id"] = document["artifacts"][1]["secret_id"]
        manifest_path.chmod(0o600)
        manifest_path.write_text(json.dumps(document) + "\n", encoding="ascii")
        manifest_path.chmod(0o400)
        self._simulate_reboot()
        self.oci_log.unlink(missing_ok=True)

        with self.assertRaisesRegex(HYDRATOR.HydrationError, "does not match mapping"):
            self._boot()

        self.assertFalse(self.oci_log.exists())

    def test_candidate_manifest_publish_fault_keeps_prior_boot_approval(self) -> None:
        self._hydrate()
        self._approve()
        prior_pointer = os.readlink(self.release_root / "current")
        prior_target = os.readlink(self.secret_root / "active")
        rotated = dict(self.bundles)
        rotated["api_env"] = rotated["api_env"].replace(
            b"smtp-password-0123456789abcdefghijklmnop",
            b"smtp-publish-fault-0123456789abcdefghijk",
        )
        self._write_bundles(rotated)
        real_publish = HYDRATOR._atomic_publish_release_file

        def fail_manifest_publish(
            path: Path, content: bytes, mode: int, expected_uid: int, expected_gid: int
        ) -> None:
            if path.name == HYDRATOR.APPROVED_MANIFEST_NAME:
                raise OSError("injected manifest publication failure")
            real_publish(path, content, mode, expected_uid, expected_gid)

        with mock.patch.object(
            HYDRATOR,
            "_atomic_publish_release_file",
            side_effect=fail_manifest_publish,
        ):
            with self.assertRaises(HYDRATOR.HydrationError):
                self._hydrate()

        self.assertEqual(os.readlink(self.release_root / "current"), prior_pointer)
        self.assertEqual(os.readlink(self.secret_root / "active"), prior_target)

    def test_candidate_verification_binds_active_marker_to_release(self) -> None:
        self._hydrate()
        candidate = self.last_release
        self.assertIsNotNone(candidate)
        assert candidate is not None
        HYDRATOR.verify_candidate_selection(
            candidate_manifest_path=(
                candidate / HYDRATOR.APPROVED_MANIFEST_NAME
            ),
            release_cohort=candidate.name,
            secret_root=self.secret_root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        marker = self._active() / HYDRATOR.MARKER_NAME
        marker.chmod(0o600)
        marker.write_bytes(
            marker.read_bytes().replace(
                b"release_cohort=oci-0123456789ab-test1",
                b"release_cohort=oci-0123456789ab-other",
            )
        )
        marker.chmod(0o400)
        with self.assertRaisesRegex(HYDRATOR.HydrationError, "another release"):
            HYDRATOR.verify_candidate_selection(
                candidate_manifest_path=(
                    candidate / HYDRATOR.APPROVED_MANIFEST_NAME
                ),
                release_cohort=candidate.name,
                secret_root=self.secret_root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

    def test_release_pointer_swap_fault_preserves_prior_approved_release(self) -> None:
        self._hydrate()
        self._approve()
        prior_pointer = os.readlink(self.release_root / "current")
        rotated = dict(self.bundles)
        rotated["api_env"] = rotated["api_env"].replace(
            b"smtp-password-0123456789abcdefghijklmnop",
            b"smtp-release-swap-0123456789abcdefghijkl",
        )
        self._write_bundles(rotated)
        self._hydrate()
        candidate = self.last_release
        self.assertIsNotNone(candidate)
        assert candidate is not None
        real_replace = os.replace

        def fail_release_pointer(source: object, destination: object) -> None:
            if Path(destination) == self.release_root / "current":
                raise OSError("injected release pointer failure")
            real_replace(source, destination)

        with mock.patch.object(HYDRATOR.os, "replace", side_effect=fail_release_pointer):
            with self.assertRaises(OSError):
                HYDRATOR.commit_candidate_release(
                    candidate_manifest_path=(
                        candidate / HYDRATOR.APPROVED_MANIFEST_NAME
                    ),
                    release_cohort=candidate.name,
                    secret_root=self.secret_root,
                    expected_uid=self.uid,
                    expected_gid=self.gid,
                )

        self.assertEqual(os.readlink(self.release_root / "current"), prior_pointer)

    def test_post_commit_fsync_fault_leaves_complete_new_boot_cohort(self) -> None:
        self._hydrate()
        self._approve()
        rotated = dict(self.bundles)
        rotated["api_env"] = rotated["api_env"].replace(
            b"smtp-password-0123456789abcdefghijklmnop",
            b"smtp-release-commit-0123456789abcdefghijkl",
        )
        self._write_bundles(rotated)
        self._hydrate()
        candidate = self.last_release
        self.assertIsNotNone(candidate)
        assert candidate is not None
        real_fsync_directory = HYDRATOR._fsync_directory
        injected = False

        def fail_after_release_swap(path: Path) -> None:
            nonlocal injected
            if (
                path == self.release_root
                and (self.release_root / "current").is_symlink()
                and os.readlink(self.release_root / "current") == str(candidate)
                and not injected
            ):
                injected = True
                raise OSError("injected release-root fsync failure")
            real_fsync_directory(path)

        with mock.patch.object(
            HYDRATOR, "_fsync_directory", side_effect=fail_after_release_swap
        ):
            with self.assertRaises(OSError):
                HYDRATOR.commit_candidate_release(
                    candidate_manifest_path=(
                        candidate / HYDRATOR.APPROVED_MANIFEST_NAME
                    ),
                    release_cohort=candidate.name,
                    secret_root=self.secret_root,
                    expected_uid=self.uid,
                    expected_gid=self.gid,
                )
        self.assertTrue(injected)
        self.assertEqual(os.readlink(self.release_root / "current"), str(candidate))

        self._simulate_reboot()
        self._boot()
        self.assertIn(b"smtp-release-commit-", (self._active() / "api.env").read_bytes())

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
