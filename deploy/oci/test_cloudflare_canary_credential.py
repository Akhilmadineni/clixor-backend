from __future__ import annotations

import base64
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_ROOT = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_ROOT / "cloudflare-canary-credential.py"
SPEC = importlib.util.spec_from_file_location("cloudflare_canary_credential", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CREDENTIAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CREDENTIAL)

ACCOUNT = "8ceacad35a884128e4575cd7b7d793b4"
TUNNEL = "94cf7377-7b59-4209-b3b0-e68ec7ebb1d6"
SECRET_OCID = "ocid1.vaultsecret.oc1.phx.amaaaaaag3ylxbqaaaaaaaaaaaaaaaaaaaaaaaa"


def tunnel_token(account: str = ACCOUNT, tunnel: str = TUNNEL) -> bytes:
    payload = {
        "a": account,
        "s": base64.b64encode(b"reviewed-tunnel-secret").decode("ascii"),
        "t": tunnel,
    }
    return base64.b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("ascii")
    )


class FakeResponse:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *arguments):
        del arguments

    def read(self, maximum: int) -> bytes:
        return self.body[:maximum]


class CredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="clixor-canary-", dir="/private/tmp" if Path("/private/tmp").is_dir() else None
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.release = self.root / "oci-0123456789ab-test"
        bundle = self.release / "runtime-bundle"
        bundle.mkdir(parents=True, mode=0o700)
        nginx = bundle / "runtime" / "api-gateway" / "nginx.conf"
        nginx.parent.mkdir(parents=True, mode=0o700)
        nginx.write_bytes((SCRIPT_ROOT / "api-gateway-nginx.conf").read_bytes())
        nginx.chmod(0o400)
        (self.release / "secret-mode").write_text("staging\n", encoding="ascii")
        (self.release / "secret-mode").chmod(0o400)
        self.metadata = CREDENTIAL._metadata_document(
            ACCOUNT, TUNNEL, SECRET_OCID, 7, 19
        )
        CREDENTIAL.stage_metadata(self.release, self.metadata)
        (bundle / "manifest.json").write_text(
            json.dumps(
                {
                    "state": {
                        "cloudflared": {"enabled": True, "active": True}
                    }
                }
            )
            + "\n",
            encoding="ascii",
        )
        (bundle / "manifest.json").chmod(0o400)
        self.runtime = self.root / "run" / "cloudflare-connector"
        self.gate = self.root / "run" / "origin-gate" / "public-open"

    def fake_oci(self, token: bytes, *, version: int = 7, secret_id: str = SECRET_OCID) -> Path:
        script = self.root / f"fake-oci-{version}"
        response = {
            "data": {
                "secret-id": secret_id,
                "version-number": version,
                "secret-bundle-content": {
                    "content-type": "BASE64",
                    "content": base64.b64encode(token).decode("ascii"),
                },
            }
        }
        # The fake rejects argument drift before returning its fixture. The
        # real helper's stderr is suppressed, so the token cannot leak through
        # a child error path.
        expected = [
            "--auth", "instance_principal", "secrets", "secret-bundle", "get",
            "--secret-id", SECRET_OCID, "--version-number", "7", "--output", "json",
        ]
        script.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            f"expected = {expected!r}\n"
            "if sys.argv[1:] != expected or os.environ.get('OCI_CLI_AUTH') != 'instance_principal':\n"
            "    raise SystemExit(91)\n"
            f"print({json.dumps(json.dumps(response))})\n",
            encoding="ascii",
        )
        script.chmod(0o500)
        return script

    def test_exact_instance_principal_version_is_published_only_to_runtime(self) -> None:
        token = tunnel_token()
        fake = self.fake_oci(token)
        with mock.patch.object(CREDENTIAL, "PRODUCTION_GATE", self.gate):
            CREDENTIAL.prepare(
                self.release,
                runtime_root=self.runtime,
                oci_binary=fake,
                enforce_tmpfs=False,
            )
        selected = self.runtime / CREDENTIAL.TOKEN_NAME
        self.assertEqual(selected.read_bytes(), token + b"\n")
        self.assertEqual(stat.S_IMODE(selected.stat().st_mode), 0o600)
        self.assertFalse(any(token in path.read_bytes() for path in self.release.rglob("*") if path.is_file()))
        CREDENTIAL.verify(self.release, runtime_root=self.runtime, enforce_tmpfs=False)

    def test_wrong_exact_version_preserves_previous_selection_and_redacts_token(self) -> None:
        self.runtime.mkdir(parents=True, mode=0o700)
        old = b"previous-safe-selection\n"
        (self.runtime / CREDENTIAL.TOKEN_NAME).write_bytes(old)
        (self.runtime / CREDENTIAL.TOKEN_NAME).chmod(0o600)
        bad_token = tunnel_token(account="0" * 32)
        fake = self.fake_oci(bad_token, version=8)
        with mock.patch.object(CREDENTIAL, "PRODUCTION_GATE", self.gate):
            with self.assertRaises(CREDENTIAL.CredentialError) as caught:
                CREDENTIAL.prepare(
                    self.release,
                    runtime_root=self.runtime,
                    oci_binary=fake,
                    enforce_tmpfs=False,
                )
        self.assertEqual((self.runtime / CREDENTIAL.TOKEN_NAME).read_bytes(), old)
        self.assertNotIn(bad_token.decode("ascii"), str(caught.exception))

    def test_account_tunnel_and_production_gate_are_fail_closed(self) -> None:
        with self.assertRaisesRegex(CREDENTIAL.CredentialError, "another account"):
            CREDENTIAL.validate_tunnel_token(tunnel_token(account="0" * 32), ACCOUNT, TUNNEL)
        with self.assertRaisesRegex(CREDENTIAL.CredentialError, "another tunnel"):
            CREDENTIAL.validate_tunnel_token(
                tunnel_token(tunnel="00000000-0000-4000-8000-000000000001"), ACCOUNT, TUNNEL
            )
        self.gate.parent.mkdir(parents=True)
        self.gate.write_text("open\n", encoding="ascii")
        with mock.patch.object(CREDENTIAL, "PRODUCTION_GATE", self.gate):
            with self.assertRaisesRegex(CREDENTIAL.CredentialError, "gate"):
                CREDENTIAL.prepare(
                    self.release,
                    runtime_root=self.runtime,
                    oci_binary=self.root / "never-run",
                    enforce_tmpfs=False,
                )

    def test_metadata_rejects_current_alias_and_non_canary_routes(self) -> None:
        bad = json.loads(json.dumps(self.metadata))
        bad["secret"]["version"] = "CURRENT"
        with self.assertRaises(CREDENTIAL.CredentialError):
            CREDENTIAL.validate_metadata(bad)
        bad = json.loads(json.dumps(self.metadata))
        bad["remote_config"]["ingress"].insert(
            0, {"hostname": "clustr-api.atlanteanz.com", "service": CREDENTIAL.CANARY_ORIGIN}
        )
        with self.assertRaises(CREDENTIAL.CredentialError):
            CREDENTIAL.validate_metadata(bad)

    def test_remote_config_requires_exact_version_routes_and_no_warp(self) -> None:
        body = json.dumps(
            {
                "version": 19,
                "config": {
                    "ingress": [
                        {"hostname": CREDENTIAL.CANARY_HOSTNAME, "service": CREDENTIAL.CANARY_ORIGIN},
                        {"service": "http_status:404"},
                    ],
                    "warp-routing": {"enabled": False},
                },
            }
        ).encode("ascii")
        with mock.patch.object(CREDENTIAL.urllib.request, "urlopen", return_value=FakeResponse(body)):
            CREDENTIAL.verify_remote_config(self.metadata, attempts=1)
        drift = json.loads(body)
        drift["config"]["ingress"][0]["hostname"] = "clustr-api.atlanteanz.com"
        with mock.patch.object(
            CREDENTIAL.urllib.request,
            "urlopen",
            return_value=FakeResponse(json.dumps(drift).encode("ascii")),
        ):
            with self.assertRaisesRegex(CREDENTIAL.CredentialError, "differs"):
                CREDENTIAL.verify_remote_config(self.metadata, attempts=1)

    def test_disabled_staging_release_removes_only_owned_runtime_files(self) -> None:
        (self.release / "runtime-bundle" / CREDENTIAL.METADATA_NAME).unlink()
        manifest = self.release / "runtime-bundle" / "manifest.json"
        manifest.chmod(0o600)
        manifest.write_text(
            json.dumps({"state": {"cloudflared": {"enabled": False, "active": False}}}) + "\n",
            encoding="ascii",
        )
        manifest.chmod(0o400)
        self.runtime.mkdir(parents=True, mode=0o700)
        for name in (CREDENTIAL.TOKEN_NAME, CREDENTIAL.SELECTION_NAME):
            (self.runtime / name).write_text("stale\n", encoding="ascii")
            (self.runtime / name).chmod(0o600)
        CREDENTIAL.prepare(self.release, runtime_root=self.runtime, enforce_tmpfs=False)
        self.assertFalse(self.runtime.exists())


if __name__ == "__main__":
    unittest.main()
