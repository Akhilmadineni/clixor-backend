from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parent))
import dependency_pki  # noqa: E402


class DependencyPKITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.pki_root = self.root / "pki"
        self.runtime_root = self.root / "runtime"
        self.pki_root.mkdir(mode=0o700)
        self.runtime_root.mkdir(mode=0o750)

    def ensure(
        self,
        *,
        leaf_days: int = 397,
        renew_before_seconds: int = 30 * 86400,
    ) -> tuple[dict[str, str], list[str]]:
        return dependency_pki.ensure_dependency_pki(
            self.pki_root,
            self.runtime_root,
            leaf_days=leaf_days,
            renew_before_seconds=renew_before_seconds,
            chown_runtime=False,
            pki_uid=None,
            pki_gid=None,
        )

    def current_leaf(self, service: str) -> Path:
        return (self.pki_root / "leaves" / service / "current").resolve()

    def test_generates_scoped_ca_signed_leaves_with_distinct_keys(self) -> None:
        state, rotated = self.ensure()

        self.assertEqual(rotated, ["dependency-tls", "postgres", "nats"])
        expected_sans = {
            "dependency-tls": ("clixor-tls", "dependency-tls"),
            "postgres": ("postgres.clixor.internal",),
            "nats": ("nats.clixor.internal",),
        }
        public_keys = set()
        for service, sans in expected_sans.items():
            generation = self.current_leaf(service)
            certificate = generation / "server.crt"
            key = generation / "server.key"
            self.assertEqual(
                tuple(sorted(dependency_pki._certificate_dns_names(certificate))),
                tuple(sorted(sans)),
            )
            dependency_pki._run_openssl(
                [
                    "verify",
                    "-purpose",
                    "sslserver",
                    "-CAfile",
                    str(self.pki_root / "ca.crt"),
                    str(certificate),
                ]
            )
            public_keys.add(dependency_pki._public_key_digest_from_key(key))
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(certificate.stat().st_mode), 0o644)
            self.assertEqual(
                state[service], dependency_pki._certificate_digest(certificate)
            )
        self.assertEqual(len(public_keys), 3)

        runtime_files = (
            ("dependency-tls", "server.pem", 0o440),
            ("postgres-tls", "server.key", 0o440),
            ("postgres-tls", "server.crt", 0o440),
            ("nats-tls", "server.key", 0o440),
            ("nats-tls", "server.crt", 0o440),
        )
        for service_root, filename, expected_mode in runtime_files:
            runtime_file = self.runtime_root / service_root / "current" / filename
            self.assertTrue(runtime_file.is_file())
            self.assertEqual(stat.S_IMODE(runtime_file.stat().st_mode), expected_mode)

    def test_rerun_is_idempotent(self) -> None:
        first_state, _ = self.ensure()
        first_targets = {
            spec.name: os.readlink(
                self.pki_root / "leaves" / spec.name / "current"
            )
            for spec in dependency_pki.LEAF_SPECS
        }
        first_generation_counts = {
            spec.name: len(
                list((self.pki_root / "leaves" / spec.name / "generations").iterdir())
            )
            for spec in dependency_pki.LEAF_SPECS
        }
        postgres_key = self.current_leaf("postgres") / "server.key"
        os.chmod(postgres_key, 0o644)

        second_state, rotated = self.ensure()

        self.assertEqual(second_state, first_state)
        self.assertEqual(rotated, [])
        self.assertEqual(stat.S_IMODE(postgres_key.stat().st_mode), 0o600)
        self.assertEqual(
            {
                spec.name: os.readlink(
                    self.pki_root / "leaves" / spec.name / "current"
                )
                for spec in dependency_pki.LEAF_SPECS
            },
            first_targets,
        )
        self.assertEqual(
            {
                spec.name: len(
                    list(
                        (
                            self.pki_root / "leaves" / spec.name / "generations"
                        ).iterdir()
                    )
                )
                for spec in dependency_pki.LEAF_SPECS
            },
            first_generation_counts,
        )

    def test_preserves_an_existing_legacy_ca(self) -> None:
        ca_key = self.pki_root / "ca.key"
        ca_certificate = self.pki_root / "ca.crt"
        dependency_pki._run_openssl(
            [
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                str(ca_key),
            ]
        )
        dependency_pki._run_openssl(
            [
                "req",
                "-x509",
                "-new",
                "-sha256",
                "-days",
                "3650",
                "-key",
                str(ca_key),
                "-subj",
                "/CN=Legacy Clixor CA",
                "-out",
                str(ca_certificate),
            ]
        )
        original_key = ca_key.read_bytes()
        original_certificate = ca_certificate.read_bytes()

        state, _ = self.ensure()

        self.assertEqual(ca_key.read_bytes(), original_key)
        self.assertEqual(ca_certificate.read_bytes(), original_certificate)
        self.assertEqual(
            state["ca"], dependency_pki._certificate_digest(ca_certificate)
        )

    def test_partial_and_mismatched_ca_fail_closed(self) -> None:
        (self.pki_root / "ca.key").write_text("partial", encoding="ascii")
        with self.assertRaisesRegex(dependency_pki.PKIError, "CA is incomplete"):
            self.ensure()
        self.assertFalse((self.pki_root / "leaves").exists())

        (self.pki_root / "ca.key").unlink()
        self.ensure()
        other_root = self.root / "other"
        other_pki = other_root / "pki"
        other_runtime = other_root / "runtime"
        other_root.mkdir()
        other_pki.mkdir()
        other_runtime.mkdir()
        dependency_pki.ensure_dependency_pki(
            other_pki,
            other_runtime,
            chown_runtime=False,
            pki_uid=None,
            pki_gid=None,
        )
        original_key = (self.pki_root / "ca.key").read_bytes()
        replacement_certificate = (other_pki / "ca.crt").read_bytes()
        (self.pki_root / "ca.crt").write_bytes(replacement_certificate)

        with self.assertRaisesRegex(dependency_pki.PKIError, "do not match"):
            self.ensure()
        self.assertEqual((self.pki_root / "ca.key").read_bytes(), original_key)
        self.assertEqual(
            (self.pki_root / "ca.crt").read_bytes(), replacement_certificate
        )

        (self.pki_root / "ca.key").write_bytes((other_pki / "ca.key").read_bytes())
        with self.assertRaisesRegex(dependency_pki.PKIError, "fingerprint changed"):
            self.ensure()

    def test_renewal_switches_generations_and_requires_restarts(self) -> None:
        first_state, _ = self.ensure(leaf_days=2, renew_before_seconds=0)
        applied_path = self.runtime_root / "dependency-pki.applied"
        dependency_pki.mark_applied(
            self.runtime_root / "dependency-pki.desired", applied_path
        )
        first_targets = {
            spec.name: os.readlink(
                self.pki_root / "leaves" / spec.name / "current"
            )
            for spec in dependency_pki.LEAF_SPECS
        }

        second_state, rotated = self.ensure(
            leaf_days=10, renew_before_seconds=3 * 86400
        )

        self.assertEqual(rotated, ["dependency-tls", "postgres", "nats"])
        self.assertNotEqual(second_state, first_state)
        self.assertEqual(
            dependency_pki.pending_restarts(
                self.runtime_root / "dependency-pki.desired", applied_path
            ),
            ["dependency-tls", "postgres", "nats"],
        )
        for spec in dependency_pki.LEAF_SPECS:
            self.assertNotEqual(
                os.readlink(self.pki_root / "leaves" / spec.name / "current"),
                first_targets[spec.name],
            )

    def test_failed_leaf_publication_keeps_the_previous_generation(self) -> None:
        first_state, _ = self.ensure(leaf_days=2, renew_before_seconds=0)
        current = self.pki_root / "leaves" / "dependency-tls" / "current"
        original_target = os.readlink(current)
        original_desired = (self.runtime_root / "dependency-pki.desired").read_bytes()
        real_atomic_symlink = dependency_pki._atomic_symlink

        def fail_before_dependency_switch(target: str, link_path: Path) -> None:
            if link_path == current:
                raise OSError("simulated publication failure")
            real_atomic_symlink(target, link_path)

        with mock.patch.object(
            dependency_pki, "_atomic_symlink", side_effect=fail_before_dependency_switch
        ), self.assertRaises(OSError):
            self.ensure(leaf_days=10, renew_before_seconds=3 * 86400)

        self.assertEqual(os.readlink(current), original_target)
        self.assertEqual(
            dependency_pki._certificate_digest(
                self.current_leaf("dependency-tls") / "server.crt"
            ),
            first_state["dependency-tls"],
        )
        self.assertEqual(
            (self.runtime_root / "dependency-pki.desired").read_bytes(),
            original_desired,
        )

    def test_restart_state_is_strict_and_service_scoped(self) -> None:
        state, _ = self.ensure()
        desired_path = self.runtime_root / "dependency-pki.desired"
        applied_path = self.runtime_root / "dependency-pki.applied"
        dependency_pki.mark_applied(desired_path, applied_path)
        self.assertEqual(
            dependency_pki.pending_restarts(desired_path, applied_path), []
        )

        changed = dict(state)
        changed["nats"] = "sha256:" + ("0" * 64)
        desired_path.write_bytes(dependency_pki._canonical_state(changed))
        self.assertEqual(
            dependency_pki.pending_restarts(desired_path, applied_path), ["nats"]
        )

        desired_path.write_text("version 1\nnats not-a-digest\n", encoding="ascii")
        with self.assertRaises(dependency_pki.PKIError):
            dependency_pki.pending_restarts(desired_path, applied_path)


if __name__ == "__main__":
    unittest.main()
