from __future__ import annotations

import importlib.util
import stat
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MODULE_PATH = ROOT / "verify-canary-negative.py"
SPEC = importlib.util.spec_from_file_location("verify_canary_negative", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)

CANDIDATE = "a" * 40
OLD = "b" * 40
EDGE_HEADERS = (
    ("server", "cloudflare"),
    ("cf-ray", "0123456789abcdef-ORD"),
)


class FakeResponse:
    def __init__(self, status: int, headers, body: bytes):
        self.status = status
        self._headers = headers
        self._body = body

    def read(self, maximum: int) -> bytes:
        return self._body[:maximum]

    def getheaders(self):
        return self._headers


class FakeConnection:
    def __init__(self, response: FakeResponse | None = None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.request_arguments = None
        self.closed = False

    def request(self, *arguments, **keywords):
        self.request_arguments = (arguments, keywords)
        if self.error is not None:
            raise self.error

    def getresponse(self):
        assert self.response is not None
        return self.response

    def close(self):
        self.closed = True


class NegativeOwnershipTests(unittest.TestCase):
    def validate(self, status: int, headers=EDGE_HEADERS, body: bytes = b""):
        return VERIFY.validate_response(status, headers, body, CANDIDATE)

    def test_different_healthy_revision_is_accepted(self) -> None:
        proof = self.validate(
            200,
            (*EDGE_HEADERS, ("x-clixor-revision", OLD)),
            b'{"status":"ready"}\n',
        )
        self.assertEqual(proof.outcome, "different-revision")

    def test_exact_live_cloudflare_1033_outage_is_accepted(self) -> None:
        proof = self.validate(530, body=b"error code: 1033\n")
        self.assertEqual(proof.outcome, "cloudflare-1033")

    def test_candidate_revision_is_rejected_at_every_status(self) -> None:
        for status, body in ((200, b"ready\n"), (530, b"error code: 1033\n")):
            with self.subTest(status=status), self.assertRaisesRegex(
                VERIFY.NegativeProofError, "candidate connector owns"
            ):
                self.validate(
                    status,
                    (*EDGE_HEADERS, ("x-clixor-revision", CANDIDATE)),
                    body,
                )

    def test_candidate_shaped_and_redirect_responses_are_ambiguous(self) -> None:
        for status in (301, 404, 503):
            with self.subTest(status=status), self.assertRaisesRegex(
                VERIFY.NegativeProofError, "ambiguous"
            ):
                self.validate(status)

    def test_cloudflare_530_requires_no_revision_and_exact_1033_body(self) -> None:
        with self.assertRaisesRegex(VERIFY.NegativeProofError, "carried"):
            self.validate(
                530,
                (*EDGE_HEADERS, ("x-clixor-revision", OLD)),
                b"error code: 1033\n",
            )
        for body in (b"", b"error code: 1016\n", b"error code: 1033"):
            with self.subTest(body=body), self.assertRaisesRegex(
                VERIFY.NegativeProofError, "reviewed 1033"
            ):
                self.validate(530, body=body)

    def test_revision_headers_are_single_and_canonical(self) -> None:
        cases = (
            (*EDGE_HEADERS, ("x-clixor-revision", OLD), ("X-Clixor-Revision", OLD)),
            (*EDGE_HEADERS, ("x-clixor-revision", "not-a-revision")),
            (*EDGE_HEADERS, ("x-clixor-revision", OLD.upper())),
        )
        for headers in cases:
            with self.subTest(headers=headers), self.assertRaises(
                VERIFY.NegativeProofError
            ):
                self.validate(200, headers)

    def test_cloudflare_edge_identity_is_required(self) -> None:
        for headers in (
            (("server", "nginx"), ("cf-ray", "0123456789abcdef-ORD")),
            (("server", "notcloudflare"), ("cf-ray", "0123456789abcdef-ORD")),
            (("server", "cloudflare"),),
            (("server", "cloudflare"), ("cf-ray", "unit")),
        ):
            with self.subTest(headers=headers), self.assertRaises(
                VERIFY.NegativeProofError
            ):
                self.validate(530, headers, b"error code: 1033\n")

        proof = self.validate(
            530,
            (("server", "CloudFlare"), ("cf-ray", "0123456789abcdef-ORD")),
            b"error code: 1033\n",
        )
        self.assertEqual(proof.outcome, "cloudflare-1033")

    def test_transport_failure_retries_but_never_becomes_outage_proof(self) -> None:
        connections: list[FakeConnection] = []

        def factory(*arguments, **keywords):
            del arguments, keywords
            connection = FakeConnection(error=OSError("injected DNS failure"))
            connections.append(connection)
            return connection

        with self.assertRaisesRegex(VERIFY.NegativeProofError, "transport"):
            VERIFY.fetch_proof(
                CANDIDATE,
                attempts=3,
                retry_delay=0,
                connection_factory=factory,
                sleep=lambda _: None,
            )
        self.assertEqual(len(connections), 3)
        self.assertTrue(all(connection.closed for connection in connections))

    def test_fetch_uses_fixed_dns_tls_host_and_never_follows_redirects(self) -> None:
        connection = FakeConnection(
            response=FakeResponse(
                530,
                EDGE_HEADERS,
                b"error code: 1033\n",
            )
        )
        factory_arguments = []

        def factory(*arguments, **keywords):
            factory_arguments.append((arguments, keywords))
            return connection

        proof = VERIFY.fetch_proof(
            CANDIDATE,
            attempts=1,
            connection_factory=factory,
        )
        self.assertEqual(proof.outcome, "cloudflare-1033")
        self.assertEqual(factory_arguments[0][0][:2], (VERIFY.PRODUCTION_HOST, 443))
        self.assertEqual(connection.request_arguments[0][0], "GET")
        self.assertEqual(
            connection.request_arguments[0][1],
            f"{VERIFY.PRODUCTION_PATH}?candidate-negative={CANDIDATE}",
        )

    def test_evidence_is_root_private_and_complete(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="clixor-negative-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        root.chmod(0o700)
        proof = self.validate(530, body=b"error code: 1033\n")
        VERIFY.write_evidence(root, proof)
        self.assertEqual((root / "production-negative.status").read_text(), "530\n")
        self.assertEqual(
            (root / "production-negative.body").read_bytes(),
            b"error code: 1033\n",
        )
        for name in (
            "production-negative.headers",
            "production-negative.status",
            "production-negative.body",
        ):
            self.assertEqual(stat.S_IMODE((root / name).stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
