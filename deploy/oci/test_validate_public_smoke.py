from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT_ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "clixor_public_smoke", SCRIPT_ROOT / "validate-public-smoke.py"
)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class PublicSmokeValidationTest(unittest.TestCase):
    revision = "a" * 40

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="clixor-public-smoke-",
            dir="/private/tmp" if Path("/private/tmp").is_dir() else None,
        )
        self.root = Path(self.temporary.name)
        self.api_headers = self.root / "api.headers"
        self.api_body = self.root / "api.json"
        self.association_headers = self.root / "association.headers"
        self.association_body = self.root / "association.json"
        self._write_valid()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _headers(self, revision: str, content_type: str = "application/json") -> bytes:
        return (
            "HTTP/2 200\r\n"
            f"content-type: {content_type}\r\n"
            f"x-clixor-revision: {revision}\r\n"
            "cache-control: no-store\r\n\r\n"
        ).encode("ascii")

    def _write_valid(self) -> None:
        self.api_headers.write_bytes(self._headers(self.revision))
        self.api_body.write_text(
            json.dumps({"status": "ready", "revision": self.revision}),
            encoding="utf-8",
        )
        self.association_headers.write_bytes(self._headers(self.revision))
        self.association_body.write_text(
            json.dumps(VALIDATOR.EXPECTED_ASSOCIATION),
            encoding="utf-8",
        )

    def _validate(self) -> None:
        VALIDATOR.validate(
            self.api_headers,
            self.api_body,
            self.association_headers,
            self.association_body,
            self.revision,
        )

    def test_accepts_exact_release_and_association_document(self) -> None:
        self._validate()

    def test_rejects_response_from_another_release(self) -> None:
        self.api_headers.write_bytes(self._headers("b" * 40))
        with self.assertRaises(VALIDATOR.SmokeValidationError):
            self._validate()

    def test_rejects_html_or_redirect_response(self) -> None:
        self.association_headers.write_bytes(
            self._headers(self.revision, "text/html; charset=utf-8")
        )
        with self.assertRaises(VALIDATOR.SmokeValidationError):
            self._validate()
        self._write_valid()
        self.api_headers.write_bytes(
            self._headers(self.revision).replace(b"HTTP/2 200", b"HTTP/2 302")
        )
        with self.assertRaises(VALIDATOR.SmokeValidationError):
            self._validate()

    def test_rejects_broadened_or_wrong_app_link(self) -> None:
        document = json.loads(self.association_body.read_text(encoding="utf-8"))
        document["applinks"]["details"][0]["components"][0]["/"] = "*"
        self.association_body.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaises(VALIDATOR.SmokeValidationError):
            self._validate()

    def test_rejects_duplicate_json_keys(self) -> None:
        self.api_body.write_text(
            '{"status":"ready","revision":"'
            + self.revision
            + '","revision":"'
            + self.revision
            + '"}',
            encoding="utf-8",
        )
        with self.assertRaises(VALIDATOR.SmokeValidationError):
            self._validate()


if __name__ == "__main__":
    unittest.main()
