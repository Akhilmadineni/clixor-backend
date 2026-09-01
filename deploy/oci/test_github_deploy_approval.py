from __future__ import annotations

import base64
import json
import subprocess
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import verify_github_deploy as approval


REPOSITORY = "Akhilmadineni/clixor-backend"
WORKFLOW_REF = f"{REPOSITORY}/.github/workflows/deploy-oci.yml@refs/heads/main"
SOURCE_SHA = "a" * 40
SOURCE_RUN_ID = "123456"
DEPLOY_RUN_ID = "654321"
DEPLOY_RUN_ATTEMPT = "2"
AUDIENCE = (
    f"clixor-oci-production:{SOURCE_SHA}:{SOURCE_RUN_ID}:"
    f"{DEPLOY_RUN_ID}:{DEPLOY_RUN_ATTEMPT}"
)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def valid_claims(now: int) -> dict[str, object]:
    return {
        "iss": approval.OIDC_ISSUER,
        "aud": AUDIENCE,
        "sub": f"repo:{REPOSITORY}:ref:refs/heads/main",
        "repository": REPOSITORY,
        "repository_owner": "Akhilmadineni",
        "event_name": "workflow_run",
        "ref": "refs/heads/main",
        "workflow_ref": WORKFLOW_REF,
        "runner_environment": "self-hosted",
        "run_id": DEPLOY_RUN_ID,
        "run_attempt": DEPLOY_RUN_ATTEMPT,
        "jti": "test-token-id",
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 300,
    }


class GitHubDeployApprovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        key_path = Path(cls.temporary.name) / "test-only-rsa.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(key_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        modulus_output = subprocess.run(
            ["openssl", "rsa", "-in", str(key_path), "-noout", "-modulus"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout.strip()
        modulus = int(modulus_output.removeprefix("Modulus="), 16)
        cls.key_path = key_path
        cls.jwk = {
            "kid": "test-key",
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": b64url(modulus.to_bytes((modulus.bit_length() + 7) // 8, "big")),
            "e": b64url((65537).to_bytes(3, "big")),
        }

    def signed_token(self, claims: dict[str, object]) -> str:
        header = b64url(
            json.dumps(
                {"alg": "RS256", "typ": "JWT", "kid": "test-key"},
                separators=(",", ":"),
            ).encode("utf-8")
        )
        payload = b64url(
            json.dumps(claims, separators=(",", ":")).encode("utf-8")
        )
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.key_path)],
            input=signing_input,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout
        return f"{header}.{payload}.{b64url(signature)}"

    def verify(self, token: str) -> None:
        with patch.object(
            approval,
            "_fetch_json",
            return_value={"keys": [self.jwk]},
        ):
            approval.verify_oidc_token(
                token,
                repository=REPOSITORY,
                workflow_ref=WORKFLOW_REF,
                audience=AUDIENCE,
                deploy_run_id=DEPLOY_RUN_ID,
                deploy_run_attempt=DEPLOY_RUN_ATTEMPT,
            )

    def test_signed_token_is_accepted_only_for_the_exact_workflow_context(self) -> None:
        now = int(time.time())
        self.verify(self.signed_token(valid_claims(now)))
        for key, replacement in (
            ("aud", "wrong-audience"),
            ("event_name", "push"),
            ("workflow_ref", f"{REPOSITORY}/.github/workflows/other.yml@refs/heads/main"),
            ("runner_environment", "github-hosted"),
            ("run_id", "999"),
        ):
            claims = valid_claims(now)
            claims[key] = replacement
            with self.subTest(key=key), self.assertRaises(approval.ApprovalError):
                self.verify(self.signed_token(claims))

    def test_signature_tampering_is_rejected(self) -> None:
        token = self.signed_token(valid_claims(int(time.time())))
        header, payload, signature = token.split(".")
        replacement = "A" if signature[0] != "A" else "B"
        tampered = f"{header}.{payload}.{replacement}{signature[1:]}"
        with self.assertRaises(approval.ApprovalError):
            self.verify(tampered)

    def test_source_run_must_be_the_successful_main_ci_run_for_the_sha(self) -> None:
        run: dict[str, object] = {
            "id": int(SOURCE_RUN_ID),
            "name": "CI",
            "path": ".github/workflows/ci.yml",
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": SOURCE_SHA,
            "repository": {"full_name": REPOSITORY},
            "head_repository": {"full_name": REPOSITORY},
        }
        approval.validate_source_run(
            run,
            repository=REPOSITORY,
            source_run_id=SOURCE_RUN_ID,
            source_sha=SOURCE_SHA,
        )
        for key, replacement in (
            ("conclusion", "failure"),
            ("event", "pull_request"),
            ("head_branch", "feature/unsafe"),
            ("head_sha", "b" * 40),
        ):
            invalid = dict(run)
            invalid[key] = replacement
            with self.subTest(key=key), self.assertRaises(approval.ApprovalError):
                approval.validate_source_run(
                    invalid,
                    repository=REPOSITORY,
                    source_run_id=SOURCE_RUN_ID,
                    source_sha=SOURCE_SHA,
                )


if __name__ == "__main__":
    unittest.main()
