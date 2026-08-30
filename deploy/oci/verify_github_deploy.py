#!/usr/bin/env python3
"""Verify a GitHub OIDC deployment caller and its completed CI source run.

The signed token is read only from stdin.  No GitHub credential is required:
Clixor's public repository and GitHub's OIDC/JWKS endpoints are read over HTTPS.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Mapping, Sequence


OIDC_ISSUER = "https://token.actions.githubusercontent.com"
OIDC_JWKS_URL = f"{OIDC_ISSUER}/.well-known/jwks"
GITHUB_API_ROOT = "https://api.github.com"
MAX_HTTP_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 32 * 1024
RSA_SHA256_DIGEST_INFO = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


class ApprovalError(ValueError):
    """A deployment approval failed closed."""


def _strict_json(raw: bytes, description: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ApprovalError(f"{description} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ApprovalError(f"{description} is not valid JSON") from error


def _fetch_json(url: str, description: str) -> Mapping[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "clixor-oci-deploy-approval/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise ApprovalError(f"{description} returned an unexpected status")
            raw = response.read(MAX_HTTP_BYTES + 1)
    except (OSError, urllib.error.URLError) as error:
        raise ApprovalError(f"could not retrieve {description}") from error
    if len(raw) > MAX_HTTP_BYTES:
        raise ApprovalError(f"{description} response is oversized")
    document = _strict_json(raw, description)
    if not isinstance(document, dict):
        raise ApprovalError(f"{description} is not a JSON object")
    return document


def _decode_base64url(value: str, description: str) -> bytes:
    if not value or any(
        character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in value
    ):
        raise ApprovalError(f"{description} is malformed")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise ApprovalError(f"{description} is malformed") from error
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise ApprovalError(f"{description} is not canonical base64url")
    return decoded


def _positive_jwk_integer(value: Any, description: str) -> int:
    if not isinstance(value, str):
        raise ApprovalError(f"OIDC signing key has an invalid {description}")
    integer = int.from_bytes(_decode_base64url(value, description), "big")
    if integer <= 0:
        raise ApprovalError(f"OIDC signing key has an invalid {description}")
    return integer


def _verify_rs256(signing_input: bytes, signature: bytes, jwk: Mapping[str, Any]) -> None:
    if jwk.get("kty") != "RSA" or jwk.get("use") not in (None, "sig"):
        raise ApprovalError("OIDC signing key is not an RSA signature key")
    if jwk.get("alg") not in (None, "RS256"):
        raise ApprovalError("OIDC signing key has an unexpected algorithm")
    modulus = _positive_jwk_integer(jwk.get("n"), "modulus")
    exponent = _positive_jwk_integer(jwk.get("e"), "exponent")
    if modulus.bit_length() < 2048 or exponent < 3 or exponent % 2 == 0:
        raise ApprovalError("OIDC signing key does not meet RSA requirements")
    width = (modulus.bit_length() + 7) // 8
    if len(signature) != width or int.from_bytes(signature, "big") >= modulus:
        raise ApprovalError("OIDC token signature has an invalid size")
    encoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(
        width, "big"
    )
    digest_info = RSA_SHA256_DIGEST_INFO + hashlib.sha256(signing_input).digest()
    padding_length = width - len(digest_info) - 3
    if padding_length < 8:
        raise ApprovalError("OIDC signing key is too small")
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    if not hmac.compare_digest(encoded, expected):
        raise ApprovalError("OIDC token signature is invalid")


def _required_string(claims: Mapping[str, Any], key: str) -> str:
    value = claims.get(key)
    if not isinstance(value, str) or not value:
        raise ApprovalError(f"OIDC token is missing the {key} claim")
    return value


def validate_claims(
    claims: Mapping[str, Any],
    *,
    repository: str,
    workflow_ref: str,
    audience: str,
    deploy_run_id: str,
    deploy_run_attempt: str,
    now: int | None = None,
) -> None:
    current = int(time.time()) if now is None else now
    for key in ("iat", "exp"):
        value = claims.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ApprovalError(f"OIDC token has an invalid {key} claim")
    issued_at = int(claims["iat"])
    expires_at = int(claims["exp"])
    not_before = claims.get("nbf", issued_at)
    if isinstance(not_before, bool) or not isinstance(not_before, int):
        raise ApprovalError("OIDC token has an invalid nbf claim")
    if issued_at > current + 60 or not_before > current + 60 or expires_at <= current - 30:
        raise ApprovalError("OIDC token is not currently valid")
    if current - issued_at > 600 or expires_at - issued_at > 600:
        raise ApprovalError("OIDC token lifetime is outside the deployment policy")

    token_audience = claims.get("aud")
    if isinstance(token_audience, str):
        audiences = [token_audience]
    elif isinstance(token_audience, list) and all(
        isinstance(item, str) for item in token_audience
    ):
        audiences = token_audience
    else:
        raise ApprovalError("OIDC token has an invalid audience")
    if audiences != [audience]:
        raise ApprovalError("OIDC token audience does not match this deployment")

    expected = {
        "iss": OIDC_ISSUER,
        "repository": repository,
        "repository_owner": repository.split("/", 1)[0],
        "event_name": "workflow_run",
        "ref": "refs/heads/main",
        "workflow_ref": workflow_ref,
        "runner_environment": "self-hosted",
        "run_id": deploy_run_id,
        "run_attempt": deploy_run_attempt,
        "sub": f"repo:{repository}:ref:refs/heads/main",
    }
    for key, expected_value in expected.items():
        if _required_string(claims, key) != expected_value:
            raise ApprovalError(f"OIDC token {key} claim is not approved")
    _required_string(claims, "jti")


def verify_oidc_token(
    token: str,
    *,
    repository: str,
    workflow_ref: str,
    audience: str,
    deploy_run_id: str,
    deploy_run_attempt: str,
) -> None:
    if not token or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise ApprovalError("OIDC token is missing or oversized")
    parts = token.split(".")
    if len(parts) != 3:
        raise ApprovalError("OIDC token is malformed")
    header_raw = _decode_base64url(parts[0], "OIDC header")
    payload_raw = _decode_base64url(parts[1], "OIDC payload")
    signature = _decode_base64url(parts[2], "OIDC signature")
    header = _strict_json(header_raw, "OIDC header")
    claims = _strict_json(payload_raw, "OIDC payload")
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise ApprovalError("OIDC token header or payload is not an object")
    if header.get("alg") != "RS256" or header.get("typ") not in (None, "JWT"):
        raise ApprovalError("OIDC token uses an unsupported algorithm or type")
    if any(key in header for key in ("crit", "jku", "jwk", "x5u")):
        raise ApprovalError("OIDC token contains an unsupported key reference")
    key_id = header.get("kid")
    if not isinstance(key_id, str) or not key_id:
        raise ApprovalError("OIDC token has no signing-key identifier")

    jwks = _fetch_json(OIDC_JWKS_URL, "GitHub OIDC signing keys")
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise ApprovalError("GitHub OIDC signing keys are malformed")
    matches = [key for key in keys if isinstance(key, dict) and key.get("kid") == key_id]
    if len(matches) != 1:
        raise ApprovalError("OIDC signing key is missing or ambiguous")
    _verify_rs256(f"{parts[0]}.{parts[1]}".encode("ascii"), signature, matches[0])
    validate_claims(
        claims,
        repository=repository,
        workflow_ref=workflow_ref,
        audience=audience,
        deploy_run_id=deploy_run_id,
        deploy_run_attempt=deploy_run_attempt,
    )


def validate_source_run(
    run: Mapping[str, Any],
    *,
    repository: str,
    source_run_id: str,
    source_sha: str,
) -> None:
    try:
        expected_id = int(source_run_id)
    except ValueError as error:
        raise ApprovalError("source workflow run ID is invalid") from error
    expected = {
        "id": expected_id,
        "name": "CI",
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
        "head_sha": source_sha,
    }
    for key, expected_value in expected.items():
        if run.get(key) != expected_value:
            raise ApprovalError(f"source CI run {key} is not approved")
    for key in ("repository", "head_repository"):
        nested = run.get(key)
        if not isinstance(nested, dict) or nested.get("full_name") != repository:
            raise ApprovalError(f"source CI run {key} does not match the repository")


def verify_source_run(repository: str, source_run_id: str, source_sha: str) -> None:
    run = _fetch_json(
        f"{GITHUB_API_ROOT}/repos/{repository}/actions/runs/{source_run_id}",
        "GitHub source workflow run",
    )
    validate_source_run(
        run,
        repository=repository,
        source_run_id=source_run_id,
        source_sha=source_sha,
    )


def parse_args(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--source-run-id", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--deploy-run-id", required=True)
    parser.add_argument("--deploy-run-attempt", required=True)
    parser.add_argument("--audience", required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = parse_args(arguments)
    try:
        raw_token = sys.stdin.buffer.read(MAX_TOKEN_BYTES + 1)
        if len(raw_token) > MAX_TOKEN_BYTES:
            raise ApprovalError("OIDC token is oversized")
        try:
            token = raw_token.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise ApprovalError("OIDC token is not ASCII") from error
        if any(character.isspace() for character in token):
            raise ApprovalError("OIDC token is malformed")
        verify_oidc_token(
            token,
            repository=options.repository,
            workflow_ref=options.workflow_ref,
            audience=options.audience,
            deploy_run_id=options.deploy_run_id,
            deploy_run_attempt=options.deploy_run_attempt,
        )
        verify_source_run(
            options.repository, options.source_run_id, options.source_sha
        )
    except (ApprovalError, EOFError) as error:
        print(f"GitHub deployment approval failed: {error}", file=sys.stderr)
        return 1
    print("GitHub OIDC caller and completed CI source run are approved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
