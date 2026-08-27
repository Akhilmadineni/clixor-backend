#!/usr/bin/env python3
"""Unit coverage for production smoke-account cleanup."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest
from unittest import mock


SMOKE_PATH = pathlib.Path(__file__).with_name("smoke.py")
SPEC = importlib.util.spec_from_file_location("clustr_smoke", SMOKE_PATH)
assert SPEC is not None and SPEC.loader is not None
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class SmokeCleanupTests(unittest.TestCase):
    def test_delete_account_uses_fresh_login_token(self) -> None:
        calls: list[tuple[str, str, str | None]] = []

        def fake_request_with_status(
            _base_url: str,
            method: str,
            path: str,
            *,
            token: str | None = None,
            body: object | None = None,
            expected: tuple[int, ...] = (200,),
        ) -> tuple[int, object | None]:
            calls.append((method, path, token))
            if path == "/v1/auth/login":
                self.assertEqual(expected, (200, 401, 404))
                assert isinstance(body, dict)
                self.assertEqual(body["email"], "alice@example.com")
                self.assertEqual(body["password"], smoke.SMOKE_PASSWORD)
                self.assertEqual(body["platform"], "ios")
                if body["device_name"] == "Smoke cleanup":
                    return 200, {"tokens": {"access_token": "fresh-token"}}
                self.assertEqual(body["device_name"], "Smoke cleanup verification")
                return 401, {"error": {"code": "invalid_credentials"}}
            self.assertEqual(expected, (204,))
            return 204, None

        with mock.patch.object(
            smoke, "request_with_status", side_effect=fake_request_with_status
        ):
            smoke.delete_registered_account("https://api.example", "alice@example.com")

        self.assertEqual(
            calls,
            [
                ("POST", "/v1/auth/login", None),
                ("DELETE", "/v1/me", "fresh-token"),
                ("POST", "/v1/auth/login", None),
            ],
        )

    def test_delete_204_must_be_followed_by_login_absence(self) -> None:
        responses = [
            (200, {"tokens": {"access_token": "fresh-token"}}),
            (204, None),
            (200, {"tokens": {"access_token": "unexpected-token"}}),
        ]
        with mock.patch.object(
            smoke, "request_with_status", side_effect=responses
        ):
            with self.assertRaisesRegex(
                smoke.SmokeFailure, "could still log in as alice@example.com"
            ):
                smoke.delete_registered_account(
                    "https://api.example", "alice@example.com"
                )

    def test_missing_cleanup_login_is_already_absent(self) -> None:
        for status in (401, 404):
            with self.subTest(status=status):
                with mock.patch.object(
                    smoke,
                    "request_with_status",
                    return_value=(status, {"error": {"code": "not_found"}}),
                ) as request_mock:
                    smoke.delete_registered_account(
                        "https://api.example", "alice@example.com"
                    )
                request_mock.assert_called_once()

    def test_cleanup_attempts_every_account_and_retries_failures(self) -> None:
        attempts: list[str] = []

        def fake_delete(_base_url: str, email: str) -> None:
            attempts.append(email)
            if email == "bob@example.com":
                raise smoke.SmokeFailure("forced cleanup failure")

        with (
            mock.patch.object(smoke, "delete_registered_account", side_effect=fake_delete),
            mock.patch.object(smoke.time, "sleep"),
        ):
            failures = smoke.cleanup_registered_accounts(
                "https://api.example",
                ["alice@example.com", "bob@example.com", "eve@example.com"],
            )

        self.assertEqual(
            attempts,
            [
                "eve@example.com",
                "bob@example.com",
                "bob@example.com",
                "bob@example.com",
                "alice@example.com",
            ],
        )
        self.assertEqual(len(failures), 1)
        self.assertIn("bob@example.com", failures[0])

    def test_run_cleans_registered_accounts_after_scenario_failure(self) -> None:
        cleaned: list[list[str]] = []

        def failing_scenario(
            _base_url: str,
            _expected_media_host: str | None,
            registered_emails: list[str],
        ) -> str:
            registered_emails.extend(["alice@example.com", "bob@example.com"])
            raise smoke.SmokeFailure("forced scenario failure")

        def fake_cleanup(_base_url: str, emails: list[str]) -> list[str]:
            cleaned.append(list(emails))
            return []

        with (
            mock.patch.object(smoke, "run_scenario", side_effect=failing_scenario),
            mock.patch.object(smoke, "cleanup_registered_accounts", side_effect=fake_cleanup),
        ):
            with self.assertRaisesRegex(smoke.SmokeFailure, "forced scenario failure"):
                smoke.run("https://api.example", None)

        self.assertEqual(cleaned, [["alice@example.com", "bob@example.com"]])

    def test_register_response_lost_still_records_candidate_for_cleanup(self) -> None:
        created_before_response_loss: list[str] = []
        cleaned: list[list[str]] = []

        def fake_request(
            _base_url: str,
            method: str,
            path: str,
            **_kwargs: object,
        ) -> object | None:
            if method == "GET" and path == "/health/ready":
                return {"status": "ready"}
            if method == "GET" and path == "/v1/me":
                return None
            if method == "POST" and path == "/v1/auth/password/reset/start":
                return {"error": {"code": "password_reset_unavailable"}}
            self.fail(f"unexpected request before registration: {method} {path}")

        def response_lost_register(_base_url: str, email: str) -> dict[str, object]:
            # The server committed the account, but the client did not receive
            # the response. The candidate must already be in the cleanup list.
            created_before_response_loss.append(email)
            raise smoke.SmokeFailure("registration response lost after commit")

        def capture_cleanup(_base_url: str, emails: list[str]) -> list[str]:
            cleaned.append(list(emails))
            return []

        with (
            mock.patch.object(smoke, "request", side_effect=fake_request),
            mock.patch.object(smoke, "register", side_effect=response_lost_register),
            mock.patch.object(
                smoke, "cleanup_registered_accounts", side_effect=capture_cleanup
            ),
        ):
            with self.assertRaisesRegex(
                smoke.SmokeFailure, "registration response lost after commit"
            ):
                smoke.run("https://api.example", None)

        self.assertEqual(cleaned, [created_before_response_loss])
        self.assertEqual(len(created_before_response_loss), 1)
        self.assertTrue(created_before_response_loss[0].endswith("-alice@example.com"))

    def test_delete_response_lost_then_login_unauthorized_is_clean(self) -> None:
        calls: list[tuple[str, str]] = []

        def fake_request_with_status(
            _base_url: str,
            method: str,
            path: str,
            **_kwargs: object,
        ) -> tuple[int, object | None]:
            calls.append((method, path))
            if len(calls) == 1:
                return 200, {"tokens": {"access_token": "fresh-token"}}
            if len(calls) == 2:
                raise smoke.SmokeFailure("delete response lost after commit")
            if len(calls) == 3:
                return 401, {"error": {"code": "invalid_credentials"}}
            self.fail(f"unexpected cleanup request: {method} {path}")

        with (
            mock.patch.object(
                smoke, "request_with_status", side_effect=fake_request_with_status
            ),
            mock.patch.object(smoke.time, "sleep"),
        ):
            failures = smoke.cleanup_registered_accounts(
                "https://api.example", ["alice@example.com"]
            )

        self.assertEqual(failures, [])
        self.assertEqual(
            calls,
            [
                ("POST", "/v1/auth/login"),
                ("DELETE", "/v1/me"),
                ("POST", "/v1/auth/login"),
            ],
        )

    def test_primary_and_cleanup_failures_are_both_reported(self) -> None:
        primary_error = smoke.SmokeFailure("primary scenario exploded")

        def failing_scenario(
            _base_url: str,
            _expected_media_host: str | None,
            registered_emails: list[str],
        ) -> str:
            registered_emails.append("alice@example.com")
            raise primary_error

        with (
            mock.patch.object(smoke, "run_scenario", side_effect=failing_scenario),
            mock.patch.object(
                smoke,
                "cleanup_registered_accounts",
                return_value=["alice@example.com: cleanup exploded"],
            ),
        ):
            with self.assertRaises(smoke.SmokeFailure) as raised:
                smoke.run("https://api.example", None)

        self.assertIn("primary scenario exploded", str(raised.exception))
        self.assertIn("cleanup exploded", str(raised.exception))
        self.assertIs(raised.exception.__cause__, primary_error)

    def test_primary_and_unexpected_cleanup_exception_are_both_reported(self) -> None:
        primary_error = smoke.SmokeFailure("primary scenario exploded")

        with (
            mock.patch.object(smoke, "run_scenario", side_effect=primary_error),
            mock.patch.object(
                smoke,
                "cleanup_registered_accounts",
                side_effect=RuntimeError("cleanup function exploded"),
            ),
        ):
            with self.assertRaises(smoke.SmokeFailure) as raised:
                smoke.run("https://api.example", None)

        self.assertIn("primary scenario exploded", str(raised.exception))
        self.assertIn("cleanup function exploded", str(raised.exception))
        self.assertIs(raised.exception.__cause__, primary_error)

    def test_run_fails_when_successful_scenario_cannot_clean_up(self) -> None:
        def successful_scenario(
            _base_url: str,
            _expected_media_host: str | None,
            registered_emails: list[str],
        ) -> str:
            registered_emails.append("alice@example.com")
            return "test-prefix"

        with (
            mock.patch.object(smoke, "run_scenario", side_effect=successful_scenario),
            mock.patch.object(
                smoke,
                "cleanup_registered_accounts",
                return_value=["alice@example.com: unavailable"],
            ),
        ):
            with self.assertRaisesRegex(smoke.SmokeFailure, "active test accounts may remain"):
                smoke.run("https://api.example", None)


if __name__ == "__main__":
    unittest.main()
