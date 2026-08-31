from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
HELPER = ROOT / "quiesce-cloudflared-rollback.sh"


FAKE_SYSTEMCTL = r"""#!/bin/sh
set -eu
command_name=$1
shift
printf '%s\n' "${command_name}" >> "${FAKE_LOG}"
case "${command_name}" in
  show)
    [ ! -e "${FAKE_STATE}/fail-show" ] || exit 91
    cat "${FAKE_STATE}/load"
    ;;
  stop)
    [ ! -e "${FAKE_STATE}/fail-stop" ] || exit 92
    printf 'inactive\n' > "${FAKE_STATE}/active"
    ;;
  is-active)
    state=$(cat "${FAKE_STATE}/active")
    printf '%s\n' "${state}"
    [ "${state}" = active ]
    ;;
  is-enabled)
    state=$(cat "${FAKE_STATE}/enabled")
    printf '%s\n' "${state}"
    [ "${state}" = enabled ]
    ;;
  disable)
    [ ! -e "${FAKE_STATE}/fail-disable" ] || exit 93
    printf 'disabled\n' > "${FAKE_STATE}/enabled"
    ;;
  *) exit 94 ;;
esac
"""


@unittest.skipIf(os.geteuid() == 0, "test override is intentionally forbidden for root")
class CloudflaredRollbackQuiesceTests(unittest.TestCase):
    def _run(
        self,
        *,
        load: str,
        active: str,
        enabled: str,
        saved_fragment: str,
        saved_enabled: str,
        saved_active: str,
        fail: str | None = None,
    ) -> tuple[subprocess.CompletedProcess[bytes], list[str], str, str]:
        with tempfile.TemporaryDirectory(prefix="clixor-cloudflared-rollback-") as raw:
            root = Path(raw)
            state = root / "state"
            state.mkdir()
            (state / "load").write_text(load + "\n", encoding="ascii")
            (state / "active").write_text(active + "\n", encoding="ascii")
            (state / "enabled").write_text(enabled + "\n", encoding="ascii")
            if fail is not None:
                (state / fail).touch()
            log = root / "calls"
            fake = root / "systemctl"
            fake.write_text(FAKE_SYSTEMCTL, encoding="ascii")
            fake.chmod(0o700)
            result = subprocess.run(
                [
                    "/bin/sh",
                    str(HELPER),
                    saved_fragment,
                    saved_enabled,
                    saved_active,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    **os.environ,
                    "CLIXOR_ROLLBACK_SYSTEMCTL_TEST_PATH": str(fake),
                    "FAKE_STATE": str(state),
                    "FAKE_LOG": str(log),
                },
                check=False,
            )
            calls = log.read_text(encoding="ascii").splitlines() if log.exists() else []
            final_active = (state / "active").read_text(encoding="ascii").strip()
            final_enabled = (state / "enabled").read_text(encoding="ascii").strip()
            return result, calls, final_active, final_enabled

    def test_prior_absent_and_current_absent_is_a_safe_noop(self) -> None:
        result, calls, active, enabled = self._run(
            load="not-found",
            active="inactive",
            enabled="not-found",
            saved_fragment="absent",
            saved_enabled="not-found",
            saved_active="inactive",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("stop", calls)
        self.assertNotIn("disable", calls)
        self.assertEqual((active, enabled), ("inactive", "not-found"))

    def test_loaded_candidate_over_absent_prior_is_stopped_and_disabled(self) -> None:
        result, calls, active, enabled = self._run(
            load="loaded",
            active="active",
            enabled="enabled",
            saved_fragment="absent",
            saved_enabled="not-found",
            saved_active="inactive",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(calls.index("stop"), calls.index("disable"))
        self.assertEqual((active, enabled), ("inactive", "disabled"))

    def test_loaded_disabled_prior_never_runs_disable_twice(self) -> None:
        result, calls, active, enabled = self._run(
            load="loaded",
            active="active",
            enabled="disabled",
            saved_fragment="/etc/systemd/system/cloudflared.service",
            saved_enabled="disabled",
            saved_active="inactive",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("stop", calls)
        self.assertNotIn("disable", calls)
        self.assertEqual((active, enabled), ("inactive", "disabled"))

    def test_enabled_active_prior_is_only_quiesced_before_full_restore(self) -> None:
        result, calls, active, enabled = self._run(
            load="loaded",
            active="active",
            enabled="enabled",
            saved_fragment="/etc/systemd/system/cloudflared.service",
            saved_enabled="enabled",
            saved_active="active",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("stop", calls)
        self.assertNotIn("disable", calls)
        self.assertEqual((active, enabled), ("inactive", "enabled"))

    def test_unknown_or_inconsistent_states_fail_closed(self) -> None:
        scenarios = (
            dict(load="", active="inactive", enabled="not-found", saved_fragment="absent", saved_enabled="not-found", saved_active="inactive"),
            dict(load="masked", active="inactive", enabled="disabled", saved_fragment="/etc/systemd/system/cloudflared.service", saved_enabled="disabled", saved_active="inactive"),
            dict(load="not-found", active="inactive", enabled="not-found", saved_fragment="/etc/systemd/system/cloudflared.service", saved_enabled="disabled", saved_active="inactive"),
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                result, _, _, _ = self._run(**scenario)
                self.assertNotEqual(result.returncode, 0)

    def test_failed_stop_or_disable_fails_closed(self) -> None:
        stop_failure, _, _, _ = self._run(
            load="loaded",
            active="active",
            enabled="enabled",
            saved_fragment="absent",
            saved_enabled="not-found",
            saved_active="inactive",
            fail="fail-stop",
        )
        self.assertNotEqual(stop_failure.returncode, 0)

        disable_failure, _, active, enabled = self._run(
            load="loaded",
            active="active",
            enabled="enabled",
            saved_fragment="absent",
            saved_enabled="not-found",
            saved_active="inactive",
            fail="fail-disable",
        )
        self.assertNotEqual(disable_failure.returncode, 0)
        self.assertEqual((active, enabled), ("inactive", "enabled"))


if __name__ == "__main__":
    unittest.main()
