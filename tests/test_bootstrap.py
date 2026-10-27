"""Tests for the first-run bootstrap subsystem.

Built by Naman Kumar Sonker (@nksdev).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secauto.bootstrap import (
    STATE_FILENAME,
    STATE_VERSION,
    BootstrapState,
    Bootstrapper,
    state_path,
)
from secauto.config import Config
from secauto.logger import Logger


class BootstrapStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self._patch = mock.patch.dict(os.environ, {"SECAUTO_HOME": str(self.home)})
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmp.cleanup()

    def test_state_path_uses_managed_home(self) -> None:
        self.assertEqual(state_path().parent, self.home)
        self.assertEqual(state_path().name, STATE_FILENAME)

    def test_load_without_file_returns_defaults(self) -> None:
        state = BootstrapState.load()
        self.assertFalse(state.completed)
        self.assertEqual(state.installed, [])
        self.assertEqual(state.failed, [])
        self.assertEqual(state.skipped, [])
        self.assertEqual(state.version, STATE_VERSION)

    def test_save_and_load_round_trip(self) -> None:
        original = BootstrapState(
            completed=True,
            completed_at="2026-01-01T00:00:00+00:00",
            last_attempt_at="2026-01-01T00:00:00+00:00",
            installed=["nmap", "nikto"],
            failed=["nuclei"],
            skipped=["amass"],
            platform="darwin",
        )
        original.save()

        self.assertTrue(state_path().exists())
        loaded = BootstrapState.load()

        self.assertTrue(loaded.completed)
        # to_dict() sorts each list for stable on-disk output.
        self.assertEqual(loaded.installed, sorted(["nmap", "nikto"]))
        self.assertEqual(loaded.failed, ["nuclei"])
        self.assertEqual(loaded.skipped, ["amass"])
        self.assertEqual(loaded.platform, "darwin")

    def test_to_dict_carries_attribution(self) -> None:
        payload = BootstrapState().to_dict()
        self.assertEqual(payload["author"], "Naman Kumar Sonker")
        self.assertEqual(payload["initials"], "NKS")
        self.assertEqual(payload["version"], STATE_VERSION)

    def test_unknown_state_version_is_discarded(self) -> None:
        state_path().parent.mkdir(parents=True, exist_ok=True)
        state_path().write_text(
            json.dumps({"version": 999, "completed": True}), encoding="utf-8"
        )
        state = BootstrapState.load()
        self.assertFalse(state.completed)

    def test_corrupt_state_is_ignored(self) -> None:
        state_path().parent.mkdir(parents=True, exist_ok=True)
        state_path().write_text("{not valid json", encoding="utf-8")
        state = BootstrapState.load()
        self.assertFalse(state.completed)


class BootstrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self._patch = mock.patch.dict(os.environ, {"SECAUTO_HOME": str(self.home)})
        self._patch.start()
        self.config = Config()
        self.log = Logger(verbosity=0, color=False)

    def tearDown(self) -> None:
        self._patch.stop()
        self._tmp.cleanup()

    def test_is_complete_false_without_state(self) -> None:
        self.assertFalse(Bootstrapper(self.config, self.log).is_complete())

    def test_should_run_true_when_incomplete(self) -> None:
        self.assertTrue(Bootstrapper(self.config, self.log).should_run())

    def test_should_run_true_when_forced(self) -> None:
        boot = Bootstrapper(self.config, self.log)
        boot.state = BootstrapState(completed=True)
        self.assertTrue(boot.should_run(force=True))

    def test_should_run_false_when_offline(self) -> None:
        self.config.offline = True
        boot = Bootstrapper(self.config, self.log)
        boot.state = BootstrapState(completed=False)
        self.assertFalse(boot.should_run())

    def test_run_offline_skips_every_target(self) -> None:
        self.config.offline = True
        boot = Bootstrapper(self.config, self.log)

        before = boot.tools.discover(probe_versions=False)
        already = sorted(k for k, v in before.items() if v.available)
        absent = sorted(k for k, v in before.items() if not v.available)

        state = boot.run(quiet=True)

        # Offline mode never installs anything: absent tools land in `skipped`.
        self.assertFalse(state.completed)
        self.assertEqual(state.installed, already)
        self.assertEqual(state.skipped, absent)
        self.assertEqual(state.failed, [])
        self.assertTrue(state_path().exists())

        persisted = BootstrapState.load()
        self.assertEqual(persisted.skipped, state.skipped)
        self.assertEqual(persisted.installed, state.installed)

    def test_run_offline_does_not_invoke_installer(self) -> None:
        self.config.offline = True
        boot = Bootstrapper(self.config, self.log)
        with mock.patch.object(boot.tools, "install_one") as install_one:
            boot.run(quiet=True)
            install_one.assert_not_called()


if __name__ == "__main__":
    unittest.main()
