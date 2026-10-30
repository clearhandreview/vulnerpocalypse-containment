"""Offline controls and handoff gates; no host kernel modifications."""
from __future__ import annotations
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import mptcp_guard
import quickstart
import vendor_handoff

class ContainmentCatalogTests(unittest.TestCase):
    def test_all_profiles_have_procedures(self):
        self.assertGreaterEqual(len(quickstart.load()["profiles"]), 5)

    def test_only_existing_profiles_returned(self):
        data = quickstart.load()
        self.assertEqual(1, len(quickstart.select(data, "linux", "CVE-2026-98432")))
        self.assertEqual([], quickstart.select(data, "ios", "CVE-2026-98432"))

    def test_unknown_system_rejected(self):
        with self.assertRaises(ValueError):
            quickstart.select(quickstart.load(), "unknown-os")

    def test_no_fake_claim_for_unmapped_android(self):
        matches = quickstart.select(quickstart.load(), "android")
        self.assertEqual(1, len(matches))
        self.assertEqual([], matches[0]["cves"])
        self.assertIn("UNKNOWN", " ".join(matches[0]["check"]))

    def test_empty_references_fail(self):
        data = json.loads(json.dumps(quickstart.load()))
        data["profiles"][0]["references"] = []
        with self.assertRaises(ValueError):
            quickstart.validate(data)

    def test_invalid_reference_fail(self):
        data = json.loads(json.dumps(quickstart.load()))
        data["profiles"][0]["references"] = ["http://malicious.invalid"]
        with self.assertRaises(ValueError):
            quickstart.validate(data)

    def test_readable_install_undo_and_verification(self):
        profile = quickstart.load()["profiles"][0]
        guide = quickstart.render(profile)
        for heading in ("Before:", "Install the temporary control:",
                        "How to verify it is active:", "Switch to the vendor fix and undo:"):
            self.assertIn(heading, guide)

    def test_reject_fake_fixed_claim(self):
        data = json.loads(json.dumps(quickstart.load()))
        data["profiles"][0]["confidence"] = "patched_by_us"
        with self.assertRaises(ValueError):
            quickstart.validate(data)

    def test_reject_nonobject_catalog(self):
        with self.assertRaisesRegex(ValueError, "Unsupported containment schema"):
            quickstart.validate([])

    def test_reject_non_string_platform(self):
        data = json.loads(json.dumps(quickstart.load()))
        data["profiles"][0]["platforms"].append({"name": "linux"})
        with self.assertRaisesRegex(ValueError, "Bad platforms"):
            quickstart.validate(data)

    def test_reject_invalid_cve(self):
        data = json.loads(json.dumps(quickstart.load()))
        data["profiles"][0]["cves"] = ["not-a-cve"]
        with self.assertRaisesRegex(ValueError, "Invalid CVE"):
            quickstart.validate(data)

class HandoffTests(unittest.TestCase):
    def test_version_only_cannot_release(self):
        r = vendor_handoff.evaluate("CVE-2026-33096", "windows", "10.0.22631.6936",
                                    "", False, False, False)
        self.assertEqual("HOLD_OR_MANUAL_VENDOR_REVIEW", r["handoff"])

    def test_three_attestations_allow_review_not_auto_undo(self):
        r = vendor_handoff.evaluate("CVE-2026-33096", "windows", "10.0.22631.6936",
                                    "", True, True, True)
        self.assertEqual("READY_FOR_CHANGE_REVIEW", r["handoff"])
        self.assertIn("Never proof", r["scope"])

    def test_old_floor_holds_even_with_attestations(self):
        r = vendor_handoff.evaluate("CVE-2026-33096", "windows", "10.0.22631.1",
                                    "", True, True, True)
        self.assertEqual("HOLD_OR_MANUAL_VENDOR_REVIEW", r["handoff"])

    def test_linux_requires_independent_vendor_review(self):
        r = vendor_handoff.evaluate("CVE-2026-98432", "linux", "7.3.0.0",
                                    "", True, True, True)
        self.assertEqual("HOLD_OR_MANUAL_VENDOR_REVIEW", r["handoff"])

    def test_windows_server_variant(self):
        r = vendor_handoff.evaluate("CVE-2026-33096", "windows", "10.0.26100.8246",
                                    "server", True, True, True)
        self.assertEqual("HOLD_OR_MANUAL_VENDOR_REVIEW", r["handoff"])

class CrossPlatformGuardTests(unittest.TestCase):
    def test_non_linux_guard_exits_before_touching_kernel_paths(self):
        for system in ("Windows", "Darwin"):
            with self.subTest(system=system):
                with patch.object(mptcp_guard.platform, "system", return_value=system), \
                        patch.object(mptcp_guard, "MPTCPGuard") as guard_class:
                    self.assertEqual(
                        2,
                        mptcp_guard.main(["apply", "--accept-service-disruption"]),
                    )
                    guard_class.assert_not_called()


@unittest.skipUnless(os.name == "posix", "requires POSIX file permission semantics")
class LinuxGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.p = Path(self.tmp.name)
        self.knob = self.p / "enabled"
        self.knob.write_text("1\n")
        self.boot = self.p / "boot"
        self.boot.write_text("boot-one\n")
        self.netns = self.p / "netns"
        self.netns.write_text("test namespace")
        self.state = self.p / "guard.state"
        self.guard = mptcp_guard.MPTCPGuard(self.knob, self.state, self.boot, self.netns)
        self.guard._readlink = lambda path: "net:[test]"

    def test_status_is_read_only(self):
        self.assertTrue(self.guard.status()["mptcp_new_sockets_enabled"])
        self.assertEqual("1", self.knob.read_text().strip())
        self.assertFalse(self.state.exists())

    def test_apply_and_rollback(self):
        self.assertIn("disabled", self.guard.apply(True))
        self.assertEqual("0", self.knob.read_text().strip())
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        self.assertIn("restored", self.guard.rollback(True))
        self.assertEqual("1", self.knob.read_text().strip())
        self.assertFalse(self.state.exists())

    def test_apply_without_ack_no_change(self):
        with self.assertRaises(mptcp_guard.GuardError):
            self.guard.apply(False)
        self.assertEqual("1", self.knob.read_text().strip())

    def test_rollback_without_ack_no_change(self):
        self.guard.apply(True)
        with self.assertRaises(mptcp_guard.GuardError):
            self.guard.rollback(False)
        self.assertEqual("0", self.knob.read_text().strip())

    def test_no_overwrite_existing_state(self):
        self.guard.apply(True)
        with self.assertRaises(mptcp_guard.GuardError):
            self.guard.apply(True)
        self.assertEqual("0", self.knob.read_text().strip())

    def test_no_takeover_if_already_disabled(self):
        self.knob.write_text("0\n")
        self.assertIn("already_disabled", self.guard.apply(True))
        self.assertFalse(self.state.exists())

    def test_refuse_on_stale_boot(self):
        self.guard.apply(True)
        self.boot.write_text("boot-two\n")
        with self.assertRaises(mptcp_guard.GuardError):
            self.guard.rollback(True)
        self.assertEqual("0", self.knob.read_text().strip())

    def test_refuse_if_operator_changed_knob(self):
        self.guard.apply(True)
        self.knob.write_text("1\n")
        with self.assertRaises(mptcp_guard.GuardError):
            self.guard.rollback(True)
        self.assertTrue(self.state.exists())

    def test_refuse_tampered_state(self):
        self.guard.apply(True)
        self.state.write_text('{"schema": 1, "prior": "0"}')
        with self.assertRaises(mptcp_guard.GuardError):
            self.guard.rollback(True)

    def test_refuse_unknown_knob(self):
        self.knob.write_text("x\n")
        with self.assertRaises(mptcp_guard.GuardError):
            self.guard.apply(True)
        self.assertFalse(self.state.exists())

    def test_refuse_symlink_state(self):
        try:
            self.state.symlink_to(self.boot)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not supported in this OS/test environment")
        with self.assertRaises(mptcp_guard.GuardError):
            self.guard.apply(True)

if __name__ == "__main__":
    unittest.main()
