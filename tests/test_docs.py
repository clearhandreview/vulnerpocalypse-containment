"""Offline release documentation checks."""
from pathlib import Path
import hashlib
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ReleaseDocsTests(unittest.TestCase):
    def test_easy_install_has_major_devices(self):
        t = (ROOT / "docs/EASY_INSTALL.md").read_text()
        for name in ("Windows", "Mac", "iPhone", "Android", "Linux", "Google Chrome", "watchOS", "ChromeOS"):
            with self.subTest(name=name):
                self.assertIn(name, t)

    def test_vendor_handoff_is_documented(self):
        for fname in ("README.md", "docs/EASY_INSTALL.md", "docs/EMERGENCY_CONTAINMENT.md", "docs/VALIDATION.md"):
            self.assertIn("vendor", (ROOT / fname).read_text().lower())

    def test_linux_guard_ack_and_rollback_in_docs(self):
        t = (ROOT / "docs/EASY_INSTALL.md").read_text()
        self.assertIn("--accept-service-disruption", t)
        self.assertIn("--accept-reexposure", t)
        self.assertIn("namespace", t)

    def test_no_unclaimed_cross_os_automation(self):
        t = (ROOT / "docs/PLATFORM_COVERAGE.md").read_text()
        self.assertIn("does **not** certify", t)
        self.assertIn("Opt-in Linux MPTCP sysctl only", t)

    def test_local_link_targets_from_readme(self):
        t = (ROOT / "README.md").read_text()
        for target in re.findall(r"\]\(([^)]+)\)", t):
            if target.startswith(("https://", "http://", "#", "mailto:")):
                continue
            with self.subTest(target=target):
                self.assertTrue((ROOT / target).is_file(), target)

    def test_release_checksums_match_files(self):
        for line in (ROOT / "SHA256SUMS").read_text().splitlines():
            expected, relative = line.split(None, 1)
            target = ROOT / relative
            with self.subTest(target=relative):
                self.assertTrue(target.is_file(), relative)
                self.assertEqual(expected, hashlib.sha256(target.read_bytes()).hexdigest())

    def test_ci_covers_host_oses_and_supported_python_lines(self):
        workflow = (ROOT / ".github/workflows/tests.yml").read_text()
        for os_name in ("ubuntu-latest", "windows-latest", "macos-latest"):
            with self.subTest(os=os_name):
                self.assertIn(os_name, workflow)
        for version in ("3.11", "3.12", "3.13", "3.14", "3.15"):
            with self.subTest(python=version):
                self.assertIn(f'"{version}"', workflow)

if __name__ == "__main__":
    unittest.main()
