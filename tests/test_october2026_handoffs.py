"""Offline coverage and no-false-fix regression checks for October 30 advisories."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import catalog
import quickstart


class October2026HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.advisories = catalog.load_catalog()
        cls.profiles = quickstart.load()

    def item(self, cve):
        return catalog.find_advisory(self.advisories, cve)

    def test_new_cves_covered_once_with_vendor_references(self):
        ids = (
            "CVE-2026-107347", "CVE-2026-119168", "CVE-2026-76024",
            "CVE-2026-92744", "CVE-2026-103093", "CVE-2023-22793",
            "CVE-2026-107238", "CVE-2026-107239",
        )
        self.assertEqual(len(set(ids)), len(ids))
        for cve in ids:
            with self.subTest(cve=cve):
                item = self.item(cve)
                self.assertTrue(item["official_advisory"].startswith("https://"))
                self.assertIsNone(item["patch_url"])
                self.assertTrue(any(cve in profile["cves"] for profile in self.profiles["profiles"]))

    def test_nomad_community_2_1_0_not_mistaken_for_fixed(self):
        for cve in ("CVE-2026-107347", "CVE-2026-119168"):
            with self.subTest(cve=cve):
                item = self.item(cve)
                self.assertEqual(item["fixed_releases"]["Community"], "2.1.1")
                self.assertEqual(item["fixed_releases"]["Enterprise 2.1"], "2.1.0+ent")
                self.assertEqual(
                    catalog.assess(item, "linux", "2.1.0.0")["result"],
                    "manual_vendor_confirmation_required",
                )

    def test_chrome_critical_media_stream_floor(self):
        item = self.item("CVE-2026-76024")
        for platform in ("linux", "windows", "macos"):
            with self.subTest(platform=platform):
                self.assertEqual(
                    catalog.assess(item, platform, "156.0.8078.78")["result"],
                    "below_published_release_floor",
                )
                self.assertEqual(
                    catalog.assess(item, platform, "156.0.8078.79")["result"],
                    "meets_published_release_floor",
                )
        self.assertEqual(
            catalog.assess(item, "android", "156.0.8078.80")["result"],
            "manual_vendor_confirmation_required",
        )

    def test_delinea_is_windows_only_and_requires_manual_version_review(self):
        item = self.item("CVE-2026-92744")
        self.assertEqual(item["fixed_releases"]["Windows agent 12.x"], "12.0.5804")
        self.assertEqual(item["fixed_releases"]["Windows agent 13.x"], "13.0.2064")
        self.assertEqual(
            catalog.assess(item, "windows", "13.0.1058")["result"],
            "manual_vendor_confirmation_required",
        )
        self.assertEqual(quickstart.select(self.profiles, "linux", "CVE-2026-92744"), [])
        matched = quickstart.select(self.profiles, "windows", "CVE-2026-92744")
        self.assertEqual(len(matched), 1)
        self.assertIn("5593", " ".join(matched[0]["steps"]))
        self.assertIn("poll", matched[0]["limitations"])

    def test_servicenow_service_not_local_os_patch(self):
        item = self.item("CVE-2026-103093")
        self.assertEqual(item["platforms"], ["service"])
        self.assertEqual(
            catalog.assess(item, "windows", "10.0.26100.1")["result"],
            "manual_vendor_confirmation_required",
        )
        self.assertEqual(len(quickstart.select(self.profiles, "service", "CVE-2026-103093")), 1)
        self.assertEqual(quickstart.select(self.profiles, "windows", "CVE-2026-103093"), [])

    def test_veeam_floor_and_supported_source_upgrade(self):
        for cve in ("CVE-2023-22793", "CVE-2026-107238", "CVE-2026-107239"):
            with self.subTest(cve=cve):
                item = self.item(cve)
                self.assertEqual(
                    catalog.assess(item, "windows", "9.1.0.3107")["result"],
                    "below_published_release_floor",
                )
                self.assertEqual(
                    catalog.assess(item, "windows", "13.1.0.334")["result"],
                    "meets_published_release_floor",
                )
                self.assertEqual(
                    catalog.assess(item, "linux", "13.1.0.334")["result"],
                    "manual_vendor_confirmation_required",
                )
        profile = quickstart.select(self.profiles, "windows", "CVE-2026-107239")[0]
        self.assertIn("9.1.0.3107", " ".join(profile["before"]))
        self.assertTrue(profile["undo"])

    def test_malformed_fixed_release_branches_are_rejected(self):
        edited = json.loads(json.dumps(self.advisories))
        for entry in edited["advisories"]:
            if entry["id"] == "nomad-cve-2026-107347":
                entry["fixed_releases"] = {"Community": None}
                break
        with self.assertRaisesRegex(ValueError, "invalid fixed_releases"):
            catalog.validate_catalog(edited, ROOT / "data")

    def test_read_only_assessments_do_not_modify_catalogs(self):
        files = (ROOT / "data/advisories.json", ROOT / "data/containments.json")
        before = [p.read_bytes() for p in files]
        for cve, platform, version in (
            ("CVE-2026-107347", "linux", "2.1.1"),
            ("CVE-2026-76024", "windows", "156.0.8078.79"),
            ("CVE-2026-92744", "windows", "13.0.2064"),
            ("CVE-2026-103093", "service", "Zurich Patch 12"),
        ):
            catalog.assess(self.item(cve), platform, version)
            quickstart.select(self.profiles, platform, cve)
        self.assertEqual(before, [p.read_bytes() for p in files])


if __name__ == "__main__":
    unittest.main()
