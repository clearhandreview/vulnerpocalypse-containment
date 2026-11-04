"""Ensure historical advisory coverage survives the November 3 merge."""
from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
TRACKED = {
    "CVE-2026-20127",
    "CVE-2026-104935",
    "CVE-2026-94127",
    "CVE-2026-93952",
    "CVE-2026-76504",
    "CVE-2026-102764",
    "CVE-2026-110447",
    "CVE-2026-119086",
    "CVE-2026-119116",
    "CVE-2026-119148",
    "CVE-2026-119117",
    "CVE-2026-115830",
    "CVE-2026-115829",
    "CVE-2026-115828",
    "CVE-2026-111357",
    "CVE-2026-111497",
}


class PriorCoverageTests(unittest.TestCase):
    def test_previous_advisory_coverage_present_and_unique(self):
        catalog = json.loads((ROOT / "data" / "advisories.json").read_text(encoding="utf-8"))
        owners = [cve for item in catalog["advisories"] for cve in item["cves"]]
        self.assertEqual(len(owners), len(set(owners)))
        self.assertTrue(TRACKED <= set(owners), TRACKED - set(owners))

    def test_previous_containment_coverage_present_and_nonexecuting(self):
        catalog = json.loads((ROOT / "data" / "containments.json").read_text(encoding="utf-8"))
        guides = catalog["profiles"]
        covered = {cve for guide in guides for cve in guide["cves"]}
        self.assertTrue(TRACKED <= covered, TRACKED - covered)
        for guide in guides:
            if TRACKED.intersection(guide["cves"]):
                self.assertFalse(guide.get("execution_enabled", False))
                self.assertFalse(guide.get("patch_applied", False))


if __name__ == "__main__":
    unittest.main()
