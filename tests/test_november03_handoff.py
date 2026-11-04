"""Offline validation for the November 3 research handoff and product-specific CVE records."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / "scripts" / "research_handoff.py"
spec = importlib.util.spec_from_file_location("research_handoff", source)
assert spec and spec.loader
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)

sys.path.insert(0, str(ROOT / "scripts"))
import catalog
import quickstart


class November03HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = handoff.load()
        cls.catalog = catalog.load_catalog()
        cls.profiles = quickstart.load()

    def test_all_source_records_retained_without_execution(self):
        self.assertEqual(len(self.ledger["records"]), 64)
        for item in self.ledger["records"]:
            with self.subTest(id=item["id"]):
                self.assertTrue(item["primary_source_url"].startswith("https://"))
                self.assertEqual(item["remediation_automation_ready"], "No")
                self.assertFalse(item["automation_allowed"])
                self.assertFalse(item["patch_applied"])
                self.assertFalse(item["deployment_verified"])

    def test_30_new_cves_in_catalog_and_profiles(self):
        ids = [
            r["id"] for r in self.ledger["records"]
            if r["record_scope"] == "Detailed CVE record"
            and r["id"] not in {
                "CVE-2026-111357", "CVE-2026-111497", "CVE-2026-107347",
                "CVE-2026-119168", "CVE-2026-98432", "CVE-2026-92744",
                "CVE-2026-115828", "CVE-2026-115829", "CVE-2026-115830",
                "CVE-2026-103093", "CVE-2023-22793", "CVE-2026-107238",
                "CVE-2026-107239", "CVE-2026-76024",
                "CVE-2026-119086", "CVE-2026-119116",
                "CVE-2026-119148", "CVE-2026-119117",
            }
        ]
        self.assertEqual(len(ids), 30)
        for cve in ids:
            with self.subTest(cve=cve):
                item = catalog.find_advisory(self.catalog, cve)
                self.assertIsNone(item["patch_url"])
                self.assertNotEqual(item["fix_type"], "vendor_release")
                self.assertEqual(len([p for p in self.profiles["profiles"] if cve in p["cves"]]), 1)

    def test_qt_coap_supported_and_unsupported_trains(self):
        item = catalog.find_advisory(self.catalog, "CVE-2026-103653")
        for below, fixed in (("6.8.8", "6.8.9"), ("6.11.2", "6.11.3")):
            self.assertEqual(catalog.assess(item, "service", below)["result"],
                             "below_published_release_floor")
            self.assertEqual(catalog.assess(item, "service", fixed)["result"],
                             "meets_published_release_floor")
        self.assertEqual(catalog.assess(item, "service", "6.12.0")["result"],
                         "meets_published_release_floor")
        for platform, version in (("service", "6.9.9"), ("linux", "6.8.9"),
                                  ("service", "6.8.8.9rc"), ("service", "6.13.0")):
            self.assertEqual(catalog.assess(item, platform, version)["result"],
                             "manual_vendor_confirmation_required")

    def test_firmware_and_unknown_fixed_versions_do_not_auto_pass(self):
        for cve in ("CVE-2026-116606", "CVE-2026-111560",
                    "CVE-2026-107441", "CVE-2026-97631",
                    "CVE-2026-120534", "CVE-2026-89292"):
            item = catalog.find_advisory(self.catalog, cve)
            self.assertEqual(catalog.assess(item, item["platforms"][0], "99.99.99")["result"],
                             "manual_vendor_confirmation_required")

    def test_ghsa_uncertain_and_watch_items_not_promoted_to_cves(self):
        known = [cve for item in self.catalog["advisories"] for cve in item["cves"]]
        self.assertEqual(len(known), len(set(known)))
        for identifier in ("GHSA-c46f-4v9j-5gpc", "GHSA-xv5x-242w-7hf7",
                           "CURSOR-2026-10-29", "CVE-2026-89293"):
            row = handoff.get(self.ledger, identifier)
            self.assertNotEqual(row["record_scope"], "Detailed CVE record")
            if identifier.startswith("CVE-"):
                self.assertNotIn(identifier, known)

    def test_plan_never_grants_its_own_permission(self):
        for identifier in ("CVE-2026-103653", "CVE-2026-120534",
                           "GHSA-c46f-4v9j-5gpc"):
            with self.subTest(identifier=identifier):
                p = handoff.plan(handoff.get(self.ledger, identifier), "windows")
                self.assertEqual(len(p["stages"]), 6)
                self.assertFalse(p["execution_enabled"])
                self.assertFalse(p["ready_for_production_change"])
                self.assertFalse(p["patch_applied"])
                self.assertFalse(p["tested_on_device"])
                self.assertIn("unknown", p["applicability"])

    def test_schema_refuses_tampered_execution_claims(self):
        edited = copy.deepcopy(self.ledger)
        edited["records"][0]["patch_applied"] = True
        with self.assertRaisesRegex(ValueError, "Unsupported execution"):
            handoff.validate(edited)
        edited = copy.deepcopy(self.ledger)
        edited["records"][0]["remediation_automation_ready"] = "Yes"
        with self.assertRaisesRegex(ValueError, "Unsupported remediation readiness"):
            handoff.validate(edited)
        edited = copy.deepcopy(self.ledger)
        edited["records"][0]["id"] = "CVE-2026-97229; rm -rf /"
        with self.assertRaisesRegex(ValueError, "Invalid or duplicate"):
            handoff.validate(edited)
        edited = copy.deepcopy(self.ledger)
        edited["records"][0]["primary_source_url"] = "file:///etc/passwd"
        with self.assertRaisesRegex(ValueError, "Invalid evidence URL"):
            handoff.validate(edited)

    def test_cli_read_only_and_offline(self):
        script = str(ROOT / "scripts" / "research_handoff.py")
        for command in ("validate", "list", "show CVE-2026-103653",
                        "plan GHSA-c46f-4v9j-5gpc --os macos"):
            result = subprocess.run(
                [sys.executable, script, *command.split()],
                cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
        from contextlib import redirect_stdout
        import io
        for output in ("list", "show", "plan"):
            with self.subTest(output=output):
                stream = io.StringIO()
                args = [output] if output == "list" else [output, "CVE-2026-103653"]
                with redirect_stdout(stream):
                    self.assertEqual(handoff.main(args), 0)
                stream.getvalue().encode("ascii")
        bad = subprocess.run([sys.executable, script, "show", "INVALID"],
                             cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(bad.returncode, 2)


if __name__ == "__main__":
    unittest.main()
