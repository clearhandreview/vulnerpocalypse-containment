"""Offline catalog checks; no vendor servers contacted and no patches installed."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("catalog_tool", ROOT / "scripts" / "catalog.py")
catalog_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog_tool)


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = catalog_tool.load_catalog()

    def item(self, identifier):
        return catalog_tool.find_advisory(self.catalog, identifier)

    def test_catalog_has_seed_records(self):
        self.assertGreaterEqual(
            sum(len(item["cves"]) for item in self.catalog["advisories"]), 19)
        self.assertGreaterEqual(len(self.catalog["advisories"]), 8)
        self.assertIn("CVE-2026-98432", [
            cve for item in self.catalog["advisories"] for cve in item["cves"]])

    def test_attributed_cves_unique(self):
        cves = [x for item in self.catalog["advisories"] for x in item["cves"]]
        self.assertEqual(len(cves), len(set(cves)))

    def test_chrome_below_minimum(self):
        result = catalog_tool.assess(self.item("CVE-2026-118306"),
                                      "linux", "156.0.8078.47")
        self.assertEqual(result["result"], "below_published_release_floor")

    def test_chrome_at_minimum(self):
        result = catalog_tool.assess(self.item("CVE-2026-118306"),
                                      "macos", "156.0.8078.73")
        self.assertEqual(result["result"], "meets_published_release_floor")

    def test_chrome_newer_version(self):
        result = catalog_tool.assess(self.item("CVE-2026-113020"),
                                      "windows", "156.0.8078.79")
        self.assertEqual(result["result"], "meets_published_release_floor")

    def test_chrome_rejects_unparsable_version(self):
        result = catalog_tool.assess(self.item("CVE-2026-113020"),
                                      "windows", "156.beta;curl example.org")
        self.assertEqual(result["result"], "manual_vendor_confirmation_required")

    def test_other_platform_does_not_claim_fixed(self):
        result = catalog_tool.assess(self.item("CVE-2026-118306"),
                                      "android", "156.0.8078.99")
        self.assertEqual(result["result"], "manual_vendor_confirmation_required")

    def test_windows_26100_requires_client_server(self):
        result = catalog_tool.assess(self.item("CVE-2026-33096"),
                                      "windows", "10.0.26100.9000")
        self.assertEqual(result["result"], "manual_vendor_confirmation_required")

    def test_windows_26100_client_pass_server_fail(self):
        item = self.item("CVE-2026-33096")
        client = catalog_tool.assess(item, "windows", "10.0.26100.9000", "client")
        server = catalog_tool.assess(item, "windows", "10.0.26100.9000", "server")
        self.assertEqual(client["result"], "meets_published_release_floor")
        self.assertEqual(server["result"], "below_published_release_floor")

    def test_windows_unlisted_branch_unknown(self):
        result = catalog_tool.assess(self.item("CVE-2026-33096"),
                                      "windows", "10.0.99999.1")
        self.assertEqual(result["result"], "manual_vendor_confirmation_required")

    def test_apple_no_inferred_universal_version_rule(self):
        result = catalog_tool.assess(self.item("CVE-2026-43715"),
                                      "macos", "99.0.0.0")
        self.assertEqual(result["result"], "manual_vendor_confirmation_required")

    def test_linux_no_inferred_kernel_version_rule(self):
        result = catalog_tool.assess(self.item("CVE-2026-98432"),
                                      "linux", "7.3.1")
        self.assertEqual(result["result"], "manual_vendor_confirmation_required")

    def test_no_fabricated_android_cves(self):
        unresolved = next(e for e in self.catalog["unresolved"]
                          if e["id"] == "android-lockscreen-chain")
        self.assertEqual(unresolved["cves"], [])

    def test_validate_rejects_duplicate_id(self):
        import copy
        edited = copy.deepcopy(self.catalog)
        edited["advisories"].append(edited["advisories"][0])
        with self.assertRaisesRegex(ValueError, "Duplicate advisory id"):
            catalog_tool.validate_catalog(edited, ROOT / "data")

    def test_validate_rejects_path_escape(self):
        import copy
        edited = copy.deepcopy(self.catalog)
        item = self.item("CVE-2026-98432")
        for record in edited["advisories"]:
            if record["id"] == item["id"]:
                record["local_patch"] = "../../outside.patch"
        with self.assertRaisesRegex(ValueError, "relative"):
            catalog_tool.validate_catalog(edited, ROOT / "data")

    def test_validate_rejects_missing_unresolved(self):
        import copy
        edited = copy.deepcopy(self.catalog)
        del edited["unresolved"]
        with self.assertRaisesRegex(ValueError, "unresolved list"):
            catalog_tool.validate_catalog(edited, ROOT / "data")

    def test_validate_rejects_non_string_version_floor(self):
        import copy
        edited = copy.deepcopy(self.catalog)
        record = next(x for x in edited["advisories"]
                      if x["fix_type"] == "vendor_release")
        record["minimum_versions"][record["platforms"][0]] = 156
        with self.assertRaisesRegex(ValueError, "version string"):
            catalog_tool.validate_catalog(edited, ROOT / "data")

    def test_validate_rejects_non_string_platform(self):
        import copy
        edited = copy.deepcopy(self.catalog)
        edited["advisories"][0]["platforms"].append(123)
        with self.assertRaisesRegex(ValueError, "invalid platforms"):
            catalog_tool.validate_catalog(edited, ROOT / "data")

    def test_cli_list_and_inventory(self):
        from contextlib import redirect_stdout
        from io import StringIO
        for command in ("validate", "list", "inventory", "unresolved"):
            buf = StringIO()
            with redirect_stdout(buf):
                rc = catalog_tool.run([command])
            self.assertEqual(rc, 0)
            self.assertTrue(buf.getvalue())

    def test_cli_chrome_status_code(self):
        from contextlib import redirect_stdout
        from io import StringIO
        def call(version):
            with redirect_stdout(StringIO()):
                return catalog_tool.run([
                    "check", "CVE-2026-118331", "--platform", "linux",
                    "--version", version
                ])
        self.assertEqual(call("156.0.8078.79"), 0)
        self.assertEqual(call("155.0.8059.79"), 1)
        self.assertEqual(call("invalid"), 2)

    def test_tool_does_not_mutate_catalog(self):
        before = (ROOT / "data" / "advisories.json").read_bytes()
        catalog_tool.assess(self.item("CVE-2026-43715"), "ios", "26.7.0.0")
        self.assertEqual((ROOT / "data" / "advisories.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
