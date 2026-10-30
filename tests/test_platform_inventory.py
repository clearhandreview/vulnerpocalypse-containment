"""Read-only platform breadth, safe fallbacks, and no-false-patch tests."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import platform_inventory
import catalog


class PlatformInventoryTests(unittest.TestCase):
    def test_os_release_quotes_are_parsed_without_execution(self):
        sample = ('NAME="Example Linux"\nID=alpine\nVERSION_ID="3.23"\n'
                  'PRETTY_NAME="Alpine Linux v3.23"\n'
                  'INJECTED="$(touch /tmp/should-not-exist)"\n')
        values = platform_inventory.parse_os_release(sample)
        self.assertEqual(values["PRETTY_NAME"], "Alpine Linux v3.23")
        self.assertEqual(values["INJECTED"], "$(touch /tmp/should-not-exist)")

    def test_distinct_linux_distribution_routes(self):
        examples = {
            "ubuntu": ("debian", "apt"),
            "debian": ("debian", "apt"),
            "raspbian": ("debian", "apt"),
            "fedora": ("fedora_rhel", "dnf"),
            "rocky": ("fedora_rhel", "dnf"),
            "opensuse-tumbleweed": ("suse", "zypper"),
            "arch": ("arch", "pacman"),
            "alpine": ("alpine", "apk"),
            "void": ("void", "xbps-install"),
            "gentoo": ("gentoo", "emerge"),
            "nixos": ("nixos", "nixos-rebuild"),
        }
        for distro, (family, tool) in examples.items():
            with self.subTest(distro=distro):
                result = platform_inventory.distro_from_os_release({"ID": distro})
                self.assertEqual((result["family"], result["common_update_tool"]), (family, tool))
                self.assertEqual(result["route_basis"], "known_distribution_id")

    def test_unknown_derivative_gets_hint_not_parent_update_command(self):
        result = platform_inventory.distro_from_os_release({
            "ID": "sampleos", "ID_LIKE": "ubuntu debian",
        })
        self.assertEqual(result["family"], "debian")
        self.assertEqual(result["route_basis"], "id_like_hint_only")
        self.assertIsNone(result["common_update_tool"])

    def test_atomic_and_vendor_managed_image_requires_distinct_route(self):
        atomic = platform_inventory.distro_from_os_release({
            "ID": "fedora", "VARIANT_ID": "silverblue"
        })
        self.assertEqual(atomic["common_update_tool"], "rpm-ostree")
        for distro in ("bottlerocket", "flatcar", "steamos"):
            with self.subTest(distro=distro):
                managed = platform_inventory.distro_from_os_release({"ID": distro})
                self.assertEqual(managed["route_basis"], "vendor_managed")
                self.assertIsNone(managed["common_update_tool"])

    def test_unknown_os_release_does_not_infer_distribution(self):
        result = platform_inventory.distro_from_os_release({})
        self.assertEqual(result["family"], "unknown")
        self.assertIsNone(result["common_update_tool"])

    def test_linux_host_inventory_uses_fixture_without_running_tools(self):
        with tempfile.TemporaryDirectory() as temp:
            top = Path(temp)
            etc = top / "etc/os-release"
            etc.parent.mkdir(parents=True)
            etc.write_text('ID="void"\nPRETTY_NAME="Void Linux"\n', encoding="utf-8")
            dmi = top / "sys/class/dmi/id"
            dmi.mkdir(parents=True)
            (dmi / "sys_vendor").write_text("Test OEM\n", encoding="utf-8")
            (dmi / "product_name").write_text("Test Device\n", encoding="utf-8")
            (dmi / "product_serial").write_text("PRIVATE_SERIAL\n", encoding="utf-8")
            with patch.object(platform_inventory.shutil, "which",
                              side_effect=lambda name: "/usr/bin/" + name if name in
                              {"python3", "gcc", "fwupdmgr"} else None):
                result = platform_inventory.collect_inventory(
                    system="Linux", os_release=etc, sysfs_root=top / "sys",
                    proc_root=top / "proc", environment={},
                )
            self.assertEqual(result["linux_distribution"]["common_update_tool"], "xbps-install")
            self.assertEqual(result["hardware"]["manufacturer"], "Test OEM")
            self.assertTrue(result["hardware"]["fwupd_cli_detected"])
            self.assertEqual(result["hardware"]["firmware_fix_status"], "unknown")
            self.assertEqual(result["fix_status"], "unknown")
            self.assertEqual(result["toolchains"]["Python"]["detected_commands"], ["python3"])
            self.assertEqual(result["toolchains"]["C"]["detected_commands"], ["gcc"])
            self.assertEqual(result["package_tool_commands"]["OS package managers"], [])
            self.assertIn("did not enumerate", result["software_inventory_limit"])
            self.assertNotIn("PRIVATE_SERIAL", json.dumps(result))
            self.assertNotIn("product_serial", json.dumps(result))
            self.assertNotIn("patch_applied", json.dumps(result))

    def test_android_does_not_claim_to_be_a_desktop_linux_distribution(self):
        with patch.object(platform_inventory.shutil, "which", return_value=None):
            result = platform_inventory.collect_inventory(
                system="Linux", environment={"ANDROID_ROOT": "/system"})
        self.assertEqual(result["system"], "Android")
        self.assertIsNone(result["linux_distribution"])
        self.assertEqual(result["fix_status"], "unknown")

    def test_windows_and_macos_remain_read_only_without_linux_routes(self):
        with patch.object(platform_inventory.shutil, "which", return_value=None):
            for system in ("Windows", "Darwin"):
                with self.subTest(system=system):
                    result = platform_inventory.collect_inventory(system=system, environment={})
                    self.assertNotIn("linux_distribution", result)
                    self.assertEqual(result["hardware"]["firmware_fix_status"], "unknown")

    def test_catalog_inventory_integrates_new_read_only_path(self):
        with patch.object(catalog, "collect_inventory", return_value={
            "system": "Linux", "fix_status": "unknown",
            "linux_distribution": {"id": "alpine"}}):
            from contextlib import redirect_stdout
            from io import StringIO
            stream = StringIO()
            with redirect_stdout(stream):
                status = catalog.run(["inventory"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stream.getvalue())["linux_distribution"]["id"], "alpine")


if __name__ == "__main__":
    unittest.main()
