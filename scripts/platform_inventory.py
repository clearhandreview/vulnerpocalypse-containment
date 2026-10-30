#!/usr/bin/env python3
"""Read-only host, distribution, runtime and firmware-context inventory.

Presence of a tool or an update route is not evidence of an installed CVE fix.
No discovered executables are launched.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import sys

# IDs come from os-release. Derivatives that only advertise ID_LIKE are
# intentionally not given copy-and-paste parent-distribution commands.
DISTRO_ROUTES = {
    "debian": ("debian", "apt"), "ubuntu": ("debian", "apt"),
    "raspbian": ("debian", "apt"), "linuxmint": ("debian", "apt"),
    "pop": ("debian", "apt"), "kali": ("debian", "apt"),
    "fedora": ("fedora_rhel", "dnf"), "rhel": ("fedora_rhel", "dnf"),
    "rocky": ("fedora_rhel", "dnf"), "almalinux": ("fedora_rhel", "dnf"),
    "centos": ("fedora_rhel", "dnf"), "ol": ("fedora_rhel", "dnf"),
    "amzn": ("fedora_rhel", "dnf"),
    "opensuse-leap": ("suse", "zypper"),
    "opensuse-tumbleweed": ("suse", "zypper"),
    "opensuse": ("suse", "zypper"), "sles": ("suse", "zypper"),
    "sled": ("suse", "zypper"),
    "arch": ("arch", "pacman"), "manjaro": ("arch", "pacman"),
    "endeavouros": ("arch", "pacman"),
    "alpine": ("alpine", "apk"),
    "void": ("void", "xbps-install"),
    "gentoo": ("gentoo", "emerge"),
    "nixos": ("nixos", "nixos-rebuild"),
}

# Do not silently apply an ordinary desktop update method to immutable,
# container-focused, or vendor-appliance images.
VENDOR_MANAGED = {
    "bottlerocket", "flatcar", "steamos", "chromeos",
    "photon", "azurelinux", "mariner",
}
ATOMIC_VARIANTS = {"silverblue", "kinoite", "sericea", "onyx",
                   "sway-atomic", "budgie-atomic"}

TOOLCHAINS = {
    "Python": ("python3", "python"),
    "JavaScript/TypeScript": ("node", "deno", "bun"),
    "Go": ("go",),
    "Rust": ("rustc", "cargo"),
    "Java": ("java", "javac"),
    "C": ("gcc", "clang", "cc"),
    "C++": ("g++", "clang++", "c++"),
    "C#/.NET": ("dotnet",),
    "Ruby": ("ruby",),
    "PHP": ("php",),
    "Perl": ("perl",),
    "Lua": ("lua", "luajit"),
    "Swift": ("swift",),
    "Kotlin": ("kotlinc",),
    "Dart": ("dart",),
    "R": ("R",),
    "Julia": ("julia",),
    "Elixir": ("elixir",),
    "Erlang": ("erl",),
    "Haskell": ("ghc",),
    "Zig": ("zig",),
    "Shell": ("bash", "zsh", "fish", "pwsh"),
}

PACKAGE_TOOLS = {
    "OS package managers": (
        "apt-get", "dnf", "yum", "zypper", "pacman", "apk",
        "xbps-install", "emerge", "nixos-rebuild", "rpm-ostree",
        "flatpak", "snap", "brew", "winget", "choco",
    ),
    "Language dependency managers": (
        "pip", "pip3", "uv", "poetry", "npm", "pnpm", "yarn",
        "cargo", "mvn", "gradle", "gem", "bundle", "composer",
        "dotnet", "go", "conda", "mix", "dart",
    ),
}

_OS_RELEASE_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")


def parse_os_release(raw: str) -> dict[str, str]:
    """Parse os-release without interpreting its contents as shell code."""
    values: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not _OS_RELEASE_KEY.fullmatch(key):
            continue
        try:
            tokens = shlex.split(value, posix=True)
        except ValueError:
            continue
        if len(tokens) == 1:
            values[key] = tokens[0]
        elif value == "":
            values[key] = ""
    return values


def distro_from_os_release(values: dict[str, str]) -> dict:
    distro_id = values.get("ID", "").lower()
    variant = values.get("VARIANT_ID", "").lower()
    parent_ids = values.get("ID_LIKE", "").lower().split()
    family, update_tool = DISTRO_ROUTES.get(distro_id, ("unknown", None))
    route_basis = "known_distribution_id" if update_tool else "unknown"
    if distro_id in VENDOR_MANAGED:
        family, update_tool, route_basis = "vendor_managed", None, "vendor_managed"
    elif distro_id == "fedora" and variant in ATOMIC_VARIANTS:
        family, update_tool, route_basis = "fedora_atomic", "rpm-ostree", "known_atomic_variant"
    elif not update_tool:
        for parent_id in parent_ids:
            if parent_id in DISTRO_ROUTES:
                family = DISTRO_ROUTES[parent_id][0]
                route_basis = "id_like_hint_only"
                break
    return {
        "id": distro_id or "unknown",
        "name": values.get("PRETTY_NAME") or values.get("NAME") or "Unknown Linux distribution",
        "version_id": values.get("VERSION_ID") or "unknown",
        "id_like": parent_ids,
        "family": family,
        "route_basis": route_basis,
        "common_update_tool": update_tool,
        "update_guidance": (
            "Consult the exact distribution and release security advisories; "
            "no update or security fix has been applied."
        ),
    }


def read_small_text(path: Path) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            return stream.read(8192).strip() or None
    except OSError:
        return None


def collect_inventory(
    *,
    system: str | None = None,
    os_release: Path = Path("/etc/os-release"),
    sysfs_root: Path = Path("/sys"),
    proc_root: Path = Path("/proc"),
    environment: dict[str, str] | None = None,
) -> dict:
    """Collect read-only hints. Inject paths/system for offline tests."""
    system = system or platform.system()
    environment = os.environ if environment is None else environment
    is_android = system == "Linux" and bool(
        environment.get("ANDROID_ROOT") or environment.get("ANDROID_DATA")
    )
    result: dict = {
        "system": "Android" if is_android else system,
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "fix_status": "unknown",
        "execution": "read_only; no discovered tools executed; no network requests",
        "note": "Inventory does not establish CVE applicability, vendor support, or patch state.",
    }
    if system == "Linux" and not is_android:
        raw = read_small_text(os_release)
        result["linux_distribution"] = (
            distro_from_os_release(parse_os_release(raw)) if raw is not None
            else distro_from_os_release({})
        )
        kernel = platform.release().lower()
        result["environment_hints"] = {
            "wsl_kernel_marker": "microsoft" in kernel or "wsl" in kernel,
            "container_marker": (
                (proc_root.parent / ".dockerenv").exists()
                or (proc_root.parent / "run/.containerenv").exists()
            ),
            "note": "Containers and WSL may not control the host kernel or firmware.",
        }
        dmi = sysfs_root / "class/dmi/id"
        result["hardware"] = {
            "architecture": platform.machine(),
            "manufacturer": read_small_text(dmi / "sys_vendor"),
            "model": read_small_text(dmi / "product_name"),
            "uefi_detected": (sysfs_root / "firmware/efi").exists(),
            "fwupd_cli_detected": bool(shutil.which("fwupdmgr")),
            "firmware_fix_status": "unknown",
            "note": "DMI model and UEFI mode do not establish OEM firmware patch availability.",
        }
    elif is_android:
        result["linux_distribution"] = None
        result["hardware"] = {
            "firmware_fix_status": "unknown",
            "note": "Android firmware and security updates are OEM/device specific.",
        }
    else:
        result["hardware"] = {
            "firmware_fix_status": "unknown",
            "note": "Check device/OEM signed firmware updates; this is not a firmware scanner.",
        }

    result["toolchains"] = {
        name: {"detected_commands": [cmd for cmd in commands if shutil.which(cmd)]}
        for name, commands in TOOLCHAINS.items()
    }
    result["package_tool_commands"] = {
        group: [cmd for cmd in commands if shutil.which(cmd)]
        for group, commands in PACKAGE_TOOLS.items()
    }
    result["toolchain_note"] = (
        "Executable discovery only; versions, package origin, dependencies, "
        "vulnerabilities and security patch status have not been tested."
    )
    result["software_inventory_limit"] = (
        "The toolkit did not enumerate installed packages, libraries, drivers, "
        "containers, application manifests or transitive dependencies."
    )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only host/distro/hardware/programming-runtime inventory")
    parser.add_argument("--json", action="store_true", help="Machine-readable output (default)")
    parser.parse_args(argv)
    print(json.dumps(collect_inventory(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
