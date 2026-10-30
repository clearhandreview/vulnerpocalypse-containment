#!/usr/bin/env python3
"""Offline, read-only CVE catalog and evidence-limited release-floor assessor.

ASSUMING: Python >=3.11, stdlib only. Never installs, downloads, or applies fixes.
Reported versions are untrusted user inputs: compare ONLY exact product editions.
"""
from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "data" / "advisories.json"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
VERSION_RE = re.compile(r"^\d+(?:\.\d+){3}$")


def version_tuple(raw: str) -> tuple[int, ...]:
    if not VERSION_RE.fullmatch(raw):
        raise ValueError("Version must contain exactly 4 dotted numeric fields")
    return tuple(int(part) for part in raw.split("."))


def load_catalog(path: Path = DEFAULT_CATALOG) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    validate_catalog(data, path.parent)
    return data


def validate_catalog(data: object, directory: Path) -> None:
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("Expected catalog schema_version: 1")
    items = data.get("advisories")
    if not isinstance(items, list) or not items:
        raise ValueError("Catalog must contain a nonempty advisories list")
    unresolved = data.get("unresolved")
    if not isinstance(unresolved, list):
        raise ValueError("Catalog must contain an unresolved list")
    known_ids: set[str] = set()
    known_cves: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Advisory entries must be objects")
        key = item.get("id")
        if not isinstance(key, str) or not re.fullmatch(r"[a-z0-9-]+", key):
            raise ValueError(f"Invalid advisory id: {key!r}")
        if key in known_ids:
            raise ValueError(f"Duplicate advisory id: {key}")
        known_ids.add(key)
        if not isinstance(item.get("product"), str) or not item["product"]:
            raise ValueError(f"{key}: missing product")
        platforms = item.get("platforms")
        if (not isinstance(platforms, list) or not platforms
                or any(not isinstance(name, str) or not name for name in platforms)):
            raise ValueError(f"{key}: invalid platforms")
        if len(platforms) != len(set(platforms)):
            raise ValueError(f"{key}: duplicate platform")
        cves = item.get("cves")
        if not isinstance(cves, list) or not cves:
            raise ValueError(f"{key}: missing CVE list")
        for cve in cves:
            if not isinstance(cve, str) or not CVE_RE.fullmatch(cve):
                raise ValueError(f"{key}: invalid CVE: {cve!r}")
            if cve in known_cves:
                raise ValueError(f"Duplicate CVE record: {cve}")
            known_cves.add(cve)
        for field in ("official_advisory",):
            url = item.get(field)
            if not isinstance(url, str) or urlparse(url).scheme != "https" or not urlparse(url).netloc:
                raise ValueError(f"{key}: {field} must be a HTTPS URL")
        for field in ("patch_url",):
            url = item.get(field)
            if url is not None and (not isinstance(url, str) or urlparse(url).scheme != "https" or not urlparse(url).netloc):
                raise ValueError(f"{key}: {field} must be null or HTTPS URL")
        if item.get("fix_type") not in {"vendor_release", "vendor_update", "upstream_patch"}:
            raise ValueError(f"{key}: unrecognized fix_type")
        if item["fix_type"] == "vendor_release":
            floors = item.get("minimum_versions", {})
            if not isinstance(floors, dict) or not floors:
                raise ValueError(f"{key}: no supported published release floors")
            if any(name not in platforms for name in floors):
                raise ValueError(f"{key}: release floor for undeclared platform")
            for floor in floors.values():
                if not isinstance(floor, str):
                    raise ValueError(f"{key}: release floor must be a version string")
                version_tuple(floor)
        if item.get("id") == "windows-cve-2026-33096":
            floors = item.get("fixed_windows_builds")
            if not isinstance(floors, dict) or not floors:
                raise ValueError(f"{key}: missing Windows fixed build floors")
            for floor in floors.values():
                if not isinstance(floor, str):
                    raise ValueError(f"{key}: Windows build floor must be a version string")
                version_tuple(floor)
        fixed_releases = item.get("fixed_releases")
        if fixed_releases is not None and (
                not isinstance(fixed_releases, dict) or not fixed_releases
                or any(not isinstance(branch, str) or not branch.strip()
                       or not isinstance(release, str) or not release.strip()
                       for branch, release in fixed_releases.items())):
            raise ValueError(f"{key}: invalid fixed_releases branch map")
        if item.get("local_patch") is not None:
            if not isinstance(item["local_patch"], str) or not item["local_patch"].strip():
                raise ValueError(f"{key}: local patch path must be a nonempty string")
            rel = Path(item["local_patch"])
            # Catalog is data and must never cause access outside repository.
            if rel.is_absolute() or ".." in rel.parts or not rel.parts:
                raise ValueError(f"{key}: local patch path must be relative")
            resolved = (directory.parent / rel).resolve()
            if not resolved.is_relative_to(directory.parent.resolve()) or not resolved.is_file():
                raise ValueError(f"{key}: local patch file missing or escapes repository")

    unresolved_ids: set[str] = set()
    for entry in unresolved:
        if not isinstance(entry, dict):
            raise ValueError("Unresolved entries must be objects")
        key = entry.get("id")
        if not isinstance(key, str) or not re.fullmatch(r"[a-z0-9-]+", key):
            raise ValueError(f"Invalid unresolved id: {key!r}")
        if key in unresolved_ids or key in known_ids:
            raise ValueError(f"Duplicate unresolved id: {key}")
        unresolved_ids.add(key)
        cves = entry.get("cves")
        if not isinstance(cves, list):
            raise ValueError(f"{key}: unresolved cves must be a list")
        if any(not isinstance(cve, str) or not CVE_RE.fullmatch(cve) for cve in cves):
            raise ValueError(f"{key}: invalid unresolved CVE")
        source = entry.get("source")
        if (not isinstance(source, str) or urlparse(source).scheme != "https"
                or not urlparse(source).netloc):
            raise ValueError(f"{key}: source must be a HTTPS URL")
        for field in ("product", "status", "reason", "next_step"):
            if not isinstance(entry.get(field), str) or not entry[field].strip():
                raise ValueError(f"{key}: missing {field}")


def find_advisory(data: dict, identifier: str) -> dict:
    matches = [
        entry for entry in data["advisories"]
        if entry["id"] == identifier or identifier in entry["cves"]
    ]
    if len(matches) != 1:
        raise ValueError(f"Not found or ambiguous: {identifier}. See 'list' and unresolved items.")
    return matches[0]


def assess(item: dict, system: str, version: str, variant: str = "") -> dict:
    """Assess only a vendor-published version floor, NOT a running fix's effectiveness."""
    out = {
        "advisory": item["id"], "cves": item["cves"], "product": item["product"],
        "platform": system, "observed_version": version, "variant": variant or None,
        "result": "manual_vendor_confirmation_required",
        "evidence_scope": "Reported version comparison only; no runtime exploit verification.",
        "official_advisory": item["official_advisory"],
    }
    if system not in item["platforms"]:
        out["reason"] = "This platform is not covered by the advisory record."
        return out
    if item["fix_type"] == "vendor_release":
        floor = item["minimum_versions"].get(system)
        if not floor:
            out["reason"] = "No vendor-release floor published for this platform."
            return out
        try:
            installed, target = version_tuple(version), version_tuple(floor)
        except ValueError as exc:
            out["reason"] = str(exc)
            return out
        out["minimum_published_fixed_version"] = floor
        if installed >= target:
            out["result"] = "meets_published_release_floor"
            out["reason"] = (
                "Assuming this is the actual vendor product/build (not the host OS version), "
                "it meets the published minimum for these CVEs. Confirm edition, vendor "
                "package, supported upgrade path and actively running version."
            )
        else:
            out["result"] = "below_published_release_floor"
            out["reason"] = "This reported product version is below the published fixed build."
        return out
    if item["id"] == "windows-cve-2026-33096":
        try:
            observed = version_tuple(version)
        except ValueError as exc:
            out["reason"] = str(exc)
            return out
        if observed[:2] != (10, 0):
            out["reason"] = "Not a recognized Windows 10.0 build numbering scheme."
            return out
        build = str(observed[2])
        key = build
        if build == "26100":
            if variant not in {"client", "server"}:
                out["reason"] = ("Build 26100 spans Windows 11 and Server 2025: "
                                 "specify --variant client or --variant server.")
                return out
            key = build + "-" + variant
        floor = item["fixed_windows_builds"].get(key)
        if floor is None:
            out["reason"] = "No affected-edition floor verified for this Windows build family."
            return out
        out["minimum_published_fixed_version"] = floor
        if observed >= version_tuple(floor):
            out["result"] = "meets_published_release_floor"
            out["reason"] = ("The reported Windows build meets this published floor for "
                             "the matching affected edition. Confirm installed cumulative "
                             "update, reboot, and product applicability in MSRC.")
        else:
            out["result"] = "below_published_release_floor"
            out["reason"] = "The reported OS build is older than the listed Microsoft fix."
        return out
    out["reason"] = (
        "Source or product-specific vendor evidence is required. "
        "Do not infer security from an OS family or a version number alone."
    )
    return out


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only, cross-platform CVE catalog and release-floor checks")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="validate catalog syntax, references and local patch")
    sub.add_parser("list", help="list tracked CVEs (not an exhaustive disclosure ledger)")
    sub.add_parser("unresolved", help="show explicitly uncovered vulnerabilities")
    sub.add_parser("inventory", help="display basic host details; NEVER implies a fix")
    check = sub.add_parser("check", help="compare a manually verified product version to a floor")
    check.add_argument("identifier", help="advisory id or CVE")
    check.add_argument("--platform", required=True,
                       help="windows, linux, macos, ios, ipados, tvos, visionos, watchos, service")
    check.add_argument("--version", required=True,
                       help="real installed product version, not assumed OS-wide version")
    check.add_argument("--variant", choices=["client", "server"], default="",
                       help="required for ambiguous Windows build 26100")
    args = parser.parse_args(argv)
    try:
        data = load_catalog(args.catalog)
        if args.command == "validate":
            print(f"VALID: {len(data['advisories'])} advisory entries, "
                  f"{sum(len(x['cves']) for x in data['advisories'])} listed CVEs")
            return 0
        if args.command == "list":
            for item in data["advisories"]:
                print(f"{item['id']:26} {item['product']}: {', '.join(item['cves'])}")
            return 0
        if args.command == "unresolved":
            print(json.dumps(data["unresolved"], indent=2))
            return 0
        if args.command == "inventory":
            print(json.dumps({
                "system": platform.system(), "release": platform.release(),
                "version": platform.version(), "machine": platform.machine(),
                "fix_status": "unknown",
                "note": "Host identification never establishes a CVE patch state."
            }, indent=2))
            return 0
        if args.command == "check":
            item = find_advisory(data, args.identifier)
            result = assess(item, args.platform.lower(), args.version, args.variant)
            print(json.dumps(result, indent=2))
            return {"meets_published_release_floor": 0,
                    "below_published_release_floor": 1}.get(result["result"], 2)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(run())
