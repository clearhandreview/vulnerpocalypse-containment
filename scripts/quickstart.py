#!/usr/bin/env python3
"""Plain-language, read-only containment selector. Does not install patches."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import platform
import re
import sys
from urllib.parse import urlparse

CATALOG = Path(__file__).resolve().parents[1] / "data" / "containments.json"
ALLOWED_PLATFORMS = {"linux", "windows", "macos", "android", "ios", "ipados", "watchos", "tvos", "visionos", "service"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
ALLOWED_CONFIDENCE = {
    "documented_kernel_control_not_an_exploit_resistance_test",
    "documented_http3_configuration_not_a_verified_cve_fix",
    "user-exposure-reduction_not_cve_fix",
    "functional_exposure_reduction_not_full_webkit_fix",
    "practical_exposure_reduction_not_fixed_device_attestation",
    "vendor_guidance_conditional_not_cve_fix",
}


def validate(data: object) -> dict:
    if (not isinstance(data, dict) or data.get("schema_version") != 1
            or not isinstance(data.get("profiles"), list) or not data["profiles"]):
        raise ValueError("Unsupported containment schema")
    ids: set[str] = set()
    for p in data["profiles"]:
        if (not isinstance(p, dict) or not isinstance(p.get("id"), str)
                or not re.fullmatch(r"[a-z0-9-]+", p["id"])):
            raise ValueError("Invalid profile")
        if p["id"] in ids:
            raise ValueError("Duplicate profile ID")
        ids.add(p["id"])
        platforms = p.get("platforms")
        if (not isinstance(platforms, list) or not platforms
                or any(not isinstance(name, str) or name not in ALLOWED_PLATFORMS
                       for name in platforms)):
            raise ValueError(f"Bad platforms: {p['id']}")
        if len(platforms) != len(set(platforms)):
            raise ValueError(f"Duplicate platform: {p['id']}")
        for field in ("when_to_use", "limitations", "control", "confidence"):
            if not isinstance(p.get(field), str) or not p[field].strip():
                raise ValueError(f"Missing {field}: {p['id']}")
        for field in ("before", "steps", "check", "undo", "references", "cves"):
            if not isinstance(p.get(field), list) or (field != "cves" and not p[field]):
                raise ValueError(f"Missing {field}: {p['id']}")
            if any(not isinstance(s, str) or not s.strip() for s in p[field]):
                raise ValueError(f"Invalid {field}: {p['id']}")
        if any(urlparse(x).scheme != "https" or not urlparse(x).netloc for x in p["references"]):
            raise ValueError(f"Missing official HTTPS references: {p['id']}")
        if any(not CVE_RE.fullmatch(cve) for cve in p["cves"]):
            raise ValueError(f"Invalid CVE: {p['id']}")
        if p["confidence"] not in ALLOWED_CONFIDENCE:
            raise ValueError("Containment must not claim vendor-fixed status")
    return data


def load(path: Path = CATALOG) -> dict:
    return validate(json.loads(path.read_text(encoding="utf-8")))


def select(data: dict, system: str, key: str = "") -> list[dict]:
    if system not in ALLOWED_PLATFORMS:
        raise ValueError(f"Unsupported platform {system!r}: choose from {', '.join(sorted(ALLOWED_PLATFORMS))}")
    return [p for p in data["profiles"] if system in p["platforms"] and
            (not key or key == p["id"] or key in p["cves"])]


def render(profile: dict) -> str:
    sections = [f"## {profile['name']}",
                f"Profile: {profile['id']}",
                "This is temporary exposure reduction — NOT a vulnerability patch.",
                f"When to consider: {profile['when_to_use']}",
                f"Scope / risks: {profile['limitations']}"]
    for title, field in (("Before", "before"), ("Install the temporary control", "steps"),
                         ("How to verify it is active", "check"), ("Switch to the vendor fix and undo", "undo")):
        sections.append(f"\n{title}:")
        sections.extend(f"  {i}. {line}" for i, line in enumerate(profile[field], 1))
    sections.append("\nSources:")
    sections.extend(f"  {x}" for x in profile["references"])
    return "\n".join(sections)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only plain-language hotfix/containment guide")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("validate", help="verify catalog schema and conservative guardrails")
    s = sub.add_parser("guide", help="show installation, checking, rollback and vendor handoff")
    s.add_argument("--os", dest="system",
                   default={"Darwin": "macos", "Windows": "windows", "Linux": "linux"}.get(platform.system(), ""))
    s.add_argument("--id", default="", help="Optional containment profile ID or CVE")
    s.add_argument("--json", action="store_true", help="Machine-readable guide")
    args = parser.parse_args(argv)
    try:
        data = load()
        if args.action == "validate":
            print(f"VALID: {len(data['profiles'])} temporary containment profiles; none claims a universal CVE patch")
            return 0
        matches = select(data, args.system.lower(), args.id)
        if not matches:
            print("NO VERIFIED PROFILE FOR THIS COMBINATION. Stop; use vendor advice or isolate.",
                  file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps({"status": "temporary_containment_only", "profiles": matches}, indent=2))
        else:
            print("\n\n".join(render(p) for p in matches))
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
