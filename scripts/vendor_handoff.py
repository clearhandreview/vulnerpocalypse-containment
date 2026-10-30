#!/usr/bin/env python3
"""Manual-evidence vendor handoff gate; no installed software modified."""
from __future__ import annotations
import argparse
import json
import sys
from catalog import load_catalog, find_advisory, assess


def evaluate(identifier: str, system: str, version: str, variant: str,
             source_reviewed: bool, running_confirmed: bool,
             smoke_test_passed: bool) -> dict:
    advisory = find_advisory(load_catalog(), identifier)
    floor = assess(advisory, system, version, variant)
    evidence = {
        "vendor_advisory_reviewed_by_operator": source_reviewed,
        "active_running_version_confirmed_by_operator": running_confirmed,
        "benign_functional_smoke_test_passed_by_operator": smoke_test_passed
    }
    eligible = floor["result"] == "meets_published_release_floor" and all(evidence.values())
    return {
        "cve": identifier,
        "product": floor["product"],
        "official_vendor_advisory": floor["official_advisory"],
        "version_assessment": floor,
        "operator_declarations_not_machine_verified": evidence,
        "handoff": ("READY_FOR_CHANGE_REVIEW" if eligible else "HOLD_OR_MANUAL_VENDOR_REVIEW"),
        "next_step": ("A person reviews impact and restores temporary controls during a planned change."
                      if eligible else
                      "Do not lift temporary controls yet; obtain exact vendor evidence and complete checks."),
        "scope": "Never proof of exploit resistance; never uninstalls the temporary control.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check readiness to REPLACE a containment with a vendor update")
    parser.add_argument("cve")
    parser.add_argument("--os", required=True, choices=["windows", "linux", "macos", "ios", "ipados", "tvos", "visionos", "watchos"])
    parser.add_argument("--version", required=True, help="REAL active installed product version, not guessed")
    parser.add_argument("--variant", default="", choices=["", "client", "server"])
    parser.add_argument("--vendor-advisory-reviewed", action="store_true")
    parser.add_argument("--active-version-confirmed", action="store_true")
    parser.add_argument("--smoke-test-passed", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = evaluate(args.cve, args.os, args.version, args.variant,
                          args.vendor_advisory_reviewed, args.active_version_confirmed,
                          args.smoke_test_passed)
        print(json.dumps(result, indent=2))
        return 0 if result["handoff"] == "READY_FOR_CHANGE_REVIEW" else 2
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
