#!/usr/bin/env python3
"""Read-only November 2026 research handoff and RIR change-review plan.

Python 3.11+, standard library only. Never downloads, installs, or runs a fix.
The stored handoff is source-reported evidence, not a claim of live product safety.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

DEFAULT_LEDGER = Path(__file__).resolve().parents[1] / "data" / "research_handoff_2026_11_03.json"
ID_RE = re.compile(r"(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+|CURSOR-\d{4}-\d{2}-\d{2})\Z")
REQUIRED = (
    "id", "record_scope", "product", "mechanism_and_exposure",
    "remediation_as_documented", "remediation_evidence", "open_question",
    "primary_source_url", "evidence_cutoff_utc", "remediation_automation_ready",
)


def validate(data: object) -> dict:
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("Expected handoff schema_version 1")
    if not isinstance(data.get("records"), list) or not data["records"]:
        raise ValueError("Missing research records")
    if data.get("execution_capability") != "none":
        raise ValueError("A research handoff must not advertise execution")
    seen: set[str] = set()
    for entry in data["records"]:
        if not isinstance(entry, dict) or any(
            not isinstance(entry.get(key), str) or not entry[key].strip()
            for key in REQUIRED
        ):
            raise ValueError("Incomplete evidence record")
        identifier = entry["id"]
        if not ID_RE.fullmatch(identifier) or identifier in seen:
            raise ValueError(f"Invalid or duplicate identifier: {identifier}")
        seen.add(identifier)
        url = urlsplit(entry["primary_source_url"])
        if url.scheme != "https" or not url.netloc or url.username or url.password:
            raise ValueError(f"Invalid evidence URL: {identifier}")
        if entry["remediation_automation_ready"].strip().lower() != "no":
            raise ValueError(f"Unsupported remediation readiness claim: {identifier}")
        if entry.get("automation_allowed") is not False or entry.get("patch_applied") is not False:
            raise ValueError(f"Unsupported execution claim: {identifier}")
        if entry.get("deployment_verified") is not False or entry.get("action_state") != "unexecuted":
            raise ValueError(f"Unsupported deployment claim: {identifier}")
    return data


def load(path: Path = DEFAULT_LEDGER) -> dict:
    return validate(json.loads(path.read_text(encoding="utf-8")))


def get(data: dict, identifier: str) -> dict:
    return next((row for row in data["records"] if row["id"] == identifier),
                None) or _missing(identifier)


def _missing(identifier: str):
    raise ValueError(f"Not tracked in this handoff: {identifier}")


def plan(row: dict, host_os: str = "") -> dict:
    """RIR-inspired evidence gates, not a risk score or automatic action selector."""
    return {
        "id": row["id"],
        "product": row["product"],
        "host_os": host_os or "not provided",
        "applicability": "unknown_until_product_edition_branch_and_component_confirmed",
        "remediation_status": "requires_independent_vendor_and_deployment_validation",
        "proposed_control": row["remediation_as_documented"],
        "evidence_basis": row["primary_source_url"],
        "open_residual": row["open_question"],
        "stages": [
            {"stage": "observe", "required": "Off-device inventory, telemetry and backup; no system changes."},
            {"stage": "verify", "required": "Exact product/build/OS context and current signed vendor advisory."},
            {"stage": "contain", "required": "Propose narrow independent boundary; prove allowed services stay available."},
            {"stage": "authorize", "required": "Separate owner/change authority approval; no self-issued permission."},
            {"stage": "recover", "required": "Vendor-supported fix, signed artifact and compromise-dependent recovery."},
            {"stage": "validate", "required": "Confirm running fixed artifact, original boundary and business service health."},
        ],
        "safety_invariants": [
            "No unattended binary/firmware patch or firewall operation",
            "Preserve external forensic evidence and verified rollback path",
            "No 'fixed' claim from a host OS label or version guess",
            "No service-impacting action without an independent approver",
        ],
        "execution_enabled": False,
        "patch_applied": False,
        "tested_on_device": False,
        "ready_for_production_change": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only November 3 RIR vulnerability handoff")
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate")
    sub.add_parser("list")
    s = sub.add_parser("show")
    s.add_argument("identifier")
    p = sub.add_parser("plan")
    p.add_argument("identifier")
    p.add_argument("--os", default="", help="For documentation only; never used as proof of a fix")
    args = parser.parse_args(argv)
    try:
        data = load(args.ledger)
        if args.command == "validate":
            print(f"VALID: {len(data['records'])} handoff records; no automation enabled")
        elif args.command == "list":
            for row in data["records"]:
                label = json.dumps(row["product"], ensure_ascii=True)[1:-1]
                print(f"{row['id']:<25} {row['record_scope']:<32} {label}")
        elif args.command == "show":
            print(json.dumps(get(data, args.identifier), indent=2, ensure_ascii=True))
        elif args.command == "plan":
            print(json.dumps(plan(get(data, args.identifier), args.os), indent=2, ensure_ascii=True))
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
