#!/usr/bin/env python3
"""Read-only triage and reviewable source patch generation for CVE-2026-98432.

Only targets the two statements corrected in upstream Linux commit e3f33b0.
This tool does NOT assess a running kernel for vulnerability or fix installation.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import platform
from pathlib import Path
import re
import sys

CVE = "CVE-2026-98432"
UPSTREAM = "e3f33b0a1d89d738e2b913dab519226eaf76e15b"

TARGETS = (
    (
        "net/ipv4/af_inet.c",
        "inet_sock_destruct",
        "struct sock",
        "sk",
        "inet->inet_opt",
    ),
    (
        "net/ipv4/tcp_ipv4.c",
        "tcp_v4_reqsk_destructor",
        "struct request_sock",
        "req",
        "inet_rsk(req)->ireq_opt",
    ),
)


def strip_comments(source: str) -> str:
    """Erase C comments while preserving offsets and newlines."""
    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in match.group())
    return re.sub(r"/\*.*?\*/|//[^\n]*", blank, source, flags=re.DOTALL)


def function_region(clean: str, name: str, arg_type: str, arg_name: str) -> tuple[int, int] | None:
    escaped_type = re.escape(arg_type).replace(r"\ ", r"\s+")
    signature = re.compile(
        rf"\bvoid\s+{re.escape(name)}\s*\(\s*"
        rf"{escaped_type}\s*\*\s*"
        rf"{re.escape(arg_name)}\s*\)\s*\{{"
    )
    matches = list(signature.finditer(clean))
    if len(matches) != 1:
        return None
    start_brace = matches[0].end() - 1
    depth = 0
    for i in range(start_brace, len(clean)):
        if clean[i] == "{":
            depth += 1
        elif clean[i] == "}":
            depth -= 1
            if depth == 0:
                return start_brace + 1, i
    return None


def call_pattern(pointer: str, deferred: bool) -> re.Pattern[str]:
    dereference = (
        r"rcu_dereference_protected\s*\(\s*"
        + re.escape(pointer).replace(r"\ ", r"\s*")
        + r"\s*,\s*1\s*\)"
    )
    if deferred:
        text = r"\bkfree_rcu\s*\(\s*" + dereference + r"\s*,\s*rcu\s*\)\s*;"
    else:
        text = r"\bkfree\s*\(\s*" + dereference + r"\s*\)\s*;"
    return re.compile(text)


def check_file(source: str, name: str, arg_type: str, arg_name: str,
               pointer: str) -> dict[str, object]:
    clean = strip_comments(source)
    region = function_region(clean, name, arg_type, arg_name)
    if region is None:
        return {"status": "unknown", "reason": "unique function body not found"}
    begin, end = region
    old = list(call_pattern(pointer, deferred=False).finditer(clean, begin, end))
    new = list(call_pattern(pointer, deferred=True).finditer(clean, begin, end))
    if len(old) == 1 and not new:
        return {"status": "vulnerable_pattern", "span": [old[0].start(), old[0].end()]}
    if len(new) == 1 and not old:
        return {"status": "upstream_fix_pattern", "span": [new[0].start(), new[0].end()]}
    return {
        "status": "unknown",
        "reason": f"ambiguous or modified cleanup expression (old={len(old)}, new={len(new)})",
    }


def check_rcu_member(source_root: Path) -> bool:
    """Check the type requirement used by the upstream kfree_rcu(..., rcu) fix."""
    path = source_root / "include/net/inet_sock.h"
    try:
        clean = strip_comments(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        return False
    block = re.search(r"\bstruct\s+ip_options_rcu\s*\{([^{}]*)\}", clean, re.DOTALL)
    return bool(block and re.search(r"\bstruct\s+rcu_head\s+rcu\s*;", block.group(1)))


def inspect_source(source_root: Path) -> tuple[dict[str, object], dict[str, str]]:
    targets: dict[str, object] = {}
    originals: dict[str, str] = {}
    for relative, name, arg_type, arg_name, pointer in TARGETS:
        path = source_root / relative
        try:
            original = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            targets[relative] = {"status": "unknown", "reason": f"cannot read file: {exc}"}
            continue
        originals[relative] = original
        targets[relative] = check_file(original, name, arg_type, arg_name, pointer)

    rcu_member = check_rcu_member(source_root)
    states = [targets.get(item[0], {}).get("status") for item in TARGETS]
    if rcu_member and states == ["upstream_fix_pattern"] * len(TARGETS):
        status = "upstream_fix_pattern_present"
    elif rcu_member and states == ["vulnerable_pattern"] * len(TARGETS):
        status = "vulnerable_cleanup_pattern_present"
    else:
        status = "indeterminate"

    report = {
        "cve": CVE,
        "source_root": str(source_root),
        "status": status,
        "rcu_member_present": rcu_member,
        "targets": targets,
        "warning": (
            "Static source-pattern inspection only. Not a kernel build, boot test, "
            "vendor advisory check, or running-kernel security certification."
        ),
    }
    return report, originals


def prepare_patch(source_root: Path) -> str:
    report, originals = inspect_source(source_root)
    if report["status"] != "vulnerable_cleanup_pattern_present":
        raise ValueError(
            "Refusing to produce a patch: both original vulnerable cleanup "
            "statements and struct ip_options_rcu.rcu must be uniquely present."
        )
    chunks: list[str] = []
    for relative, name, arg_type, arg_name, pointer in TARGETS:
        original = originals[relative]
        finding = check_file(original, name, arg_type, arg_name, pointer)
        start, end = finding["span"]
        new_expr = f"kfree_rcu(rcu_dereference_protected({pointer}, 1), rcu);"
        updated = original[:start] + new_expr + original[end:]
        changes = list(difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=f"a/{relative}",
            tofile=f"b/{relative}",
            n=3,
        ))
        if not changes:
            raise ValueError(f"No patch generated for {relative}")
        chunks.extend(changes)
    return "".join(chunks)


def host_report() -> dict[str, str]:
    if sys.platform != "linux":
        return {
            "cve": CVE,
            "running_kernel": "not-a-linux-kernel",
            "distribution": platform.system(),
            "status": "unknown",
            "reason": "Linux kernel CVE host inventory is only applicable on Linux."
        }
    release = os.uname().release
    distro = "unknown"
    try:
        lines = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
        for line in lines:
            if line.startswith("PRETTY_NAME="):
                distro = line.partition("=")[2].strip('"')
                break
    except OSError:
        pass
    return {
        "cve": CVE,
        "running_kernel": release,
        "distribution": distro,
        "status": "unknown",
        "reason": (
            "Kernel release numbers cannot establish vendor backport status. "
            "Compare the installed kernel package with the vendor's CVE advisory."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CVE-2026-98432 read-only host triage and source patch preparation"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    host = sub.add_parser("host", help="show host kernel details (status always unknown)")
    host.add_argument("--json", action="store_true")
    inspect = sub.add_parser("inspect-source", help="check the two upstream source patterns")
    inspect.add_argument("source_root", type=Path)
    inspect.add_argument("--json", action="store_true")
    patch = sub.add_parser("prepare-patch", help="emit a reviewable patch; never edit source")
    patch.add_argument("source_root", type=Path)
    args = parser.parse_args(argv)
    if args.command == "host":
        report = host_report()
        print(json.dumps(report, indent=2) if args.json else
              f"Kernel: {report['running_kernel']}\nDistribution: {report['distribution']}\n"
              f"Status: unknown — {report['reason']}")
        return 0
    if args.command == "inspect-source":
        report, _ = inspect_source(args.source_root)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"{CVE}: {report['status']}")
            print(f"RCU member: {'present' if report['rcu_member_present'] else 'not verified'}")
            for name, finding in report["targets"].items():
                print(f"  {name}: {finding['status']}")
            print(report["warning"])
        if report["status"] == "upstream_fix_pattern_present":
            return 0
        if report["status"] == "vulnerable_cleanup_pattern_present":
            return 1
        return 2
    if args.command == "prepare-patch":
        try:
            diff = prepare_patch(args.source_root)
        except ValueError as exc:
            print(f"Refused: {exc}", file=sys.stderr)
            return 2
        sys.stdout.write(diff)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
