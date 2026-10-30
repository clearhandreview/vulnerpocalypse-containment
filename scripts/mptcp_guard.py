#!/usr/bin/env python3
"""Runtime-only, explicit opt-in MPTCP exposure reduction for Linux.
Not a CVE fix. No persistence, no internet, no shell, no kernel rebuild.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import stat
import sys

SYSCTL = Path("/proc/sys/net/mptcp/enabled")
STATE = Path("/run/vulnerpocalypse-mptcp-guard.state")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
NETNS = Path("/proc/self/ns/net")


class GuardError(Exception):
    pass


class MPTCPGuard:
    """Only the CLI binds to real kernel paths; fixtures can be tested offline."""

    def __init__(self, knob: Path = SYSCTL, state: Path = STATE,
                 boot: Path = BOOT_ID, netns: Path = NETNS):
        self.knob, self.state, self.boot, self.netns = knob, state, boot, netns
        self._readlink = os.readlink

    def current(self) -> str:
        try:
            raw = self.knob.read_text(encoding="ascii").strip()
        except OSError as exc:
            raise GuardError("MPTCP sysctl unavailable or unreadable") from exc
        if raw not in {"0", "1"}:
            raise GuardError("Unexpected MPTCP sysctl value; no change made")
        return raw

    def identity(self) -> dict[str, str]:
        try:
            boot = self.boot.read_text(encoding="ascii").strip()
            netns = self._readlink(self.netns)
        except OSError as exc:
            raise GuardError("Cannot establish boot/network namespace; no change made") from exc
        if not boot or not netns:
            raise GuardError("Empty boot/network namespace identity")
        return {"boot_id": boot, "netns": netns}

    def _load_state(self) -> dict[str, str]:
        if self.state.is_symlink():
            raise GuardError("Unsafe state symlink; refusing to proceed")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.state, flags)
        except OSError as exc:
            raise GuardError("Cannot safely open state file") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600:
                raise GuardError("State file type/permissions are unsafe")
            if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
                raise GuardError("State file owner does not match current user")
            with os.fdopen(fd, "r", encoding="utf-8") as stream:
                fd = -1
                obj = json.load(stream)
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise GuardError("Invalid state file; manual review required") from exc
        finally:
            if fd != -1:
                os.close(fd)
        if not isinstance(obj, dict) or obj.get("schema") != 1 or obj.get("prior") != "1":
            raise GuardError("Unexpected state format; manual review required")
        if obj.get("boot_id") != self.identity()["boot_id"] or obj.get("netns") != self.identity()["netns"]:
            raise GuardError("Different boot or network namespace; refuse rollback")
        return obj

    def status(self) -> dict[str, str | bool]:
        val = self.current()
        return {
            "mptcp_new_sockets_enabled": val == "1",
            "sysctl_value": val,
            "state_file_present": self.state.exists() or self.state.is_symlink(),
            "scope": "current network namespace; not an installed CVE fix",
            "existing_sockets": "not checked; restart exposed listeners when required",
            "after_reboot": "runtime switch may revert"
        }

    def _set(self, value: str) -> None:
        # Procfs sysctl write, rather than a shell or executable download.
        try:
            with self.knob.open("w", encoding="ascii") as stream:
                stream.write(value + "\n")
        except OSError as exc:
            raise GuardError(f"Cannot write MPTCP sysctl: {exc}") from exc
        if self.current() != value:
            raise GuardError("MPTCP sysctl read-back mismatch; manual review required")

    def apply(self, ack: bool) -> str:
        if not ack:
            raise GuardError("Requires --accept-service-disruption; no change made")
        if self.state.exists() or self.state.is_symlink():
            raise GuardError("Guard state already present; inspect status; no change made")
        if self.current() == "0":
            return "already_disabled; no ownership taken, no state created"
        identity = self.identity()  # Establish before any change.
        obj = {"schema": 1, "prior": "1", **identity}
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.state, flags, 0o600)
        except OSError as exc:
            raise GuardError("Cannot safely reserve rollback state; no change made") from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(obj, stream)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            raise GuardError("Could not persist rollback state; sysctl was NOT changed") from exc
        # If writing /proc fails, retain state for operator inspection.
        self._set("0")
        return "new MPTCP sockets disabled in this namespace; NOT a CVE fix"

    def rollback(self, ack: bool) -> str:
        if not ack:
            raise GuardError("Requires --accept-reexposure; no change made")
        self._load_state()
        if self.current() != "0":
            raise GuardError("Current setting changed since apply; refuse to overwrite")
        self._set("1")
        try:
            self.state.unlink()
        except OSError as exc:
            raise GuardError("Restored setting but could not delete state; inspect manually") from exc
        return "previous value restored; verify services and vendor patch status"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Limited, reversible Linux MPTCP exposure control (NOT a patch)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("apply").add_argument("--accept-service-disruption", action="store_true")
    sub.add_parser("rollback").add_argument("--accept-reexposure", action="store_true")
    args = parser.parse_args(argv)
    if platform.system() != "Linux":
        print("UNSUPPORTED: this control only runs on Linux. No change made.", file=sys.stderr)
        return 2
    if args.command != "status" and (not hasattr(os, "geteuid") or os.geteuid() != 0):
        print("ERROR: apply/rollback require Linux root permissions.", file=sys.stderr)
        return 2
    guard = MPTCPGuard()
    try:
        if args.command == "status":
            print(json.dumps(guard.status(), indent=2))
        elif args.command == "apply":
            print(guard.apply(args.accept_service_disruption))
        else:
            print(guard.rollback(args.accept_reexposure))
        return 0
    except GuardError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
