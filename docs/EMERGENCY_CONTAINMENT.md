# Emergency containment: safety boundaries and rollback

## What the repository actually provides

- **Source patch:** an attributed Linux upstream patch, usable only with a
  compatible source tree and independent kernel build/release process.
- **Temporary Linux runtime change:** optional `scripts/mptcp_guard.py`
  that sets `net.mptcp.enabled=0` in *its network namespace*. It is not
  compiled into any running kernel and does not fix a use-after-free.
- **Windows, macOS, Chrome, Android:** carefully documented human-operated
  risk reduction; **no new proprietary binaries or kernel drivers**.
- **Unknown/unpublished bugs:** no generated patches or claims of protection.

The choice to include only one executable mitigation is deliberate.
Feature toggles and firewall policies are not interchangeable across OS
versions. Any additional automatic mitigation must be verified against the
**actual vulnerable component and supported environment** first.

## Linux runtime control: exact handling

**Preconditions:** Linux; `net.mptcp.enabled` exists; local root; current
network namespace known; approved service downtime; system backup and
independently verified recovery path. This control may break MPTCP
applications, and it does **not** change existing sessions.

**Run (only in a controlled maintenance window):**

```bash
python3 scripts/mptcp_guard.py status
sudo python3 scripts/mptcp_guard.py apply --accept-service-disruption
python3 scripts/mptcp_guard.py status
```

**Expected result:** `sysctl_value` is `0` for that namespace. The
control writes a root-owned, mode `0600` state file under `/run` containing
the old value, Linux boot ID and namespace identity, and refuses to
overwrite an existing state. It rejects unknown sysctl values and requires
an explicit flag. There are no remote downloads, shell commands, persistence
files, kernel images, or automatic service restarts.

**Remaining risks:** Existing listening sockets may persist until restarted.
A host with different network namespaces (including containerized apps)
can remain exposed. Reboot may re-enable MPTCP. You must verify operational
health and decide whether this containment fits the actual threat model.

**Before removal:** install the signed distribution kernel security update,
restart into the kernel that contains the fix, and verify *exact running
package and vendor advisory*. Do not treat a version string alone as proof.

**Remove (same boot / network namespace only):**

```bash
sudo python3 scripts/mptcp_guard.py rollback --accept-reexposure
python3 scripts/mptcp_guard.py status
```

The rollback refuses unexpected ownership, mode, boot ID, namespace or
changed sysctl value. If the host rebooted or the state was tampered with,
follow your platform's approved system restore process — do not delete
the state file blindly or force an unknown sysctl value.

**Failure response:** stop automation. If the tool reports a partial state,
have an administrator examine the read-back sysctl and `/run` state before
any further changes. Report a bug using `SECURITY.md`.

## Why we do not ship "universal zero-day patches"

A binary fix needs the actual flaw, exact builds, ABI details, symbol
layout, code signing and a reproducible build/test chain. Different kernel
versions, vendor backports and device firmware can have different memory
layouts and safety invariants. An unsigned cross-OS binary that claimed
to work universally would itself create unacceptable risk.

For a **new CVE without vendor fix**, a contributor must submit
a public technical advisory / source reference, clear applicability,
minimal code change with test fixtures, build matrix, documented regression
risk, independently reviewed test output, and a safe rollback process.
Until those exist, use an isolated deployment or a vendor-supported
mitigation and list the finding as `unknown`; never claim a patched host.

## Vendor handoff

The temporary control has no ownership of vendor security updates:
1. Observe the exact OS/device and applicable official advisory.
2. Install the vendor-signed fix and activate it (restart/relaunch).
3. Validate the installed **and running** product version/package.
4. Run benign smoke tests (not proof-of-exploit attempts).
5. Review removal of the temporary control, then test services again.
6. Close the finding only once a reviewer confirms evidence, not when a
   Python checker happens to exit with code zero.

Use `python scripts/vendor_handoff.py --help` for a human attestation
worksheet that does not modify the host. Use `docs/VALIDATION.md` for
platform-specific evidence.
