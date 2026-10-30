# Verification worksheet and platform-specific commands

**Purpose:** separate *available fix*, *installed fix*, *activated/running fix*,
*functional smoke test*, and *independently verified exploit resistance*.
Those are five different claims. Only the first four can usually be evaluated
from vendor records and benign tests here.

The term "working" means **the fixed-version product is active and its
ordinary functions still work**. It does **not** mean the original exploit
cannot be reproduced. Do not run the attack against production systems.

## Evidence worksheet (copy into a PR or change ticket)

| Field | Record |
| --- | --- |
| Date/time / reviewer | |
| Asset identifier (do not publish private details) | |
| OS + full edition / architecture / support status | |
| Exact affected product + installed channel | |
| CVE / vendor advisory link | |
| Affected? (yes/no/unknown, with source) | |
| Vendor-published fixed release / KB / package | |
| Installed package version / source / signature evidence | |
| Running version **after restart** | |
| Read-only checker result | |
| Benign smoke test + result | |
| Remaining uncertainty / rollback plan | |
| Independent exploit-resistance proof (usually **not performed**) | |

**Decision rule:** A fix is only *version-supported* if a vendor advisory
links the exact product/edition to the fix and the **active** version is in
the fixed range. Functional "working" additionally needs a successful smoke
test. If a premise is unknown, record UNKNOWN rather than guessing.

## Windows: CVE-2026-33096

Official source:
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33096

Use supported Microsoft cumulative security updates via the approved update
channel. After reboot, run **PowerShell** (no elevation needed for these
registry read commands in ordinary installations):

```powershell
$r = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$r | Select-Object ProductName, DisplayVersion, CurrentBuild, UBR
"10.0.$($r.CurrentBuild).$($r.UBR)"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
```

`Get-HotFix` can omit updates and does not independently prove this CVE is
fixed. Use the full OS build *and* MSRC affected-edition table.

Selected affected build-family floors published for the April 2026 fix:

| Edition | Build family | Minimum fixed OS build |
| --- | --- | --- |
| Windows 11 23H2 | 22631 | 10.0.22631.6936 |
| Windows 11 24H2 | 26100 client | 10.0.26100.8246 |
| Windows 11 25H2 | 26200 | 10.0.26200.8246 |
| Windows 11 26H1 | 28000 | 10.0.28000.1836 |
| Windows Server 2022 | 20348 | 10.0.20348.5020 |
| Windows Server 23H2 | 25398 | 10.0.25398.2274 |
| Windows Server 2025 | 26100 server | 10.0.26100.32690 |

**The 26100 distinction is essential:** Windows 11 24H2 and Windows Server
2025 share 26100 but require different release floors. For this reason:

```powershell
python scripts/catalog.py check CVE-2026-33096 --platform windows --version 10.0.26100.32690 --variant server
```

If the installed build/edition is absent from the Microsoft affected product
list, this tool returns manual review — *not* vulnerable and not fixed.
Compare later cumulative update and servicing / hotpatch policies with MSRC.

**Smoke test:** restart the particular HTTP.sys-based service; verify
normal, authenticated HTTP requests and an ordinary HTTP/3 request if your
service uses it, plus normal service logs and client connectivity. Avoid
sending malformed traffic or running a DoS probe.

## Linux kernel: CVE-2026-98432

Kernel advisory:
https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/refs/heads/master/cve/published/2026/CVE-2026-98432.mbox

```sh
uname -r
python cve98432.py host --json
# If you have the *matching source tree* for the kernel actually built:
python cve98432.py inspect-source /path/to/linux --json
```

On Debian/Ubuntu-family systems the following can help identify the exact
running package; commands are examples, **not proof of a fix**:

```sh
dpkg-query -W "linux-image-$(uname -r)"
```

On RPM-based systems use the distribution's package manager to inspect the
exact installed kernel version and vendor erratum (package names vary).
**A CVE may be backported without changing the upstream version string.**
Reboot into the updated kernel, check `uname -r`, compare the running package
against the distribution security bulletin for the exact CVE, and preserve
package signature/provenance records.

**Source-level check:** `upstream_fix_pattern_present` means a static match
for two `kfree_rcu` cleanup sites and RCU member. It does *not* establish
which binary was compiled, deployed, running, or whether all network paths
are safe. A mismatch or unknown result requires expert review.

**Smoke test:** run your normal network service health checks (IPv4
connections, authorized MPTCP connections if used, service logs, and
application connection tests) after the update. No exploit in production.

## Chrome Stable (Windows, macOS, Linux)

**Do not substitute Chromium, Edge, a system WebView, or a browser
user-agent string** for a verified Google Chrome Stable binary. Versions
for those different products require separate advisories.

1. Open `chrome://settings/help` or Chrome menu → About Chrome.
2. Update through Chrome's signed updater and **relaunch**.
3. Re-open About Chrome to confirm the **running** full version.
4. Compare against the correct per-CVE floor from `data/advisories.json`
   or the linked release notice.
5. Run the read-only checker; for example:

```sh
python scripts/catalog.py check CVE-2026-118331 --platform macos --version 156.0.8078.79
```

**Smoke test:** visit a trusted internal/test page, verify ordinary
navigation, downloads/permissions you depend on, and browser process
stability. A higher version number cannot establish the status of
unlisted CVEs.

Official release info:
https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_0562499947.html
https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_02107719452.html

## Apple Safari/WebKit: CVE-2026-43715

Apple's advisory:
https://support.apple.com/en-us/127594

Reported fixes include Safari 26.5.2, iOS/iPadOS 26.5.2,
macOS Tahoe 26.5.2, and tvOS/watchOS/visionOS 26.6. **These are not
universal version thresholds for every Apple branch.** Later security
release documentation and the particular supported device take precedence.

macOS read-only inventory:

```sh
sw_vers
softwareupdate --history
```

On macOS, use Safari → About Safari for the browser version. On
iPhone/iPad, use Settings → General → About and Software Update to inspect
the OS and update. For other Apple devices, use their native Settings and
Apple security content page.

Install a vendor-supported update, restart as required, confirm the
active version with the *matching* Apple bulletin. The Python checker
**intentionally does not return 'fixed' for Apple numeric comparisons**.

**Smoke test:** load trusted pages in Safari, validate ordinary authenticated
navigation for a nonproduction test account, and observe stability.
Do not reproduce the cookie-exfiltration exploit.

## Android: the reported lock-screen bypass

The October 27 Anthropic article says Google addressed the Android/Pixel
chain but does **not** provide a public mapping to CVEs, Play services
versions, firmware releases, or Android security patch level. The Google
October 2026 Android Security Bulletin describes many CVEs but
**does not by itself establish which fixed this Anthropic chain**.

Review device vendor Security & Privacy / System Update, Google Play System
Update and Google Play services updates separately. After update and reboot
record device model and installed OS/security patch level. Until an exact
vendor advisory mapping exists, mark this specific chain **UNKNOWN**.

## Unsupported versions and forks

If your OS/browser/device cannot receive a vendor-supported update, this
repository cannot manufacture a safe binary patch. Document end-of-support
status and plan a supported upgrade, replacement, or vendor-approved interim
workaround. Never treat "newest available for EOL" as "all CVEs patched."

## CI checks vs deployed security

CI validates JSON structure, release-floor comparison behavior and static
Linux C fixture handling. It does not install vendor updates, execute a
real kernel, run malware or prove exploit resistance. A successful CI badge
does not certify any organization's endpoint security.


## Temporary containment validation (new)

| Tool/control | Verify what | Cannot prove |
| --- | --- | --- |
| `python scripts/mptcp_guard.py status` | MPTCP sysctl is `0` in **this** network namespace | Running kernel is patched, pre-existing MPTCP sockets gone, other namespaces protected |
| Windows HTTP.sys containment | Administrator-confirmed HTTP/3 exposure restriction and normal HTTPS/TCP operation | All HTTP.sys exploitation routes are blocked or all HTTP/3 servers stopped |
| Safari JavaScript setting | Settings show **Enable JavaScript** disabled | WebKit bug absent or all Safari attack vectors blocked |
| Chrome V8 optimizer setting | The browser UI shows the opt-in restriction | All Chrome CVEs or sandbox-escape chains are mitigated |
| Android physical USB precautions | Operator physical access precautions and exact update history | Lost devices or all lock-screen bypasses are protected |

Full per-OS steps: `docs/EASY_INSTALL.md`. Official-vendor transition:
`docs/EMERGENCY_CONTAINMENT.md`. Review the code before using any
privileged command. For Windows and browsers the repository offers
operator guidance **only**; it never edits their system configuration.

For version-floor-eligible products, `scripts/vendor_handoff.py` only
returns `READY_FOR_CHANGE_REVIEW` after a published floor is met and the
operator explicitly attests to reading the vendor source, checking the
active version and passing benign tests. That is not an automatic
machine inspection, compliance finding, or claim of exploit resistance.
