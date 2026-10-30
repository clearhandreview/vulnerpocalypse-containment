# Supported systems and honest limits (2026-10-30)

This project does **not** certify that its controls are safe on every OS
version. Control applicability depends on the affected product, device
architecture, service state, distribution backports and vendor policy.

| OS / target | Official fix | Temporary control | Automated mutation | Proof missing |
| --- | --- | --- | --- | --- |
| Linux kernel on a maintained distro | Distro security update; upstream source patch for maintainers | MPTCP new-socket disable, only current namespace | **Opt-in Linux MPTCP sysctl only** | Real kernel test, all namespaces, running binary applicability |
| Windows desktop | Microsoft cumulative update | Restrict risky usage; administrator plan for an exposed HTTP.sys service | **No** | Broad client/Server/version implementation |
| Windows Server HTTP.sys | MSRC update for exact edition/build | Review HTTP/3 endpoint restriction | **No** | Effectiveness across all cohosted services |
| macOS Safari | Apple signed update | Disable Safari JavaScript if appropriate | **No** | All WebKit attack routes and app embeddings |
| iOS / iPadOS | Apple signed device update | Avoid risky browsing | **No** | Equivalent desktop control; exact branch |
| watchOS / tvOS / visionOS | Apple signed device update | None established | **No** | Applicable CVEs and device branch |
| Chrome Stable (Windows/macOS/Linux) | Signed Google browser update | Restrict V8 optimizer / pause affected browser | **No** | Protection from every Chrome exploit chain |
| Android / Pixel | Device & Play system updates, model-specific | Avoid unknown USB hosts | **No** | Public CVE-to-fixed-build mapping for reported chain |
| ChromeOS, *BSD and other OSes | Original vendor/distribution advisories | None established in this catalog | **No** | Version, applicability and vetted host-side control |
| End-of-life OS or firmware | **No guaranteed support** | Isolate or migrate | **No** | Trustworthy fix support |

Read `docs/EASY_INSTALL.md` before making changes and `docs/VALIDATION.md`
to decide whether a published fix is actively installed.

Never interpret the presence of the original Linux source patch in this
repository as proof that the installed kernel includes it. A patch file
and a patched, running kernel are different states.

## Additional product-specific handoffs (October 30)

Nomad on installed client platforms: Community 2.1.1 or the Enterprise
branch-specific fix; avoid untrusted workload privileges until deployment.
Chrome desktop: 156.0.8078.79 for CVE-2026-76024, not an Android/fork fix.
Delinea: Windows Core Agent only, with vendor TCP 5593 restriction.
ServiceNow: `--os service` for tenant-level remediation, not an OS fix.
Veeam: Windows Management Pack only, with 9a upgrade prerequisite.

See [October 30 vendor handoffs](2026-10-30-HOTFIX-COVERAGE.md).


## Expanded read-only discovery

`python3 scripts/platform_inventory.py --json` reports Linux distribution
identity and typical package-management **routes**, executable presence
for common language toolchains, architecture, and limited Linux firmware
context. It does **not** certify patch status, automatically update
packages, scan every software dependency, or detect all hardware.

Known distro IDs include Debian/Ubuntu derivatives, Fedora/RHEL,
openSUSE/SLES, Arch derivatives, Alpine, Void, Gentoo and NixOS.
Fedora Atomic desktops use a distinct `rpm-ostree` route. Vendor-image
systems and unknown derivatives receive no privileged upgrade command.
WSL, containers, Android, macOS and Windows are treated differently
from native physical Linux hosts. This is discovery, not testing
each distribution on a native machine.

For the actual coverage and limits, use
[Linux distributions, languages, hardware](LINUX_DISTRIBUTIONS_AND_RUNTIME_COVERAGE.md).
