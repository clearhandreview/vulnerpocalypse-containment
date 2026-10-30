# Supported systems and honest limits (2026-10-29)

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
