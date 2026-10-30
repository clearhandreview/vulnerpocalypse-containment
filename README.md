# Vulnerpocalypse Fix Ledger — cross-platform security-update evidence toolkit

[![Offline tests](https://img.shields.io/badge/tests-offline%20only-blue)](#verification-and-testing)

**Maintained catalog, not a universal zero-day patcher.** This project tracks
publicly disclosed security fixes linked to Anthropic/Claude security research.
It contains an **attributed original Linux upstream patch** for
CVE-2026-98432, **vendor update references** for proprietary or
signed products, a cross-platform **read-only** version-floor checker,
and an optional Linux-only temporary runtime control with explicit rollback.

> **No arbitrary kernel or binary modification, no automatic patch downloads,
> no exploitation tests, and no claim that every OS or every Anthropic finding
> is covered.** Optional, explicitly approved Linux runtime MPTCP containment
> is the only executable change introduced by this toolkit. If no verified vendor fix or supported release exists, the
> correct result is **unknown / manual review**, never “patched.”

## Start here — choose your operating system

**For the simplest instructions, open [Easy install](docs/EASY_INSTALL.md).**
Pick your device and follow its numbered steps. You do **not** need to
install Python on a phone. On computers, Python 3.11–3.15 is needed only to
run this repository's optional offline checking tools.

| Device | Quickest safe step | Optional containment |
|---|---|---|
| Windows | **Settings → Windows Update → Check for updates → Restart** | HTTP.sys HTTP/3 exposure review for administrators; not a binary patch |
| Mac | **System Settings → General → Software Update** | Safari JavaScript restriction; not a full WebKit fix |
| iPhone / iPad | **Settings → General → Software Update** | Avoid untrusted browsing pending Apple update |
| Android / Pixel | **Settings → System → Software updates**; check Google Play system updates too | Avoid untrusted USB hosts; not a device lock-screen fix |
| Linux | **Use your distro's signed security updates, then reboot** | Optional supervised, reversible MPTCP feature switch (Linux only) |
| Chrome | **Chrome → Help → About Chrome → Relaunch** | Limit V8 optimization or stop using outdated Chrome |
| Other / unsupported | **Use the original device vendor's published security update** | No universal cross-OS binary patch exists |

**Guide from a laptop/desktop (no root/admin rights needed):**

```bash
python scripts/quickstart.py guide --os linux
python scripts/quickstart.py guide --os windows
python scripts/quickstart.py guide --os macos
python scripts/quickstart.py guide --os android
```

Each guide provides: *before you change anything → simple steps → how to
verify the temporary control → how to replace it with the vendor fix.*
If a profile cannot be justified, the command returns **no verified profile**.

**One executable temporary control:** Linux MPTCP runtime disable.
It modifies the current namespace only after a separate, explicit administrator
command, creates limited rollback state, and does NOT patch the kernel or
persist across reboot. See [Emergency containment](docs/EMERGENCY_CONTAINMENT.md).
All other temporary actions are **manual guidance**, not unsigned binaries.

### How to know a real patch is applied and working

**Do not treat a successful install command as proof.** Record these separately:

1. The official vendor advisory names the CVE **and your exact OS/device**.
2. A signed update was installed; the device or affected service was restarted.
3. The **running** product or kernel package is at a vendor-confirmed fixed release.
4. A benign normal-use check succeeds, such as visiting a trusted page or
   testing authorized network connections; verify service logs.
5. Only then, review removing the temporary containment and check function again.

`docs/VALIDATION.md` has exact commands and an evidence worksheet. For some
products (including Android's unmapped chain and vendor-backported kernels),
the result must remain **unknown / manual review** without vendor proof.

**Assisted vendor handoff**, for products with a published, comparable version
floor (example uses an existing MSRC advisory):

```bash
python scripts/vendor_handoff.py CVE-2026-33096 --os windows --version 10.0.22631.6936 --vendor-advisory-reviewed --active-version-confirmed --smoke-test-passed
```

The flags are **operator attestations**, not automated detection. The strongest
result is `READY_FOR_CHANGE_REVIEW`, never an automatic rollback or claim of
exploit resistance. OS versions without a verified release floor are held
for manual vendor confirmation.

### What about vulnerabilities with no vendor patch?

**No code patch is made up for an undisclosed flaw.** Most entries in
[Anthropic's disclosure dashboard](https://red.anthropic.com/2026/cvd/)
do not expose enough technical data to write or validate a legitimate fix.
A kernel/device "universal hotfix" cannot safely be synthesized from a CVE
name or a hashed disclosure. Use a source-backed, reversible containment
where available; otherwise isolate or stop using the affected service.

The `data/containments.json` catalog contains **five conditional,
limited exposure-reduction guides**. These do not establish CVE remediation.
A new automatic patch is accepted only after source code, reproducible
vulnerability, supported versions, regression tests, rollback and review
have been established. See [Contribution rules](CONTRIBUTING.md).

## Current scope — reviewed October 29, 2026

The curated `data/advisories.json` contains **19 individually identified CVEs**
across **8 advisory records**. The source for each record is linked inside the
catalog. The Chrome list is limited to CVEs explicitly credited to Anthropic,
Claude, or their research partners in the selected Google release notices —
**not** the 62 Chrome CVEs Anthropic describes collectively, and **not** the
thousands of entries on Anthropic's broader disclosure dashboard.

| Component | Included identifiers | How the fix is obtained | How to validate |
| --- | --- | --- | --- |
| Linux IPv4 TCP | CVE-2026-98432 | Distribution-maintained kernel update, or attributed upstream source patch for maintainers | Compare vendor advisory and installed *running* kernel package; optional source checker |
| Windows HTTP.sys | CVE-2026-33096 | Microsoft Update / WSUS / enterprise deployment | Installed Windows build **and** correct client/server edition; MSRC applicability |
| Safari / Apple WebKit | CVE-2026-43715 | Apple Software Update / supported device updates | Actual Safari/OS release and matching Apple security bulletin |
| Google Chrome Stable | 16 CVEs named in `data/advisories.json` | Google's signed browser stable update | Confirm **running** official Chrome Stable version is at least the cited release floor |

**Additional unresolved:** Anthropic's Android/Pixel lock-screen-chain
report does not disclose a verifiable CVE-to-fixed-build mapping. That case is
recorded in `unresolved`, not falsely labeled fixed. Hash-only disclosure
ledger entries cannot be turned into independently validated patches.

Sources: [Anthropic's October 27 report](https://www.anthropic.com/research/discovering-vulnerabilities-with-claude),
[Anthropic's disclosure dashboard](https://red.anthropic.com/2026/cvd/),
[Google Chrome releases](https://chromereleases.googleblog.com/),
[Apple security content](https://support.apple.com/en-us/127594),
[Microsoft MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33096),
[Linux kernel advisory](https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/refs/heads/master/cve/published/2026/CVE-2026-98432.mbox).

## Requirements

**ASSUMING:** Python 3.11–3.15 on Windows/macOS/Linux, standard library only.
The read-only catalog and quickstart tools need no administrator/root rights
and do not contact the network. **Exception:** the opt-in Linux MPTCP runtime
containment requires an explicit elevated command and can affect services.
iOS/iPadOS/Android devices use their vendor-native update UI; the Python CLI
does **not** run on those devices as an installer.

## Quick start — inventory and compare, never automatically apply

From this repository's root:

```shell
python scripts/catalog.py validate
python scripts/catalog.py list
python scripts/catalog.py unresolved
python scripts/catalog.py inventory
```

Find the real **installed product version** *after* updating it, then compare:

```shell
# Exact Google Chrome Stable release, not Chromium, Edge or an OS version:
python scripts/catalog.py check CVE-2026-118306 --platform linux --version 156.0.8078.79

# Windows: full 10.0.<build>.<UBR> installed OS version
python scripts/catalog.py check CVE-2026-33096 --platform windows --version 10.0.22631.6936

# Critical: Windows 11 and Windows Server 2025 both use build 26100.
python scripts/catalog.py check CVE-2026-33096 --platform windows --version 10.0.26100.32690 --variant server

# No automatic status asserted for vendor-specific Linux or Apple builds:
python scripts/catalog.py check CVE-2026-98432 --platform linux --version 7.3.0.0
```

`check` outcomes are deliberately bounded:

| Result | Meaning | Exit code |
| --- | --- | --- |
| `meets_published_release_floor` | User-supplied product/version is at or above a verified release floor for the **listed CVEs**, **assuming correct product and vendor** | `0` |
| `below_published_release_floor` | It is below that version floor for a matching listed product | `1` |
| `manual_vendor_confirmation_required` | Insufficient evidence, differing OS/product branch, an unknown fix, or unrecognized version | `2` |

**Exit 0 is not “exploitation is impossible.”** It does not certify the vendor
binary, update provenance, successful reboot, or every CVE on the machine.

### Download and install the *real* fix

Use official vendor-delivered updates rather than applying arbitrary patch
files found on GitHub. The checker NEVER installs anything.

| System | Supported update path |
| --- | --- |
| Windows 11 / Windows Server | Windows Update, approved WSUS/Intune/enterprise package, Microsoft Update Catalog, MSRC bulletin |
| macOS / Safari | System Settings → General → Software Update; Safari → About Safari |
| iPhone / iPad | Settings → General → Software Update |
| Android / Pixel | Settings → System → Software updates, plus Google Play system update and Play services as applicable; no claimed fix mapping yet for Anthropic's lock-screen chain |
| Linux distributions | Distro security repository and vendor bulletin for **exact kernel package** (Debian/Ubuntu, Fedora/RHEL, SUSE, etc.); reboot into updated kernel |
| Google Chrome | Google-signed official Chrome stable updater on Windows/macOS/Linux, then restart browser |

Unsupported and end-of-life OS versions might **not have a secure update
available**. Upgrade to a supported release or apply vendor-supported
isolation/retirement procedures. Never attempt cross-OS binary patching.

## How to validate the patch is applied **and working**

**Perform these four independent checks**, recording results in the
[validation worksheet](docs/VALIDATION.md):

1. **Applicability:** Identify exact product, edition, architecture, channel,
   OS branch, running build, and vendor advisory. Check that the CVE actually
   affects that product; do not infer applicability from an OS name alone.
2. **Installed fix:** Obtain the official update from a signed vendor channel.
   Record update ID/build, package origin and signature where supported. Use
   `catalog.py check` only where the release-floor mapping is explicit.
3. **Running fix:** Restart the browser/service or reboot the OS **when the
   vendor requires it**. Re-read the currently running version and compare
   it to the applicable vendor bulletin. A downloaded or installed package
   that has not been activated is insufficient evidence.
4. **Functional verification:** Verify normal functionality (Chrome launches,
   a test page loads; a Windows HTTP/3 service returns an ordinary authorized
   response; Linux networking and MPTCP workloads behave normally; Safari
   loads a trusted page). Record logs/health checks. This is a **smoke test**,
   not proof of exploit resistance. Independent exploit-resistance validation
   is outside this repository and should be conducted only by authorized
   specialists in an isolated environment.

Platform-specific exact commands, Windows 26100 edition handling, kernel
source review, and the limits of each check: **[docs/VALIDATION.md](docs/VALIDATION.md)**.
For supported-platform updating instructions, see
**[docs/UPDATE_GUIDE.md](docs/UPDATE_GUIDE.md)**.

### The Linux source patch (maintainers only)

The **only locally bundled `.patch`** is the attributed upstream
Linux commit `e3f33b0a1d89d738e2b913dab519226eaf76e15b`:

```shell
python cve98432.py host --json
python cve98432.py inspect-source /path/to/linux --json
# If inspection confirms the exact vulnerable source patterns:
python cve98432.py prepare-patch /path/to/linux > candidate.patch
git -C /path/to/linux apply --check /absolute/path/to/candidate.patch
```

Do not apply a source patch to a running system or to an unmatched distro
branch. Read [the complete Linux-specific instructions](docs/LINUX_CVE-2026-98432.md).
Source matching is not an assurance about a compiled, deployed kernel.

## Repository contents

```text
data/advisories.json        Curated, attributed CVE/fix catalog
data/containments.json      Verified-source, limited temporary controls
scripts/quickstart.py       Plain-language per-OS containment + handoff guide
scripts/vendor_handoff.py   Human-reviewed vendor update transition gate
scripts/mptcp_guard.py      Opt-in Linux-only MPTCP runtime control
docs/EASY_INSTALL.md        Short step-by-step guide for major OSes
docs/EMERGENCY_CONTAINMENT.md  Preconditions, impact and rollback limits
docs/QA_QC_SENTINEL.md      Internal defect review, validation and gaps
scripts/catalog.py          Offline list, validate, inventory, release-floor check
cve98432.py                 Linux-specific source checker + patch proposal
patches/                    Original attributed upstream Linux patch
tests/                      Offline tests; no exploitation
docs/VALIDATION.md          How to confirm installed AND running fixes
docs/UPDATE_GUIDE.md        Official update paths for supported OSes
docs/LINUX_CVE-2026-98432.md   Original kernel repair guide
CONTRIBUTING.md             How to add verified public fixes
GITHUB_SETUP.md            How to publish or update an existing GitHub repo
SECURITY.md                 Responsible disclosure/reporting boundaries
.github/workflows/tests.yml  Multi-OS, multi-Python automated tests
```

## Verification and testing

```shell
python -m unittest discover -s tests -v
```

CI is configured to test the scripts on Windows, macOS, and Linux (hosted runs not yet executed). Synthetic Linux C fixtures
only: **no real kernel compilation, no live exploit tests, no cross-platform
security certification**. See `TEST_RESULTS.md` for the last local run.

## Maintain and grow this repository

For each new public CVE, submit a PR updating `data/advisories.json`
with the **original vendor advisory**, independently verified fixed build /
upstream source commit if available, product-specific applicability, and a
non-destructive verification recipe. Run `python scripts/catalog.py validate`
and the offline tests. `CONTRIBUTING.md` explains the review criteria and
how to handle vendor backports, disclosures without identifiers, and
unavailable patches.

The repository **does not mirror proprietary OS binaries** and does not
silently turn unverified attribution, a bare CVE number, or a source commit
into a guaranteed installed fix.

## Licensing and credits

Original toolkit scripts/docs: MIT (`LICENSE`). The Linux source patch is
original upstream Linux work licensed under its upstream terms with original
credit retained (`NOTICE.md`). Security research is credited to the
researchers, vendors, and maintainers in the linked advisories.
This is an **independent community project, not an Anthropic, Microsoft,
Apple, Google or Linux Foundation endorsed updater**.
