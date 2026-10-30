**New users:** follow [Easy install](EASY_INSTALL.md) first. For safety/rollback read [Emergency containment](EMERGENCY_CONTAINMENT.md).

# Safe update routes for supported platforms

**Not a universal patch command.** This guide helps people reach official
updates while avoiding arbitrary binaries. Each command changes software —
read your vendor's release notes, back up, and follow your site's maintenance
and reboot procedures. The catalog checker itself never changes software.

## Linux distributions (examples)

First identify your vendor and **supported OS release**:

```sh
cat /etc/os-release
uname -r
```

**Debian / Debian-derived systems using APT** (verify the security repository
is configured and that the package has a vendor CVE fix before assuming it
protects the running kernel):

```sh
sudo apt-get update
sudo apt-get upgrade
```

If Debian's security advisory names specific binary packages, follow the
advisory's package names rather than assuming an upstream version string.
Vendor source: https://www.debian.org/security/faq.en.html

**Fedora and DNF-based systems:** supported releases may use:

```sh
sudo dnf upgrade --refresh
```

This does not switch to a newer major Fedora release. For unsupported/EOL
releases, upgrade using the distribution's documented migration process.
Use the official distro advisory and package signature to confirm the CVE.

**openSUSE / SUSE systems:** use the vendor's published patches:

```sh
sudo zypper patch
```

A system whose repositories do not publish a given patch **cannot be
declared fixed just because this command succeeds**. Check SUSE's published
CVE patch details and product applicability:
https://scc.suse.com/psearch

**Arch and other rolling distributions:** follow your distribution's
documented full-system update procedure and validate the installed package
against its security advisory. Avoid applying cherry-picked patches to a
partially updated dependency set.

For kernel changes, reboot when required and validate the **running**
kernel, not only the installed package. For CVE-2026-98432 see
`docs/LINUX_CVE-2026-98432.md`.

## Windows clients and servers

Use Settings → Windows Update → Check for updates → Download & install,
or your organization's approved Windows Update/WSUS/Intune channel.
Restart when prompted. Check the edition/build against the Microsoft CVE
record before calling it fixed.

Official update instructions:
https://support.microsoft.com/en-us/windows/deployment/updates-lifecycle/install-windows-updates

The **Windows 11 vs Server 2025 build 26100 distinction** is documented in
`docs/VALIDATION.md`.

## macOS, iPhone, iPad, and other Apple devices

Use Apple Software Update for the *device's supported software branch*,
then read the Apple security-content entry for that exact OS and Safari
version. Old devices may not receive all current fixes; this repo cannot
invent support or substitute an unsigned WebKit binary.

Apple's referenced CVE record:
https://support.apple.com/en-us/127594

## Google Chrome Stable

Open `chrome://settings/help`, allow the **official Google updater** to
install the available Stable build, relaunch, and compare the running version
to the advisory. Version floors in this repository do not automatically
apply to Chromium-derived browsers or Android WebView.

## Android / Pixel

Use the OEM's System/Security Update and Google Play system update, plus
Play services updates where the OEM/advisory requires them. Do not assume
the October Android security patch level contains Anthropic's lock-screen
chain fix unless Google publishes a corresponding mapping.

## If the release cannot be updated

Record that the OS is unsupported or vendor fix unavailable, and plan
upgrade/replacement or vendor-approved containment. No OS-independent
patch file can retroactively make all unsupported operating systems safe.
