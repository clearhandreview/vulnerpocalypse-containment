# Easy setup — temporary protection and real vendor updates

**Choose your device below.** This repository is a free reference/checking toolkit,
not a replacement for Apple, Microsoft, Google, Linux-distribution or OEM security updates.

**Rule:** a temporary control can reduce exposure. It cannot certify that vulnerable
code was repaired. When an official security update exists, install it first.

Before any change, save your work, back up the system, and allow time for a restart.
For managed work devices, ask the IT administrator. **Never paste a terminal command
from an untrusted source into an elevated prompt.**

## Windows 10/11 and Windows Server

**Install the real fix:**
1. Open **Start → Settings → Windows Update → Check for updates**.
2. Install approved **security updates** (or use the company's WSUS/Intune process).
3. Restart when asked. On servers, schedule an outage before restarting anything.
4. Open **Win + R → `winver`** and note the full Windows version/build.
   For CVE-2026-33096, use the full four-part build from `docs/VALIDATION.md`.
5. Open Microsoft's [Security Update Guide](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33096)
   and check that it covers your *exact* Windows edition/build.

**Temporary containment when you cannot yet update an HTTP.sys server:**
ask a server administrator to restrict HTTP/3 per the vendor documentation,
then check that normal HTTPS works. Do not run an unknown registry script.
See `python scripts/quickstart.py guide --os windows`.

**After the fix:** compare the active build, test ordinary website/service
requests, then remove temporary HTTP/3 restrictions under a change ticket.

**If Microsoft no longer supports your OS:** do not infer that its newest
available patch is sufficient. Plan a supported OS upgrade or isolation.

## Mac / macOS and Safari

**Install the real fix:**
1. Open **Apple menu → System Settings → General → Software Update**.
2. Install the newest supported **security update** and restart if requested.
3. Use **Safari → About Safari** to see the actual browser version.
4. Compare your *device, macOS branch and Safari build* with the
   [Apple security advisory](https://support.apple.com/en-us/127594).

**Temporary risk reduction:** On Mac, Safari → Settings → Security →
turn off **Enable JavaScript** if needed. Many websites will stop working.
This **does not prove** the WebKit flaw is blocked. For higher-risk browsing,
stop using the outdated browser until its vendor fix is active.

**After the fix:** confirm version, try trusted pages, then restore your
approved JavaScript setting.

## iPhone and iPad (iOS / iPadOS)

**Install the real fix:**
1. Open **Settings → General → Software Update**.
2. Install the device's supported Apple update.
3. Return to **Settings → General → About** and note the installed version.
4. Check the Apple security-content bulletin for your **exact device and OS**.

**Temporary period:** Avoid untrusted links and risky browsing on an
unpatched device. This is not a complete workaround for WebKit.
Apple mobile security patches are **not** replaced by a desktop Python script.

**After the fix:** restart if requested and test ordinary Safari browsing.

## Android and Google Pixel

**Install official updates:**
1. Open **Settings → System → Software updates** (the menu can vary).
2. Install **Android/device security updates** from your phone maker.
3. Also check **Google Play system update** in **Security & privacy**.
4. Record the **phone model, Android security patch level, and Google Play
   system update date**.
5. Compare with the manufacturer's security advisory. For Anthropic's
   Android lock-screen chain there is **no verified public CVE-to-fixed-build
   mapping in this repository**. The result stays **UNKNOWN**.

**Temporary precautions:** Keep control of the phone and avoid connecting
it to unknown USB hosts/accessories. This does not secure a lost or stolen
vulnerable phone.

**After the fix:** record exact vendor fix mapping when it becomes available.
Never flash a community-supplied or unsigned phone image to "fix" this report.

## Linux: Ubuntu / Debian / Fedora / RHEL / SUSE and other distributions

**Install the real fix:**
1. Open a terminal and run `cat /etc/os-release` to identify your distribution.
2. Use **your distribution's supported package manager** to install its
   published security fixes:
   - Ubuntu/Debian: `sudo apt-get update && sudo apt-get upgrade`
   - Fedora / supported DNF systems: `sudo dnf upgrade --refresh`
   - openSUSE / SUSE: `sudo zypper patch`
   - Other distributions: follow their own official security instructions.
3. **Restart** after a kernel update.
4. Run `uname -r` and look up the exact running kernel package in the
   distribution's **CVE-specific advisory**. Backports mean the kernel
   version alone may not reveal the patch.

**Temporary Linux-only control for CVE-2026-98432 on a potentially exposed
MPTCP host**, if the vendor kernel fix cannot yet be activated and disabling
MPTCP is operationally acceptable:

```bash
python3 scripts/mptcp_guard.py status
# Review possible service interruption first. Then, on the Linux host:
sudo python3 scripts/mptcp_guard.py apply --accept-service-disruption
python3 scripts/mptcp_guard.py status
```

The helper changes only the **runtime sysctl for the current network
namespace** and records the prior value in `/run`. It will not make a
persistent change across reboot. Existing MPTCP connections and other
namespaces are **not** checked or protected by this command. Restart affected
listeners in a maintenance window. If the system is not Linux, or the sysctl
doesn't exist, it refuses the operation.

**After the signed vendor kernel fix is active**, and if you are still in
the same boot and namespace:

```bash
sudo python3 scripts/mptcp_guard.py rollback --accept-reexposure
python3 scripts/mptcp_guard.py status
```

After a reboot, first inspect the current value; the runtime control can
have reverted, and the rollback state in `/run` is normally gone.
**Do not assume that `status: 0` proves the CVE is fixed.** A broken
MPTCP-dependent service is a possible side effect. Review in
`docs/EMERGENCY_CONTAINMENT.md`.

## Google Chrome on Windows, Mac, and Linux

1. Open **Chrome → More → Help → About Google Chrome** or
   `chrome://settings/help`.
2. Let Google's signed updater install the available Stable release.
3. **Relaunch** Chrome.
4. Open **About Chrome** again and check the *active* version. Use
   `python scripts/catalog.py check CVE-2026-118306 --platform windows --version YOUR.FOUR.PART.VERSION`
   with the real Windows/Mac/Linux platform.
5. Test trusted pages and your normal sign-in flow.

Temporary option: Chrome → Settings → Privacy and security → Security →
**Manage JavaScript optimization & security** → **Don't allow sites to use
JavaScript optimization**, where supported. This is **not a proven fix** for
the multi-CVE Chrome chain; prefer to stop using the affected build until
the signed update arrives.

## Other Apple systems: watchOS, tvOS and visionOS

Use your device's or its paired iPhone's **Settings → Software Update**
process, following Apple's instructions for that product. Verify the
software version and exact security advisory. This repository has **no
one-click installer** for these devices.

## ChromeOS, BSD, other mobile systems, forks and unsupported releases

Use the device vendor or distribution's **official** security updater.
If a matching, published fix is unavailable, mark it **UNKNOWN**. Do not
run Linux-specific sysctl changes on other kernels. For unmaintained
devices, arrange isolation, a supported replacement, or professional help.

## Always confirm the transition — five checks

1. **Vendor published the fix** for your exact product, OS branch and device.
2. **Official updater installed it** and the package/signature is trusted.
3. **Updated software is active** after its restart/reload.
4. **Normal use works**: web browsing, network service and expected features.
5. **Remove temporary restrictions carefully**; verify the re-enabled
   service works. Keep the temporary control until the change is approved.

The CLI can help with version floors:

```bash
python scripts/vendor_handoff.py CVE-2026-33096 --os windows --version 10.0.22631.6936 --vendor-advisory-reviewed --active-version-confirmed --smoke-test-passed
```

Those three switches are **human statements**, not detection or proof.
A `READY_FOR_CHANGE_REVIEW` result is **not** permission for automatic rollback.
For Linux, Apple and Android the tools require manual matching vendor
evidence; they must not invent a fixed version.
