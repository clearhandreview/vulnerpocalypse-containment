# Linux distributions, languages and hardware — read-only coverage

This is **device and runtime discovery**, not automatic CVE detection or patching.
The toolkit does not modify installed software, kernel packages, firmware, or
network controls when running `scripts/platform_inventory.py` or
`scripts/catalog.py inventory`.

## Run on a computer with Python 3.11–3.15

```sh
python3 scripts/platform_inventory.py --json
# The existing catalog inventory now includes the same details:
python3 scripts/catalog.py inventory
```

The JSON reports the host OS, a Linux `os-release` identity when available,
architecture, limited system manufacturer/model information (Linux DMI if
readable), UEFI detection, `fwupdmgr` command presence, and whether common
language toolchain and package-tool executables are on `PATH`. It **does not run** those
executables or contact repositories. It does **not** read device serial
numbers, license keys, package manager databases, firmware images or secrets.

`toolchains.*.detected_commands` means **command found**, not installed
version, correct package origin, security support or CVE status. Package
managers also install libraries, drivers and software the language toolchain
inventory does not discover. The Python currently running the inspector
requires the documented Python version.

## Distribution-specific update routes

The `common_update_tool` field identifies a usual **review route** only
for known distribution IDs. There is no built-in auto-updater.

| Distro or family | Typical manager | Vendor-side review |
| --- | --- | --- |
| Ubuntu, Debian, Raspberry Pi OS / Raspbian, Mint, Pop!_OS, Kali | `apt` | Distro security notices, repositories, release and backports |
| Fedora, RHEL, Rocky, AlmaLinux, CentOS, Oracle Linux, Amazon Linux | `dnf` | Exact vendor/major version and supported repositories |
| openSUSE, SLES / SLED | `zypper` | Exact product stream and SUSE advisory |
| Arch, Manjaro, EndeavourOS | `pacman` | Full-system update policy of the actual derivative |
| Alpine | `apk` | Branch, repository and diskless/embedded boot mode |
| Void | `xbps-install` | Repository/architecture; XBPS self-update staging |
| Gentoo | `emerge` | Repository sync, profile/use flags and rebuilt dependencies |
| NixOS | `nixos-rebuild` | Channel/flake lock, generation and rollback plan |
| Fedora Atomic desktop (Silverblue, Kinoite, etc.) | `rpm-ostree` | Deployment and reboot; not the usual DNF path |
| Flatcar, Bottlerocket, ChromeOS, SteamOS, appliance images | **Vendor managed** | Platform image, device and supported update mechanism |
| Unknown derivatives with only `ID_LIKE` | **No inferred command** | Use the derivative's own official instructions |

This list indicates known **routes**, not validated releases or hardware
compatibility. A derivative's `ID_LIKE=ubuntu` cannot prove it uses Ubuntu
repositories or is safe to upgrade with Ubuntu commands. A package tool may
also be absent despite the distro ID. For distro commands, see
[Safe update routes](UPDATE_GUIDE.md).

WSL and containers may report a distro running on a host-controlled kernel.
A distro package update from inside a container or WSL does not establish the
host kernel or physical firmware is patched. Also distinguish host operating
system security from software supplied by containers, Flatpak/Snap, virtual
machines, language package ecosystems and cloud services.

## Language ecosystems

Discovery includes Python, JavaScript/TypeScript runtimes (Node, Deno, Bun),
Go, Rust, Java, C, C++, C#/.NET, Ruby, PHP, Perl, Lua, Swift, Kotlin,
Dart, R, Julia, Elixir, Erlang, Haskell, Zig and common shells.

The scanner does not infer transitive dependency versions. For source and
applications built in those languages, use the relevant lockfile, signed
vendor advisory, and appropriate audit/SBOM tooling. Language support never
implies that every package, executable, or embedded library has been scanned.
Use the product-specific `catalog.py check` only where an official version
floor is documented for **that product and platform**.

## Devices and firmware

Linux desktop/server, Raspberry Pi OS and many compatible embedded Linux
machines can run the Python inventory **if a supported Python is available**.
Embedded routers, BMCs, industrial controllers, IoT, mobile devices and
locked-down appliances may not permit running it. Windows/macOS can collect
basic OS and executable-presence hints; the Linux-specific sysfs/DMI
fields are not available there. Android under Termux is identified as
Android when Android environment variables are present, not as Ubuntu.

A detected UEFI environment, model, or available `fwupdmgr` **does not
confirm** a manufacturer's UEFI patch. For firmware CVEs, obtain the signed
OEM update and verify applicability and installation through OEM records;
where evidence is absent, report **unknown**. No firmware flashing or
automatic package installation is provided.

## Evidence needed to mark a host fixed

1. A specific disclosed CVE applies to the exact hardware/software
   product, release, edition and architecture.
2. The vendor names a supported, fixed package/firmware/application build.
3. Installation is confirmed and the **running** version or booted image is
   checked after any required restart.
4. A benign functionality check passes and relevant temporary restrictions
   are reviewed before rollback.

If one part is unknown, the result remains **unknown**. A broad inventory
cannot turn an unknown CVE into a fixed claim.

## Official update documentation

- Debian: https://www.debian.org/security/faq
- Fedora Atomic desktops: https://docs.fedoraproject.org/en-US/fedora-silverblue/
- Alpine: https://wiki.alpinelinux.org/wiki/Apk
- Void: https://docs.voidlinux.org/xbps/
- NixOS: https://nixos.org/manual/nixos/stable/
- Other distributions: review official distribution documentation for the
  exact installed version before using privileged update commands.
