# October 30, 2026 — CVE patch and containment handoffs

**No automatic binary installation, host firewall change, or firmware flash.**
These records provide read-only vendor update and conditional containment guides.
A fixed version listed by a vendor does not prove that an endpoint is patched.

## Eight added CVEs

| CVE | Affected product | Vendor patch target | Temporary control |
| --- | --- | --- | --- |
| CVE-2026-107347 | Nomad dispatch/log writes | Community **2.1.1**; Enterprise **2.1.0+ent**, **1.11.12+ent**, **1.10.18+ent** | Review untrusted job submit/dispatch permissions |
| CVE-2026-119168 | Nomad sticky-disk migration | Same Nomad release branches | Review job update and same-client allocation reuse permissions |
| CVE-2026-76024 | Official desktop Chrome Stable | **156.0.8078.79** or later on Windows/macOS/Linux | Avoid untrusted browsing until signed update and relaunch |
| CVE-2026-92744 | Delinea Privilege Manager **Windows Core Agent** | 12.x **12.0.5804+**; 13.x **13.0.2064+** | Inbound TCP **5593** block or source restriction per Delinea |
| CVE-2026-103093 | ServiceNow AI Platform **service** | Branch-specific ServiceNow hotfix, confirmed via KB3228994 | Minimize unnecessary admin roles pending patch |
| CVE-2023-22793 | Veeam Management Pack Virtualization Extensions | **13.1.0.334** | Limit management-plane exposure |
| CVE-2026-107238 | Veeam Management Pack Collector | **13.1.0.334** | Limit management-plane exposure |
| CVE-2026-107239 | Veeam Management Pack Collector | **13.1.0.334** | Review privileges and Veeam user groups |

## Conditions and limitations

**Nomad correction:** Both HashiCorp bulletins were corrected on October 30.
Community **2.1.0 is not fixed**. Enterprise releases are separate.
Check the edition and running version for all affected clients. Do not perform
numerical comparisons across Community and Enterprise release branches.
Restricted ACLs reduce opportunity; they are not a validated symlink fix.

**Delinea TCP 5593:** Delinea documents blocking inbound TCP 5593; for
on-premises installations it can change policy delivery to scheduled polling.
Review revocation/policy timing with the endpoint owner before changing GPO
or host firewall policy. Never fabricate management-server IP addresses.
Record rollback of any centrally managed rule. No firewall writes are shipped.

**Nomad Enterprise branch caution:** The current HCSEC-2026-52/-53
bulletins list specific Enterprise release lines, while the Nomad 2.1.1
release announcement says 2.1.0+ent was released without some security
patches. Until the exact build contents are independently confirmed, require
vendor verification for the Enterprise 2.1.0+ent path. The checker does not
automatically clear any Nomad branch.

**Veeam upgrade prerequisite:** KB4949 states the supported upgrade to
13.1 requires **9a build 9.1.0.3107** first. Older builds may need a
separate supported upgrade. A Management Pack version is not a Windows
OS version or a Veeam Backup & Replication version.

**ServiceNow:** This is a hosted or self-hosted *service* issue, not a local
OS issue. Hosted customers should confirm ServiceNow deployment status;
self-hosted customers need the vendor-approved branch-specific update.
An `admin` role review reduces access, not the vulnerability itself.
Some branch details may require a ServiceNow Support login.

**Chrome:** Google rates CVE-2026-76024 Critical; other assessments may
differ. Severity is not proof of active exploitation. Do not apply the
desktop Chrome version floor to ChromeOS, Android/iOS, or other Chromium forks.

**Historical hardware watch:** No standalone hotfix is claimed here for the
previously discussed Moxa unsupported-device/SMS issue or TianoCore EDK II
OEM firmware mappings. Source-level changes do not establish that a
specific hardware manufacturer's firmware image is fixed. Obtain model-
specific signed firmware and vendor evidence; do not flash automatically.

**All operating systems:** A product CVE only applies where the named
software is installed. No universal hotfix exists for Windows, Linux,
macOS, Android, iOS, or firmware; use official vendor updates for each
supported target.

## Read-only commands

```sh
python scripts/catalog.py validate
python scripts/quickstart.py validate
python scripts/catalog.py list
python scripts/quickstart.py guide --os linux --id CVE-2026-107347
python scripts/quickstart.py guide --os windows --id CVE-2026-92744
python scripts/quickstart.py guide --os service --id CVE-2026-103093
python scripts/quickstart.py guide --os windows --id CVE-2026-107239
python scripts/catalog.py check CVE-2026-76024 --platform linux --version 156.0.8078.79
python scripts/catalog.py check CVE-2026-107239 --platform windows --version 13.1.0.334
```

Pass the *actual installed product version* to the checker, **not**
the host OS version. An exit code of zero means the reported matching
product/build meets the published floor, not successful local installation
or tested exploit resistance.

## Vendor sources checked October 30, 2026

- [HashiCorp HCSEC-2026-52](https://discuss.hashicorp.com/t/hcsec-2026-52-nomad-dispatch-payload-writes-can-escape-the-allocation-directory-through-symlinks/77930)
- [HashiCorp HCSEC-2026-53](https://discuss.hashicorp.com/t/hcsec-2026-53-nomad-allocation-data-migration-may-allow-host-directory-permission-modification-via-symlink-following/77931)
- [Nomad 2.1.1 release](https://discuss.hashicorp.com/t/nomad-v2-1-1-released/77928)
- [Chrome Stable release](https://chromereleases.googleblog.com/2026/10/stable-channel-update-for-desktop_02107719452.html)
- [Delinea security advisory](https://delinea.com/security-advisories)
- [Delinea Windows agent release notes](https://docs.delinea.com/online-help/privilege-manager/release-notes/13.0.0.htm)
- [Delinea TCP 5593 agent ports](https://docs.delinea.com/online-help/privilege-manager/install/agents/agent-ports.htm)
- [ServiceNow customer bulletin KB3228994](https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB3228994) (may require login)
- [Veeam KB4961](https://www.veeam.com/kb4961)
- [Veeam supported upgrade requirements KB4949](https://www.veeam.com/kb4949)

**Still unverified:** patch deployment on live endpoints, production firewall
policy effects, real Nomad allocation boundary resistance, ServiceNow
instance hotfix state, and Veeam collector/SCOM operation after upgrade.
