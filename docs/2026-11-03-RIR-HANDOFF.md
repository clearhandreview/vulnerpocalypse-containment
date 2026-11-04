# November 3 RIR security handoff — review-only integration

**Status:** Evidence ingestion and offline change-review planning only. **Not** 30 verified patches and
**not** a cross-OS installer. The source archive is `cybersecurity-handoff-2026-11-03(1).zip`;
its evidence cutoff is **2026-11-03 17:01:51.994 UTC**. Treat the original handoff as a
timestamped research snapshot, not an automatically refreshed vendor advisory.

## What is included

- `data/research_handoff_2026_11_03.json` preserves **64 source inventory records**, including
  detailed advisories, watch items, aliases, GitHub advisories and a non-CVE incident.
  Records keep their source URLs, qualified remediation, residual uncertainty and date.
- **30 previously untracked, detailed CVEs** were added to `data/advisories.json`; previously
  tracked CVEs were not duplicated. All new entries require manual vendor confirmation
  except a **limited Qt CoAP library release-train comparison**.
- **30 operator-reviewed containment/recovery guides** were added to
  `data/containments.json`. Their `steps` are human review text, not executable
  system modifications. The existing Linux MPTCP helper is unchanged.
- `scripts/research_handoff.py` validates, searches and proposes bounded RIR plans for
  the entire source inventory, including GHSA-only records.

**The 64 source records are not 64 distinct, confirmed, newly disclosed vulnerabilities.**
Watch-only leads, aliases and older records are retained with their original labels.
No vendor patch file, firmware image, system ACL, firewall rule or cloud configuration
is installed by this update.

## Example commands (Python 3.11–3.15, stdlib only)

```bash
python3 scripts/research_handoff.py validate
python3 scripts/research_handoff.py list
python3 scripts/research_handoff.py show CVE-2026-103653
python3 scripts/research_handoff.py plan CVE-2026-116606 --os network
python3 scripts/research_handoff.py plan GHSA-c46f-4v9j-5gpc
python3 scripts/catalog.py check CVE-2026-103653 --platform service --version 6.11.2
python3 scripts/catalog.py check CVE-2026-103653 --platform service --version 6.11.3
python3 scripts/quickstart.py guide --os network --id CVE-2026-116606
```

### RIR × Atelier safety architecture

The proposed target state is an exact running, vendor-corrected product with protected
credentials, intact authorization boundaries and healthy business services. For each
CVE or advisory:

1. **Observe** independently: asset inventory, branch, exact image, service owner,
   current traffic dependency, recovery evidence.
2. **Verify** affectedness and exact fixed artifact against a fresh vendor advisory;
   record the supported update route, including signed-firmware model compatibility.
3. **Propose** the smallest allowed interim boundary, if any. Do not declare it
   safe by graph calculations or unmeasured assumptions. Document application,
   authentication, control-plane, firmware and availability invariants.
4. **Authorize** externally via change control or incident command. An analyst
   recommendation cannot grant itself production privileges.
5. **Recover and validate** vendor-signed active artifact, possible prior compromise,
   independent business-service health and controlled recovery. No automatic rollback
   to a known-vulnerable image.

This follows the *RIR retrosynthetic* idea of selecting permitted changes that
preserve independently enforced invariants. No quantitative optimizer or threat
probability is claimed here: no service-specific costs or calibrated model inputs
were supplied. **All proposed changes remain unexecuted**.

## Load-bearing exceptions and examples

| Product / identifier | Handoff and independently verified limitation |
|---|---|
| **Qt CoAP — CVE-2026-103653** | [Qt advisory](https://www.qt.io/blog/security-advisory-cve-2026-103653) lists **6.8.9 LTS / 6.11.3 / 6.12.0** and paired source patches; exact SDK/deployment and linked application remain to be verified. Version checker only recognizes the listed numeric trains; unlisted releases return *manual vendor confirmation*. Restrict CoAP to trusted peers if approved. |
| **Barracuda — CVE-2026-116606, CVE-2026-111560** | [Barracuda advisory](https://trust.barracuda.com/security/pre-authentication-authorization-bypass-command-injection) lists ESG-specific patch **BNSF-40425** (9.4.017+) or **BNSF-40430** (older), while ADC/BMA/WCC/WAF/WSG have different IDs. An installed-version string alone cannot certify the required product patch. Restrict admin access to trusted networks where approved. |
| **ACF Extended PRO — CVE-2026-120534** | [Wordfence research record](https://www.wordfence.com/threat-intel/vulnerabilities/id/b8a7a925-2b9e-43bc-b649-c7ec518e063c) lists conditional paths via non-default preview or missing-OpenSSL fallback. Exact supported fixed release unresolved; suspend the exposed feature under operator review pending vendor evidence. |
| **Eclipse Mnestix — CVE-2026-89292** | Supplied CNA range ends before 2.3.0, but release artifacts and credentials need separate verification. Upgrading does not automatically rotate exposed keys or establish no previous access. |
| **GLPI — GHSA-c46f-4v9j-5gpc** | Handoff flags conflicting fixed targets. A separate [French CERT bulletin](https://cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1444/) lists affected versions before 10.0.28 and 11.0.10. Do not automatically infer release safety without the exact vendor advisory and supported branch. |
| **Linux/AWS — CVE-2026-98432** | Existing Linux-specific analyzer and temporary MPTCP control remain unchanged; kernel source alone cannot prove an installed/running vendor fix, and AWS managed fleets require service-specific rollout confirmation. |
| **Zyxel, TianoCore, Moxa, WAVLINK** | Model/board-specific firmware and signed image state must be checked. Unsupported hardware or upstream source changes do not establish corrected OEM firmware. |
| **Flowise / Agno** | Handoff lacks a verified supported fixed release; do not substitute nearby CVE patch levels or an OS upgrade. |
| **eMudhra / Red Hat trust-store** | Certificate distrust can require updating multiple images, stores and running services. Exact certificate identity and applicability were unresolved at cutoff; no automatic trust-store deletion. |

All remaining product entries preserve source-specific remediation notes, URLs and
residuals in the machine-readable handoff. For additional dated documents and
original comparisons, use the attached **source handoff ZIP**; the ledger does not
replace its full records.

## Evidence classifications and release gate

- **Verified in this release:** catalog syntax, CLI behavior, regression tests,
  checksum verification, ZIP extraction and patch application where explicitly run.
- **Source-reported / requires confirmation:** a vendor upgrade target mentioned in
  the original handoff unless independently corroborated and deployed.
- **Unknown:** actual customer exposure, installed firmware, remediation efficacy,
  existing compromise, cryptographic state and ability to roll back without harm.
- **Prohibited claims:** universal patch, confirmed exploit resistance, autonomous
  incident recovery, zero business disruption, and proof from a mere OS label.

Before pushing, run:

```bash
python3 scripts/catalog.py validate
python3 scripts/quickstart.py validate
python3 scripts/research_handoff.py validate
python3 -m unittest discover -s tests -q
sha256sum -c SHA256SUMS
git diff --check
```

After pushing, verify GitHub-hosted Windows/macOS/Linux test outcomes; a Linux
test run does not certify every device or vendor platform.
