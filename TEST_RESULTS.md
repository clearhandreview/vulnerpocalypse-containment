# Current offline verification — October 30, 2026

**Local result:** 86 offline unit tests passed on the available Linux
Python 3.13 runner, including October 30 CVE checks and nine
additional platform-inventory tests. Known distro routes, toolchain
discovery and simulated Windows/macOS/Android branches are unit-tested;
native device or distribution testing was not performed. Catalog: **16 advisories / 27 CVEs**. Containment guide: **10
profiles**. This is software correctness and catalog validation; it does
not test real-world exploit resistance or install patches.

Executed:

```sh
python3 -m py_compile scripts/catalog.py scripts/quickstart.py scripts/vendor_handoff.py scripts/mptcp_guard.py scripts/platform_inventory.py cve98432.py
python3 scripts/catalog.py validate
python3 scripts/quickstart.py validate
python3 scripts/platform_inventory.py --json
python3 -m unittest discover -s tests -v
sha256sum -c SHA256SUMS
```

The check tools remain read-only, except the separate Linux MPTCP control,
which still requires an explicit privileged operator invocation.

**Not verified:** current GitHub-hosted Windows/macOS CI for this release,
Python 3.11/3.12/3.14/3.15 hosted jobs, real vendor package updates,
Veeam/SCOM upgrade behavior, ServiceNow hosted-tenant state, Delinea GPO
enforcement and policy-polling latency, Nomad symlink resistance, and actual
device/kernel security status.

Run the GitHub Actions matrix on the uploaded commit before publishing
a release. For prior QA criteria, see `docs/QA_QC_SENTINEL.md`.
