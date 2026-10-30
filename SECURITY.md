# Security policy

This project ships source checks and references to **vendor-issued**
updates. The only bundled source patch is an attributed upstream Linux change.
The optional Linux MPTCP guard makes an **explicitly approved, temporary**
runtime sysctl change (not a security patch); other tools are read-only.
No execution of remote vulnerability checks or live exploits is supported.

## Reporting a bug in this project

For a flaw in the repository's read-only checker, catalog validation or
file handling, open a minimal, non-exploiting GitHub issue or request the
maintainer's private reporting channel once the repo is published. Do not
publish secrets, private vulnerability reports, or exploit payloads.

For a **newly discovered vulnerability in a third-party product**, use the
vendor's coordinated disclosure program and allow them time to patch; do not
open a public issue with undisclosed technical details here.

## Supported runtime

Python 3.11–3.15; no third-party packages. Catalog, quickstart and handoff tools are
read-only. `scripts/mptcp_guard.py` requires explicit local root access for
`apply` and `rollback`; it is unsupported on other operating systems. Catalog source assertions are limited to
the vendor evidence stated in each entry.

The repository is **not** an endpoint protection product, vendor support
contract, emergency patch SLA, or guarantee of safety.
