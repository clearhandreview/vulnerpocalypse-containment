# Contributing public security fixes

This is a **public security-advisory catalog and read-only verification
toolkit**. Contributions should increase public remediation coverage without
inventing fixes, fetching arbitrary binaries, or exposing undisclosed issues.

## Adding a CVE / advisory

1. Confirm the vulnerability is public. Link **the vendor advisory** or
   upstream maintainer security announcement, not only a news article.
2. Identify the exact product, branch, supported OS edition, and fixed
   release/commit. If the vendor does not specify them, put the case in
   `unresolved` with the missing proof.
3. Add a new, unique record to `data/advisories.json` following an existing
   record. The `id` must be lower-case `a-z0-9-`; each CVE must be unique.
   For a release floor, provide product-specific **four-field numeric version**
   strings in `minimum_versions` and a direct vendor HTTPS advisory URL.
   `fix_type`: `vendor_release`, `vendor_update`, or `upstream_patch`.
4. Only set a `local_patch` for correctly attributed, redistributable
   upstream source changes. Keep the original author, upstream commit,
   license, and dependencies. Never mirror Windows/Apple/Chrome proprietary
   binaries or manufacture byte patches for them.
5. Explain **how to verify installation and activation**, plus a harmless
   functional smoke test, without weaponized exploitation.
6. Run:

```shell
python scripts/catalog.py validate
python -m unittest discover -s tests -v
```

7. Update the README's reviewed-as-of date and current CVE/advisory count when
new public records are added. Submit a PR stating: official advisory, product/branch applicability,
   patch source or verified release floor, all manual unknowns, and test output.

## Safety and evidence policy

- `Verified` means the cited vendor has actually published this fix or
  the relevant checked tests ran. A *proposed* fix is never a validated one.
- A URL existing does not prove that a patch applies across distributions.
- EOL OS versions, forks, kernels with vendor backports and hidden
  security fixes require an explicit **unknown** state.
- Anthropic's hash-only ledger commitments are not public CVEs and should
  not be reverse-labeled or turned into fabricated fixes.
- A patch is **not** installed simply because a source file has the expected
  text. Record actual binary/package and running version.
- Avoid adding new third-party Python dependencies without clear need.
- Never add live payloads, secrets, customer data, malware, exploit chains,
  automatic remote execution, or "try this against a target" instructions.

## Reviewing PRs

Maintainers should check the advisory's date and fixed release against
vendor material, confirm the exact affected product/branch, check licensing,
run the offline tests on supported Python versions, and review diffs for
unrelated source changes or unsafe installation behavior. If a mapping cannot
be substantiated, move it to `unresolved`.

## Updating old records

Retain original publication date and citations. On correction, amend the
record with the newer vendor source and explain the change in the PR. Version
floors are evidence **for the listed CVEs**; do not extrapolate them to all
vulnerabilities in an OS.


## Requirements for any NEW community-written security fix

A community fix may be accepted only with **public, verifiable evidence**
that the affected code and version are known and testable. Every pull request
must supply: the CVE or vendor bug reference, source-code commit/line anchors,
affected branches/architectures, minimal diff, rollback plan, a benign
regression test, the independent code-reviewer, and proof that the proposed
build does not silently break code signing or vendor updateability.

Do **not** publish hidden coordinated-disclosure details, exploit steps,
payloads or attack code. A synthetic test fixture or source-level check is
not evidence that an arbitrary Windows/macOS/Android binary is patched.

**Additional temporary-control proposals** must define: exact scope;
evidence for the control mechanism; explicit user authorization before any
system change; safe preconditions; service impact; pre-change state;
idempotency and conflict behavior; runtime verification; rollback; no
automatic persistence; and vendor handoff. Expand `data/containments.json`,
add offline tests and extend `docs/EASY_INSTALL.md` when the evidence exists.

Unknown, non-public or unsupported targets should remain an explicit
unknown/backlog entry, **not** a fabricated patch.

## Publishing rules

Never imply a green CI badge validates exploit resistance. Do not call
`READY_FOR_CHANGE_REVIEW` equivalent to a vendor certificate. The maintainer
must review `docs/QA_QC_SENTINEL.md` on each high-impact code change.
New dependencies need a supply-chain review; default is Python stdlib only.
