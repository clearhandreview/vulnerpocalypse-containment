# Internal QA / QC / SENTINEL — release review (2026-10-29)

**Method:** RSR. **Evidence:** cited official documentation, local code,
synthetic offline tests. **Scope:** no production deployment, no exploit,
no compiled/rebooted kernels, no signed Windows/Apple/Google updates applied.

## Acceptance criteria

The package may ship as a **community, evidence-limited toolkit** if all
of the following hold: no generic binary patch claims; all privileged
actions require explicit operator action; controls disclose impact and
rollback; future vendor updates take precedence; unknown findings remain
unknown; input catalogs validate; all offline tests pass.

It **may not** ship as a universal, production-certified hotfix solution.

## QA defect inspection

| QA | Check | Result | Supporting observation / limitation |
| --- | --- | --- | --- |
| QA1 | Authority | PASS | System instructions retain precedence over external snippets; source patch attribution preserved. |
| QA2 | Evidence labels | PASS with limit | Each profile says control mechanism / limits; official releases separate from temporary control; effectiveness not inferred from a version alone. |
| QA3 | Arithmetic | PASS | Catalog independently parses 16 advisories / 27 named CVEs; 10 containment profiles; unit test count from test runner. |
| QA4 | Missing inputs | PASS | Undisclosed findings cannot yield code patches; Android CVE/build mapping remains UNKNOWN. |
| QA5 | Safety routing | PASS with limit | Root Linux changes require explicit outage/reexposure flags. Production readiness remains expert/operator review. |
| QA6 | Data/instructions boundary | PASS by inspection | JSON and web references are data; scripts do not execute remote content or external shell commands. |
| QA7 | Anthropomorphism | PASS | Describes performed operations, not presumed agency or certainty. |
| QA8 | Scope | PASS | Attributed upstream patch retained; one new Linux runtime control only; all other OS steps require human action. |
| QA9 | Completeness | PASS for documented platforms | Windows, Mac, iOS/iPadOS, Android, Linux, Chrome, Apple devices and other/EOL paths contain next steps. Individual OS builds remain unverified. |
| QA10 | Ambiguity | PASS | “Vendor patch”, “source patch”, “temporary exposure reduction”, and “working smoke test” are separate states. |
| QA11 | Contrast pairs | PASS | “Fix installed” is distinct from “active”, “version floor met”, “mitigated”, and “exploitation impossible”. |
| QA12 | Executable tests | PASS locally | Python syntax, catalog and profile validation, 76 offline unit tests. Windows/macOS hosted CI has not run. |
| QA13 | Release integrity | PASS locally | Packaging manifest SHA-256 records repository files; archive reopens and local tests pass. Not a notarized signature. |

## QC results and reproducible checks

These commands completed with exit code 0 in the local Linux test runtime:

```sh
python -m py_compile scripts/catalog.py scripts/quickstart.py scripts/vendor_handoff.py scripts/mptcp_guard.py cve98432.py
python scripts/catalog.py validate
python scripts/quickstart.py validate
python -m unittest discover -s tests -v
```

**Unit tests:** 76 passed, 0 project test failures, in this Linux runtime.
Fixture tests exercise consent gates, version-floor gating, rollback
identity, tamper refusals, bad sysctl values, symlink state refusal,
documented instructions and file references. Existing source-level Linux
patch tests are still included. Tests do not alter this machine's kernel
sysctl; the new write tests use temporary files.

**Not tested:** actual Windows/macOS execution, Android or iOS installation,
distribution-specific kernel builds/backports, existing live MPTCP socket
behavior, crash/restart races or cross-network-namespace operations, binary
code signing, vendor update installation, functional production service
health, exploit resistance, GitHub-hosted CI workflow results. Also the
runtime emitted a separate spreadsheet-initialization warning during some
subprocess launches; project commands returned success and unit tests
passed. This warning has not been established as a project defect.

## SENTINEL repair pass (targeted, not a rewrite)

SENTINEL scores are human triage *priorities*, not safety-performance proof.

| Defect | Pressure 1–5 | Impact 1–5 | Fixability 1–5 | Score | Repair |
| --- | ---: | ---: | ---: | ---: | --- |
| False promise of a universal zero-day binary patch | 5 | 5 | 5 | **125** | Require source evidence; prohibit generic binary mutation; provide controlled mitigation and explicit UNKNOWN outcomes. |
| Confidence-label validator rejected `not_fixed...` as a *fixed* claim | 4 | 3 | 5 | **60** | Replace substring filtering with allowed conservative confidence labels. 7 initially failing tests now pass. |
| Synthetic Linux guard tests depended on Windows-restricted symlink creation | 3 | 3 | 5 | **45** | Inject a test namespace reader; POSIX-only permission tests skip on non-POSIX runners. |

**Highest-priority repair implemented:** remove unverifiable universal-patch
claim and gate any operating-system write behind explicit authorized,
supported control. Only targeted documentation and control code were added.
**Deliberately unresolved:** unpublicized CVEs, missing Android update mapping,
all-OS runtime safety proof, non-Linux host-side automatic mitigations,
live exploit-resistance and real service regression tests. These cannot be
legitimately repaired by changing text or multiplying a confidence score.

## Release decision

**PASS to publish as limited public reference and opt-in Linux containment tool.**

**NO-GO** to market, distribute or configure it as a universal security patch,
a guaranteed zero-day fix, an automated OS update agent, or production
endpoint protection. A live environment needs independent engineering
review, backup, controlled rollout and vendor confirmation.

For each future PR rerun the same checks and update this review date,
advisory provenance and test results. Do not edit an old PASS into a new one.
