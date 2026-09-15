# FORMATION-0001 — Bootstrap of the RB-001 method-development pipeline

```text
STATUS = METHOD_DEVELOPMENT_ONLY
CLAIM_BEARING_USE = PROHIBITED
CLAIM_BEARING_TRIAL_AUTHORIZED = FALSE
```

Work order: `OAT-REPO-BUILD-001`. Date: 2026-09-15.

## 1. What was built

An executable OAT instrument around the frozen synthetic reference boundary
RB-001 (revocation-before-commit / TOCTOU):

- an observable-first canonical model with a deterministic byte encoding;
- the RB-001 development falsifier, returning a predicate trace;
- three enforcement paths — two defective by construction (`VULN-A`
  stale cached decision, `VULN-B` lagging replica) and one correct
  (`CONTROL`, re-evaluation at the commit boundary);
- a deterministic local adversary performing an ordered grid search over the
  scenario's declared dimensions, capturing every candidate it proposed;
- **V1**, a deterministic verifier that recomputes every value it reports;
- deterministic replay without the adversary;
- a checked-in reference run whose regeneration is enforced by `make ci`.

Observed dispositions: `VULN-A` → `COUNTEREXAMPLE_CONFIRMED` (candidate 4 of 5
explored), `VULN-B` → `COUNTEREXAMPLE_CONFIRMED` (candidate 18 of 19),
`CONTROL` → `NO_COUNTEREXAMPLE` across its entire 48-candidate space.

## 2. Frozen doctrine implemented

- `OAT_REFERENCE_BOUNDARY_RB001_REVOCATION_TOCTOU_v0.1` — scenario, authority
  envelope (`AP_AGENT_17` / `SUPPLIER_A` / 250000 USD), payment of 200000 USD,
  the three variants, the falsifier expression, and the evidence-bundle list.
- `OAT_DEVELOPMENT_ONLY_RUNBOOK_v0.1` — mandatory banner, run sequence
  (freeze manifest, hash target, hash falsifier, record environment, capture
  all candidates, run V1, replay without adversary), and the prohibition on
  promoting any artifact from this lane.
- `OAT_FORMALISM_REQUIREMENTS_v0.1_FROZEN` — observable-first canonical model,
  layer separation, and formalism identity pinning.

## 3. Why a deterministic adversary precedes a frontier adversary

The instrument must be falsifiable before it is powerful. A deterministic grid
search has three properties a model-driven adversary does not: its candidate
sequence is reproducible by anyone, its coverage of the declared space is
countable (so a passing control can be shown to have been *searched*, not
merely unchallenged), and it cannot silently change the question. Commit 1 also
must not depend on provider access or credentials.

The provider seam exists as an interface
(`oat.adversaries.base.ProviderAdversary`) and raises `NotImplementedError`.
**No NIM/Nemotron or other provider run occurred.** A frontier model, when
added, is a witness generator — never the oracle.

## 4. Doctrine conflict discovered (owner review required)

**Run-folder layout.** The runbook's "Required run folder" specifies
`manifest.json`, `target/`, `adversary/`, `candidates/`, `witness/`,
`verifier/`, `replay/`, `formation_record.md`,
`README_METHOD_DEVELOPMENT_ONLY.md`. Work order §4 and §22 instead specify a
flat `examples/rb001/reference-run/` of `manifest.json`, `witness.json`,
`verifier-result.json`, `replay-result.json`, `SHA256SUMS.json`.

These cannot both be satisfied literally. Resolution taken: the work order's
flat layout is used for the deposited reference run, and every *content*
requirement of the runbook folder is carried inside it —

| Runbook element | Where it lives now |
| --- | --- |
| `target/` | `manifest.json` → `target.code_digest` (SHA-256 of the boundary module) |
| `adversary/` | `manifest.json` → `adversary`, and `witness.json` → `adversary` |
| `candidates/` | `witness.json` → `search.transcript` (every candidate proposed) |
| `witness/`, `verifier/`, `replay/` | `witness.json`, `verifier-result.json`, `replay-result.json` |
| `formation_record.md` | this file, at `docs/formation/FORMATION-0001.md` |
| `README_METHOD_DEVELOPMENT_ONLY.md` | present in the run directory |

No doctrine was reinterpreted: the conflict is recorded here and in the
executor return for the owner to settle.

## 5. Ambiguities discovered in RB-001 / canonicalization

1. **Temporal representation.** RB-001 states validity as `valid_from = t0`,
   `valid_until = t9` and the work order's authority shape shows `"valid_from":
   "..."`, neither of which fixes a concrete type. Wall-clock timestamps would
   put a volatile value inside the digest domain and break byte-identical
   replay. Resolved: integer **logical ticks**. Any later scenario needing real
   timestamps must place them outside the digest domain or define a canonical
   time normalization first. *This constrains later method design.*
2. **"The bound manifest digest".** Ambiguous between the per-run manifest and
   the frozen scenario-family manifest. Resolved: the witness binds the **run**
   manifest, which itself pins the family manifest digest, the authority
   digest, and the scenario digest — so the binding is transitive and one
   comparison detects tampering at any level.
3. **"Committed".** RB-001 says a payment becomes "economically committed"
   without defining the observable. Resolved: a single
   `consequence_committed` event carrying a boolean; a trace with zero or
   several is rejected as unevaluable rather than guessed at.

## 6. Implementation decisions that constrain later method design

1. **What is inside the digest domain.** Target boundary code digest, falsifier
   digest, scenario/authority/manifest digests and the full predicate trace are
   canonical. The verifier's own source-tree digest and all environment values
   are recorded under a `runtime` key that every digest strips, summarized as
   an `environment_digest`. Rationale: pinning verifier source bytes into the
   evidence digest would churn every checked-in artifact on any edit to the
   package, including comments. **Owner review:** a claim-bearing lane may want
   the verifier bytes pinned canonically and to accept that churn.
2. **Falsifier identity is verified against the locally loaded falsifier**, not
   against a digest frozen into the scenario file. A witness produced under a
   different falsifier is rejected (`FALSIFIER_IDENTITY_MISMATCH`), but the
   scenario file does not independently pin the falsifier digest.
3. **Formalism layers 3 and 4** (protocol-native representation, protocol
   adapter) do not exist here and are pinned as `null` with a stated reason
   rather than left silently absent. RB-001 is synthetic and protocol-free; any
   cross-protocol trial must supply and pin these before it can be
   claim-bearing.
4. **Schemas have one copy.** `schemas/` is mapped into the wheel as the
   `oat.schemas` package, so the installed artifact and the repository cannot
   disagree. All `$ref`s resolve through a local registry — validation never
   touches the network.
5. **No wall-clock value is written anywhere**, so a run directory is
   byte-identical when regenerated on the same host.

## 7. Formation defect found

**Yes — one, in the instrument's own reporting surface.** `oat inspect` raised
an unhandled `KeyError` when pointed at a run package whose `witness.json` had
been replaced with `{}`, instead of reporting the checksum failure it had
already computed. An evidence tool that crashes on damaged evidence tells the
reader nothing about the damage. Fixed: checksums are verified first and every
displayed field degrades to `<unavailable>`; the failure now exits `5` with the
offending file named. Covered by
`tests/test_cli.py::test_inspect_exits_nonzero_when_checksums_fail`.

Two hazards were also pre-empted rather than discovered as failures:

- A control can pass trivially by refusing everything, which would look like a
  correct instrument. `test_control_still_commits_when_authority_is_live`
  asserts the control *does* commit while authority is live.
- A control can pass because the search gave up early.
  `test_control_search_space_is_exhausted_not_truncated` asserts the recorded
  candidate count equals the full declared space.

No defect was found in the falsifier, the canonical model, the verifier's
disposition logic, or replay determinism. Nothing was invented for narrative
value.

## 8. Refusals and narrowings

- **No claim-bearing behavior was implemented or implied.** No VEIP evaluation,
  no certification language, no comparator mapping.
- **No GitHub remote was created and nothing was pushed.** GitHub Actions
  status is reported as `NOT_RUN_REMOTE_NOT_CREATED`; the CI workflow is
  configured but has never run remotely.
- **No provider run was reported**, because none occurred.
- **No V2 verifier.** The runbook permits its absence for private method
  development; its absence independently blocks claim-bearing standing.
- **The falsifier was never relaxed.** No test was skipped or weakened to reach
  a passing gate.

## 9. Claim ceiling

> A deterministic local instrument reproduced a documented synthetic
> authorization failure class (RB-001) under frozen scenario conditions. This
> supports no claim about VEIP, OAuth, any agent system, any vendor, or any
> deployed system.

```text
CLAIM_BEARING_TRIAL_AUTHORIZED = FALSE
```

No artifact in this lane may be promoted into claim-bearing evidence. After the
constitutional gates pass, any applicable trial must be rerun from a newly
frozen manifest.
