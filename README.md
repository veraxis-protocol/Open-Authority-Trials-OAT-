# Open Authority Trials (OAT)

**OAT is an adversarial evidence system for machine-authority boundaries.** It
searches for a machine-checkable counterexample to a frozen authorization
property, and it makes the search, the witness, and the verdict reproducible by
anyone who has the repository.

> ## This repository is a non-claim-bearing method-development testbed.
>
> ```text
> STATUS              = METHOD_DEVELOPMENT_ONLY
> CLAIM_BEARING_USE   = PROHIBITED
> CLAIM_BEARING_TRIAL_AUTHORIZED = FALSE
> ```
>
> It exists to prove the **instrument** works, not to evaluate anything. A
> successful run here **does not certify** VEIP, OAuth, any agent framework,
> any vendor, or any deployed system, and it establishes no protocol standing.

The first reference test, **RB-001**, is a *synthetic, documented* failure
class: **revocation-before-commit (TOCTOU)** — an authorization decision is
taken, the authority is revoked, and the consequence commits anyway.

## Reproduce RB-001 locally

```bash
python -m pip install -e ".[dev]"

oat run scenarios/rb001/VULN-A.json     # expect COUNTEREXAMPLE_CONFIRMED
oat run scenarios/rb001/VULN-B.json     # expect COUNTEREXAMPLE_CONFIRMED
oat run scenarios/rb001/CONTROL.json    # expect NO_COUNTEREXAMPLE
```

Or run the whole local gate — lint, types, tests, coverage, tamper suite,
reference run, and replay:

```bash
make ci
```

## What the instrument has to demonstrate

| Scenario | Enforcement path | Required disposition |
| --- | --- | --- |
| `RB-001-VULN-A` | decision checked once, then cached | `COUNTEREXAMPLE_CONFIRMED` |
| `RB-001-VULN-B` | re-checked, but against a lagging replica | `COUNTEREXAMPLE_CONFIRMED` |
| `RB-001-CONTROL` | re-evaluated at the commit boundary | `NO_COUNTEREXAMPLE` |

The control matters as much as the vulnerable variants. An instrument that
reports a counterexample against correct enforcement is not evidence, it is
noise.

## How a run is put together

```text
frozen scenario
  → frozen canonical representation   (observable-first, no VEIP-native state)
  → deterministic adversarial search  (ordered grid over allowed dimensions)
  → candidate witness                 (a proposal, never a verdict)
  → V1 verifier                       (recomputes everything it reports)
  → deterministic replay              (same bytes, same digest, no adversary)
  → evidence digest
```

Three separations do the work:

- **The adversary cannot rule.** It only proposes variations inside the
  scenario's declared search space. It never touches the falsifier, the
  verifier, or the frozen authority facts, and V1 recomputes its claim rather
  than trusting it.
- **The falsifier is mechanical.** `committed(payment) AND
  authority_effective_at(commit_time) == REVOKED` — evaluated against ground
  truth, returning a predicate trace, with no prose judgment anywhere.
- **The digest domain is deterministic.** Logical ticks, not wall clocks;
  runtime metadata is recorded outside the digest. Two replays produce
  byte-identical canonical material.

## Commands

```bash
oat run <scenario.json> [--out DIR]   # search, verify, optionally write a run package
oat verify <witness.json | run-dir>   # re-verify an existing witness
oat replay <run-dir> [--write]        # re-derive the run without the adversary
oat inspect <run-dir>                 # identities, disposition, checksums
oat demo                              # regenerate examples/rb001/reference-run
```

Every command that presents a result prints the quarantine banner, and every
JSON artifact carries `run_mode` and `claim_bearing_use` fields.

## Layout

```text
oat/                    instrument: canonical model, falsifier, adversary, V1, replay
scenarios/rb001/        frozen scenario definitions and authority input
schemas/                JSON schemas, also shipped inside the wheel
examples/rb001/         checked-in reference run with SHA256SUMS.json
docs/                   current state, boundary doctrine, formation record
tests/                  behavioral, tamper, replay, quarantine, and CLI suites
```

Start with [`docs/CURRENT-STATE.md`](docs/CURRENT-STATE.md) and
[`docs/METHOD-DEVELOPMENT-BOUNDARY.md`](docs/METHOD-DEVELOPMENT-BOUNDARY.md).

## License

Apache-2.0. See [LICENSE.md](LICENSE.md).
