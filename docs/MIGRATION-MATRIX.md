# Capability migration matrix

```text
STATUS = METHOD_DEVELOPMENT_ONLY
CLAIM_BEARING_USE = PROHIBITED
```

Every capability present at `a71bebe` (tag `oat-method-development-v0.1`) is
accounted for below. Nothing was removed.

| Capability | Disposition | Where it lives now |
| --- | --- | --- |
| Canonical JSON (`oat-canonical-json/1`) | PRESERVED | `oat/canonical.py`, reused unchanged by the consequence layer |
| Digest machinery | PRESERVED | `oat/digest.py`, reused unchanged |
| Manifest binding | PRESERVED | `oat/manifest.py` |
| Schema validation | PRESERVED | `oat/verifier/v1.py`, `schemas/` |
| V1 independent recomputation | PRESERVED | `oat/verifier/v1.py` |
| RB-001 reference boundary | PRESERVED, RECLASSIFIED | `oat/reference_boundaries/rb001.py`; now reference boundary / regression fixture / deterministic positive control |
| RB-001 falsifier | PRESERVED | `oat/falsifiers/rb001.py` |
| RB-001 scenarios VULN-A / VULN-B / CONTROL | PRESERVED | `scenarios/rb001/`, frozen outcomes unchanged |
| RB-001 reference run + evidence digest | PRESERVED | `examples/rb001/reference-run/`, bytes unchanged |
| Deterministic replay (RB-001) | PRESERVED | `oat/replay.py` |
| Trial adjudication (6 RB-001 dispositions) | PRESERVED | `oat/trial.py`, untouched |
| Provider-run provenance | PRESERVED | `oat/adversaries/provider.py` |
| Claim-bearing quarantine | PRESERVED | `oat/__init__.py`, CLI banner, every run package |
| Licensing enforcement | PRESERVED | `tests/test_licensing.py`, BSL 1.1 + CC BY 4.0 |
| CLI infrastructure | REFACTORED | `oat/cli.py`; existing commands unchanged, `consequence` and `paths` added |
| Test infrastructure | PRESERVED | `tests/`, extended |
| CI | REFACTORED | `.github/workflows/ci.yml`; same gates, new suites included |
| Primary scientific object | REFACTORED | was a local predicate over a frozen scenario; now a protected consequence over the reachable execution graph |
| Disposition taxonomy | EXTENDED | `oat/trial.py` six RB-001 dispositions retained; `oat/verifier/consequence.py` adds a separate, non-collapsible consequence taxonomy |

## Nothing deprecated or removed

```text
DEPRECATED = (none)
REMOVED_WITH_JUSTIFICATION = (none)
```

## Why the taxonomies are separate

`oat.trial.Disposition` answers "did this candidate falsify a frozen local
predicate?". `oat.verifier.consequence.ConsequenceDisposition` answers "did a
protected consequence commit without valid current authority?". Merging them
would reintroduce exactly the collapse this refactor exists to prevent: a
local predicate failure is not a boundary crossing, and an instrument defect
is neither.

## Provenance

The consequence layer's deterministic primitives derive from OAT Consequence
Boundary Instrument Candidate 001 (2026-09-18), reimplemented against this
repository's canonicalization, digest and evidence conventions. The candidate's
claim ceiling is carried forward intact: representative test primitives, not
production infrastructure.
