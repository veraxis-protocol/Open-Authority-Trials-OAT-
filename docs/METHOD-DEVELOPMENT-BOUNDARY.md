# Method-development boundary

This repository operates under `METHOD_DEVELOPMENT_ONLY`. The boundary is not
advisory; it is the reason the work is trustworthy at all.

## Inside the boundary

- Building and testing the instrument: canonical representation, falsifiers,
  adversaries, verifiers, replay, evidence digests.
- Running synthetic reference boundaries whose ground truth is known by
  construction, so instrument error is detectable.
- Reporting whether the instrument found, or failed to find, a counterexample
  under frozen conditions.

## Outside the boundary

- Certification of anything, by any wording.
- Claims about VEIP, OAuth, agent frameworks, competitors, or deployed systems.
- Publishing a result as if a provider or frontier-model adversary had run when
  it had not.
- Relaxing a frozen falsifier so a test passes.
- Treating an adversary, or any model, as the oracle.
- Converting missing evidence into a favorable result.

## Why the control case is mandatory

`RB-001-CONTROL` implements correct enforcement: authority is re-evaluated at
the consequence commit boundary. If the instrument reports a counterexample
against the control, the instrument is wrong — the run says nothing about the
target and everything about the tool. Control failure is therefore an
instrument defect, not a finding.

## Why the adversary precedes the oracle

The adversary's job is to *propose*. The verifier's job is to *decide*. These
are separated in code: the adversary receives a scenario and emits variations,
with no access to the falsifier, the verifier, or the authority facts, and V1
recomputes the falsifier rather than reading the adversary's claim. A witness
carrying a false claim is rejected with `CLAIMED_EVALUATION_MISMATCH`.

That separation is what lets a frontier model be added later as a witness
generator without becoming the oracle.

## Determinism as an evidence property

Evidence that cannot be replayed is testimony. The digest domain therefore
excludes wall-clock time, random identifiers, machine paths, and volatile
environment values; scenario time is expressed in integer logical ticks. Runtime
metadata is recorded under a `runtime` key that every digest strips, so where a
run happened is knowable without letting it perturb what the run proved.
