# OAT Adversary Qualification 001

Synthetic, non-claim-bearing qualification of a candidate adversary *search
strategy* against a corpus of eight neutral synthetic targets. It never touches
the real frozen OAT target, never reads Sequence 004 adjudicator ground truth,
and never authorizes Sequence 005.

## What this answers

> Can a candidate adversary, without target-specific ground truth, search
> broadly enough across undeclared routes and authority-binding dimensions to
> justify use in a successor OAT consequence-boundary experiment?

It does **not** ask whether the real OAT target is secure, and it does not use
the Sequence 004 hidden route as a training or selection signal.

## Pieces

| Path | Role |
|---|---|
| `oat/qualification/synthetic_targets.py` | deterministic 8-target generator; adjudicator-only ground truth |
| `oat/qualification/target_service.py` | in-process target evaluation and counterexample adjudication |
| `oat/qualification/leak_audit.py` | mandatory pre-run ground-truth leak audit per target/candidate |
| `oat/qualification/probes.py` | probe canonicalization, near-duplicate + coverage accounting |
| `oat/qualification/runner.py` | fail-closed candidate runner (transport injected) |
| `oat/qualification/provider.py` | frozen Run-D-compatible NIM transport (no authorization coupling) |
| `oat/qualification/selection.py` | aggregator applying `03_SELECTION_RULES.json` exactly, plus replay |
| `oat/provenance.py` | provenance-naming patch (WO-06): labels/prefixes derived from bound identity |
| `tools/oat_adversary_qualification_001.py` | `freeze` and `run` CLI |
| `docs/qualification/OAT_ADVERSARY_CANDIDATE_B_PROMPT_001.txt` | Candidate B (frozen before the generator existed) |

Candidate A is the byte-identical Sequence 004 adversary baseline
(`docs/experiment-runs/OAT_NIM_ADVERSARY_PROMPT_001.txt`).

## Design-independence note

Candidate B was authored and hashed **before** the synthetic generator was
written, so it cannot be tuned to the corpus. Its hash is recorded in
`OAT_ADVERSARY_QUALIFICATION_001_FROZEN_MANIFEST.json`. The generator draws its
targets from the fixed pools in `02_SYNTHETIC_TARGET_GENERATOR_SPEC.json`
without reference to any candidate.

## Execution boundary

Qualification is not executed in the repository binding. It runs on the Owner
Mac after: full CI green, provider preflight PASS, and the frozen manifest,
candidate prompts, generator and selection rules all frozen. See
`07_SEQUENCE_005_BINDING_PREREQUISITES.md`.

```text
CLAIM_BEARING_USE = PROHIBITED
```
