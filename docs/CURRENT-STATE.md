# Current state

```text
CLAIM_BEARING_TRIAL_AUTHORIZED = FALSE
PERMITTED_MODE                 = METHOD_DEVELOPMENT_ONLY
CLAIM_BEARING_USE              = PROHIBITED
GITHUB_ACTIONS                 = NOT_RUN_REMOTE_NOT_CREATED
```

## What exists

- A frozen synthetic reference boundary, **RB-001** (revocation-before-commit /
  TOCTOU), with two defective enforcement paths and one correct one.
- A machine-evaluable RB-001 falsifier that returns a predicate trace.
- A deterministic local adversary performing an ordered grid search over the
  scenario's declared variation dimensions.
- **V1**, a deterministic verifier that recomputes every value it reports and
  rejects schema-invalid, misbound, tampered, or unsupported input.
- Deterministic replay that reproduces a frozen run without the adversary.
- A checked-in reference run under `examples/rb001/reference-run/`.

## What does not exist

- Any claim-bearing trial. None is authorized.
- Any frontier-model or provider adversary run. The provider seam is an
  interface only (`oat.adversaries.base.ProviderAdversary`), and it raises
  rather than pretending to have run.
- Any evaluation of VEIP, OAuth, an agent framework, a vendor, or a deployed
  system. RB-001 is synthetic and models nothing real.
- Any GitHub Actions result. The remote does not exist yet; CI is configured
  but has never run remotely.

## Claim ceiling

A deterministic local instrument reproduced a documented synthetic
authorization failure class under frozen scenario conditions. That is the
entire claim. It supports no statement about any external system.
