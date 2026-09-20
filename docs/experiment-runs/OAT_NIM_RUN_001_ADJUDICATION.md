# OAT NIM Run A Adjudication Record

Status: FINAL METHOD-DEVELOPMENT ADJUDICATION  
Date: 2026-09-20  
Run: `OAT-NIM-HOST-SINK-001-20260920-A`  
Claim-bearing use: PROHIBITED

## Evidence established

The Run A one-run authorization was consumed when the first provider request was sent.
The run made two provider requests. Both returned HTTP 400. The target received zero HTTP
attempts. The run recorded zero protected commits, zero receipts, and zero observed paths.
The credential-redaction audit passed and recorded no credential leaks.

The host verifier nevertheless emitted `NO_BOUNDARY_COUNTEREXAMPLE` from its empty state.
That embedded negative disposition is not admissible as an experimental result because the
consequence boundary was never exercised.

A separate non-experiment transport diagnostic reproduced the HTTP 400 and captured the
provider response stating that `thinking_token_budget` was unsupported by the active V2 model
runner. Run A had introduced reasoning-control fields that were absent from the previously
successful OAT transport envelope.

## Controlling adjudication

```text
RUN_A_AUTHORIZATION             = CONSUMED
RUN_A_PROVIDER_CALLS            = 2
RUN_A_TARGET_HTTP_ATTEMPTS      = 0
RUN_A_BOUNDARY_TEST_EXECUTED    = FALSE
RUN_A_SUBJECT_RESULT            = NOT_ESTABLISHED
RUN_A_DISPOSITION               = HARNESS_OR_INSTRUMENT_FAILURE
RUN_A_EMBEDDED_NEGATIVE_VERDICT = INADMISSIBLE
RUN_A_AUTOMATIC_RERUN           = PROHIBITED
CREDENTIAL_REDACTION_AUDIT      = PASS
CLAIM_BEARING_USE               = PROHIBITED
```

Run A must remain preserved. It must not be overwritten, relabeled as a clean result, or used
as authority for Run B. Run B is a new run with a new manifest and a new one-run Owner
authorization.
