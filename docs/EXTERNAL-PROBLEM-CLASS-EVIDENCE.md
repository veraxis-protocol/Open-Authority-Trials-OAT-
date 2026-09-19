# External problem-class evidence

```text
STATUS = METHOD_DEVELOPMENT_ONLY
CLAIM_BEARING_USE = PROHIBITED
CLASSIFICATION = EXTERNAL_PROBLEM_CLASS_EVIDENCE
```

This file records that the problem class OAT studies is observed outside this
project. It is not validation of OAT, and nothing here is claim-bearing.

## The narrow technical relevance

Two distinctions motivate the consequence-boundary architecture, and both are
observable in publicly reported agent-security work:

```text
intended execution boundary  !=  actual reachable execution graph
post-consequence safe behavior  !=  absence of boundary crossing
```

The first is why `docs/REACHABILITY-AND-UNKNOWN-PATHS.md` exists: a system can
be correct on every route its designers enumerated and still be reachable by
one they did not. The second is why the disposition taxonomy separates
`CONSEQUENCE_BOUNDARY_FAILURE` from everything else: an agent that behaves
well *after* a consequence has committed has not prevented the crossing.

## What must not be claimed

The September 2026 Gemini / Irregular reporting may be referenced only as
evidence that this problem class is real and is being worked on by others.

It must **not** be represented as:

- OAT validation
- VEIP validation
- customer validation
- evidence that OAT would have prevented that incident
- evidence that OAT would necessarily have detected that incident
- claim-bearing evidence of any kind

## Sourcing

No vendor-specific technical detail is asserted here beyond what a cited
public source states. This repository does not reproduce, infer, or extend
Google-, Gemini-, or Irregular-specific internals. Any future citation added
to this file must carry its source and must not be paraphrased into a
stronger claim than the source makes.

At the time of writing, this document deliberately contains no technical
detail attributed to that incident, because no source has been verified
inside this repository's evidence discipline. The problem-class statement
above stands on its own reasoning.
