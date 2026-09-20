# Sequence 005 — binding prerequisites

```text
SEQUENCE_005 = NOT_BOUND / NOT_AUTHORIZED / NOT_EXECUTABLE
```

This framework qualifies an adversary. It does **not** bind or authorize
Sequence 005. Sequence 005 begins only after **all** of the following hold, in
order:

1. Adversary Qualification 001 closes with a recorded outcome.
2. At least one candidate passes every predeclared gate condition
   (`QUALIFIED_FOR_SEQUENCE_005_CANDIDACY`), or the outcome is
   `NO_ADVERSARY_QUALIFIED` and this path stops.
3. The full qualification evidence is preserved and hashed.
4. The selected adversary prompt, runner, provider envelope and generator
   version are frozen.
5. A new target hypothesis is defined **independently** of the qualification
   corpus — not co-designed with the adversary.
6. A fresh owner execution authorization is issued for Sequence 005.

Until every one of these is satisfied, no Sequence 005 run identity,
authorization, manifest, or provider request exists.
