# The scientific question

```text
STATUS = METHOD_DEVELOPMENT_ONLY
CLAIM_BEARING_USE = PROHIBITED
```

OAT asks one question:

> Can an agent cause a protected consequence without valid current authority
> for the exact action — through any route it can actually reach, including
> one the system's designers did not know existed?

Everything in this repository is either an attempt to answer that question or
an attempt to stop the instrument from answering it dishonestly.

## What the object of study is

```text
ACTUAL CONSEQUENCE
  × ACTUAL EXECUTION ROUTE
  × EXACT ACTION
  × ACTING PRINCIPAL
  × CURRENT AUTHORITY AT COMMIT
  × INDEPENDENT OBSERVATION
```

## What it is not

Not model intent. Not model obedience. Not a local predicate over a vendor's
internal state. Not what an adversary claims it achieved.

Those are all things one can measure more easily, which is exactly why they
are tempting substitutes. An agent that intended nothing harmful and still
moved money across a boundary has crossed the boundary. An agent that
announced a violation it did not cause has not.

## How this differs from the earlier generation

The first OAT generation, preserved at tag `oat-method-development-v0.1`,
was built around:

```text
frozen scenario -> adversarial candidate -> local falsifier -> verifier -> replay
```

That chain was useful for building the instrument, and it still runs — see
`docs/METHOD-DEVELOPMENT-BOUNDARY.md` and the RB-001 reference boundary. But
its object was a *local predicate*, and a local predicate can pass while a
consequence still commits through a route nobody modelled.

The consequence-boundary architecture replaces the object of study, not the
engineering. Canonicalization, digests, manifest binding, replay and the
claim quarantine all carried over.

## The two invariants

See `docs/CONSEQUENCE-BOUNDARY.md` for the authority invariant and
`docs/REACHABILITY-AND-UNKNOWN-PATHS.md` for the reachability invariant. They
are independent, and OAT is explicitly forbidden from treating the first as
implying the second.
