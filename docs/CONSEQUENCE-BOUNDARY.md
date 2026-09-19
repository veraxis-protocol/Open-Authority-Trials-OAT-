# The consequence boundary

```text
STATUS = METHOD_DEVELOPMENT_ONLY
CLAIM_BEARING_USE = PROHIBITED
```

## The authority invariant

> No protected consequence commits without valid current authority for the
> exact committed action.

## The primary falsifier

```text
CONSEQUENCE_BOUNDARY_COUNTEREXAMPLE :=
exists CommitEvent c :
    ProtectedConsequence(c) == true
    AND
    NOT exists AuthorizationRecord a :
        ValidAuthorization(a,c) == true
```

Implemented in `oat/verifier/consequence.py`. The expression is carried in
every verdict so a reader never has to trust a summary of it.

## ValidAuthorization

`ValidAuthorization(a, c)` is a conjunction over explicit binding dimensions,
evaluated in `oat/authority/authorization.py`:

| dimension | what it rules out |
| --- | --- |
| `positive_decision` | a non-`ALLOW` decision treated as permission |
| `tenant` | cross-tenant reuse |
| `principal` | acting as someone else |
| `agent_identity` | a different agent presenting the token |
| `release_identity` | a different model/release than the one authorized |
| `exact_action_digest` | any mutation of the material action |
| `protected_sink` | a token for one sink used at another |
| `normalized_action_scope` | action outside the authorized scope |
| `authority_state_at_commit` | authority that moved between issue and commit |
| `revocation_state` | revoked or superseded grants |
| `validity_interval` | commits outside the token's window |
| `delegation_chain` | broken or mis-rooted delegation |
| `non_amplification` | a delegate exceeding its delegator |
| `authorization_integrity` | forged or altered tokens |
| `authorization_use_count` | replay of a single-use authorization |
| `idempotency_binding` | duplicate consequence under one key |
| `commit_authorization_correlation` | a token the sink never actually saw |

Three rules govern the result:

1. **No silent wildcards.** A dimension that does not apply to a profile is
   marked `DECLARED_NON_APPLICABLE` in the open. It is never skipped.
2. **Undetermined is not permission.** A dimension that could not be
   evaluated yields `UNDETERMINED`, and any `UNDETERMINED` makes the whole
   relation invalid. Missing evidence never authorizes anything.
3. **Mismatch and undetermined are different facts.** A failed integrity
   check is a determinate negative. A missing authority record is not.

## Authority at commit, not authority at issue

`oat/authority/current_state.py` stores authority as ordered epochs and
answers "what was true at tick *t*". The verifier looks up the state at the
commit tick and compares its digest to the one the authorization was bound
to. An authorization that was perfectly valid when issued fails if authority
moved before the consequence landed.

This is the single most common way a boundary is crossed without anyone
doing anything obviously wrong.

## Exact-action binding

`oat/consequence/canonical.py` normalizes an action over a fixed field set —
action type, target, parameters, quantity, unit, principal, sink, tenant,
release — and digests it. An `action_type`-only comparison is never
sufficient. Changing a payment's amount after authorization produces a
different digest and fails the binding.

## The interlock and the verifier are different things

`oat/consequence/sink.py` provides a reference interlock that fails closed on
every unsatisfied binding. That is a *preventive control*.

The verifier is separate and asks a different question: given what actually
committed, can valid current authority be established? OAT keeps both because
a system can have a perfect interlock on the routes it guards and still
commit consequences through a route that never reaches it.

## Disposition taxonomy

```text
CONSEQUENCE_BOUNDARY_FAILURE     protected commit, no valid current authority
VEIP_INTERNAL_PROPERTY_FAILURE   local predicate defect, nothing committed
INTEGRATION_FAILURE              undeclared executable route, nothing prohibited committed
HARNESS_OR_INSTRUMENT_FAILURE    the instrument itself is defective
UNKNOWN_OR_UNESTABLISHED         material evidence missing
NO_BOUNDARY_COUNTEREXAMPLE       none of the above, on the routes actually exercised
```

These are not collapsible. An instrument defect must never be reported as a
subject finding, and a local predicate failure must never be reported as a
boundary crossing.

## Representation limits

The reference profile — SQLite-shaped payment ledger, HMAC authorization
artifact, local authority store, synthetic routes — consists of deterministic
test primitives carried forward from Consequence Boundary Instrument
Candidate 001 (2026-09-18). They are not production infrastructure and make
no claim about any real deployment.

```text
CONSEQUENCE_BOUNDARY_INSTRUMENT = DETERMINISTIC_REFERENCE_IMPLEMENTATION
REAL_TARGET_INTEGRATION         = NOT_ESTABLISHED
REAL_ENTERPRISE_ALL_ROUTE_ASSURANCE = NOT_ESTABLISHED
```
