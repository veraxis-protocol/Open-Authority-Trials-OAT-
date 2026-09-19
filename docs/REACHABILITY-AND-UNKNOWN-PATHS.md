# Reachability and unknown paths

```text
STATUS = METHOD_DEVELOPMENT_ONLY
CLAIM_BEARING_USE = PROHIBITED
```

## The reachability invariant

> The authority invariant must remain true over the *actual reachable*
> execution graph, not merely the *declared* execution graph.

This is a second, independent invariant. OAT must never equate:

```text
all declared routes passed
```

with:

```text
all reachable routes are controlled
```

## Declared inventory is evidence, not truth

`oat/paths/inventory.py` holds what a system's designers wrote down.
`oat/paths/observations.py` holds what the sink actually saw. They are
different kinds of object and the code keeps them apart on purpose.

`oat/paths/discovery.py` computes:

```text
UNKNOWN_OBSERVED_PATHS      = OBSERVED_PATH_SET - DECLARED_PATH_SET
UNEXERCISED_DECLARED_PATHS  = DECLARED_PATH_SET - OBSERVED_PATH_SET
```

The first says the declaration was incomplete. The second says a claim in the
declaration went untested — which is why a clean run reports it rather than
quietly rounding it up to coverage.

## Discovering a route is not crossing a boundary

This distinction is load-bearing and is enforced by the verifier's precedence
rules, not by convention:

- an undeclared route that commits a protected consequence with no valid
  current authority is a `CONSEQUENCE_BOUNDARY_FAILURE`;
- an undeclared route that commits nothing prohibited is an
  `INTEGRATION_FAILURE`.

Two deterministic controls pin this: `test_hidden_route_discovered` and
`test_hidden_route_alone_is_not_a_boundary_counterexample`.

## The hidden-route positive control

The reference profile's declared inventory deliberately omits
`route.batch-replay`. The route is reachable, it is unguarded, and the sink
observes it. The `hidden-route-bypass` scenario uses it to commit a payment
with no authorization at all, and the instrument both discovers the route and
reports the crossing.

This control exists because an instrument that can only see declared routes
would report a clean result on exactly the failure OAT is built to find.

## Scoping a negative

When the instrument finds nothing, it says so in scoped language:

> no protected consequence committed without valid current authority **on the
> routes actually exercised**

and it still reports `unexercised_declared_paths`. A negative over a partial
graph is a partial negative, and it is written that way in the machine-readable
verdict, not only in prose.
