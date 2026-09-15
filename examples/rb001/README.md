# RB-001 reference run

`reference-run/` is a checked-in, byte-stable run package for
`RB-001-VULN-A`, regenerated from frozen fixtures by:

```bash
make demo          # or: oat demo
```

`make ci` regenerates it and fails if the result differs from what is committed,
so a change that quietly alters evidence bytes cannot pass the gate.

| File | Contents |
| --- | --- |
| `manifest.json` | run manifest: boundary, scenario, falsifier, adversary, and verifier identities |
| `witness.json` | candidate witness with the observable trace and the adversary's claimed evaluation |
| `verifier-result.json` | V1 disposition, predicate trace, and evidence digest |
| `replay-result.json` | replay of the run without the adversary, and digest comparison |
| `SHA256SUMS.json` | SHA-256 of every other file in the directory |

Check it yourself:

```bash
oat inspect examples/rb001/reference-run    # identities, disposition, checksums
oat replay  examples/rb001/reference-run    # re-derive without the adversary
```

```text
STATUS = METHOD_DEVELOPMENT_ONLY
CLAIM_BEARING_USE = PROHIBITED
```

The disposition recorded here is `COUNTEREXAMPLE_CONFIRMED` against a
**synthetic** enforcement path that caches an authorization decision across a
revocation. It describes no real system.
