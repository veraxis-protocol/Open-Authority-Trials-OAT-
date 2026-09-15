# FORMATION-0004 — Validation tooling mutated a frozen subject worktree

**Status:** hard gate adopted for Experiment 001  
**Observed:** 2026-09-15

Editable/local package installation and Python bytecode generation can alter
tracked generated artifacts inside an otherwise commit-pinned subject
worktree. In the stopped harness-validation attempt, tracked `egg-info` and
`__pycache__` paths changed in the verifier and registry worktrees even though
their commits and Git trees remained pinned.

Commit/tree pinning is therefore necessary but insufficient for execution
workspace purity. Frozen subject worktrees must never be used as editable build
targets. Experiment subject execution must use immutable Git-derived artifacts
installed into an isolated runtime, with artifact and import provenance bound
back to the frozen commits. A subject-integrity sentinel must confirm the
frozen head, tree, and empty worktree status before and after each validation
phase.

Tracked `egg-info` and `__pycache__` artifacts materially increase contamination
risk. This experiment does not modify the frozen VEIP repositories to address
that separate repository-hygiene concern.
