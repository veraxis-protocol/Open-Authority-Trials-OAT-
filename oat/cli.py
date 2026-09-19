"""``oat`` command line interface.

Every command that presents a development result prints the quarantine banner
on stdout and carries the machine-readable equivalent in its JSON output.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from oat import CLAIM_BEARING_USE, CLAIM_CEILING, RUN_MODE, __version__
from oat.consequence.scenarios import SCENARIOS as CONSEQUENCE_SCENARIOS
from oat.dryrun import run_dry_run
from oat.evidence import replay as consequence_replay
from oat.manifest import read_json
from oat.pipeline import (
    run_scenario,
    strip_runtime_from_run_dir,
    verify_sha256sums,
    write_sha256sums,
)
from oat.replay import replay_run
from oat.verifier import v1

DEFAULT_DEMO_SCENARIO: str = "scenarios/rb001/VULN-A.json"
DEFAULT_DEMO_OUT: str = "examples/rb001/reference-run"


def banner(stream: Any) -> None:
    """Print the mandatory development-only quarantine labels."""
    print(f"STATUS = {RUN_MODE}", file=stream)
    print(f"CLAIM_BEARING_USE = {CLAIM_BEARING_USE}", file=stream)


def _emit(payload: dict[str, Any], as_json: bool, stream: Any) -> None:
    if as_json:
        print(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False), file=stream)


def _load_witness(path: Path) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Accept either a witness file or a run directory."""
    if path.is_dir():
        return read_json(path / "witness.json"), read_json(path / "manifest.json")
    witness = read_json(path)
    manifest_path = path.parent / "manifest.json"
    manifest = read_json(manifest_path) if manifest_path.is_file() else None
    return witness, manifest


def cmd_run(args: argparse.Namespace, stream: Any) -> int:
    run = run_scenario(args.scenario, out_dir=args.out)
    result = run["verifier_result"]
    banner(stream)
    print(f"scenario          = {run['scenario_id']}", file=stream)
    print(f"disposition       = {result['disposition']}", file=stream)
    print(f"computational     = {result['computational_result']}", file=stream)
    print(f"candidates        = {run['witness']['search']['candidates_explored']}", file=stream)
    print(f"witness digest    = {result['witness_digest']}", file=stream)
    print(f"evidence digest   = {result['evidence_digest']}", file=stream)
    if args.out:
        print(f"run package       = {run['run_dir']}", file=stream)
    print(f"claim ceiling     = {CLAIM_CEILING}", file=stream)
    _emit(result, args.json, stream)
    return 0 if result["disposition"] != v1.DISPOSITION_REJECTED else 3


def cmd_verify(args: argparse.Namespace, stream: Any) -> int:
    witness, manifest = _load_witness(Path(args.target))
    result = v1.verify(witness, expected_manifest=manifest)
    banner(stream)
    print(f"scenario          = {result['scenario_id']}", file=stream)
    print(f"disposition       = {result['disposition']}", file=stream)
    print(f"rejection reason  = {result['rejection_reason']}", file=stream)
    print(f"evidence digest   = {result['evidence_digest']}", file=stream)
    for entry in result["predicate_trace"]:
        print(f"  predicate {entry['predicate']} -> {entry['result']}", file=stream)
    for line in result["detail"]:
        print(f"  detail: {line}", file=stream)
    _emit(result, args.json, stream)
    return 0 if result["disposition"] != v1.DISPOSITION_REJECTED else 3


def cmd_replay(args: argparse.Namespace, stream: Any) -> int:
    result = replay_run(args.run, write=args.write)
    if args.write:
        write_sha256sums(args.run)
    banner(stream)
    print(f"scenario          = {result['scenario_id']}", file=stream)
    print(f"adversary used    = {result['adversary_used']}", file=stream)
    print(f"disposition       = {result['disposition']}", file=stream)
    print(f"evidence digest   = {result['recomputed_evidence_digest']}", file=stream)
    print(f"replay ok         = {result['replay_ok']}", file=stream)
    _emit(result, args.json, stream)
    return 0 if result["replay_ok"] else 4


def _field(document: dict[str, Any], *path: str, default: str = "<unavailable>") -> str:
    """Read a nested field for display, tolerating a damaged package."""
    node: Any = document
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return str(node)


def cmd_inspect(args: argparse.Namespace, stream: Any) -> int:
    directory = Path(args.run)
    # Checksums first: a damaged package must report as damaged, not traceback.
    sums = verify_sha256sums(directory)
    manifest = read_json(directory / "manifest.json")
    witness = read_json(directory / "witness.json")
    result = read_json(directory / "verifier-result.json")
    banner(stream)
    print(f"scenario          = {_field(manifest, 'scenario', 'id')}", file=stream)
    print(f"enforcement path  = {_field(manifest, 'scenario', 'enforcement_path')}", file=stream)
    print(
        f"boundary          = {_field(manifest, 'boundary', 'id')} "
        f"{_field(manifest, 'boundary', 'version')}",
        file=stream,
    )
    print(
        f"falsifier         = {_field(manifest, 'falsifier', 'id')} "
        f"{_field(manifest, 'falsifier', 'version')}",
        file=stream,
    )
    print(
        f"adversary         = {_field(manifest, 'adversary', 'id')} "
        f"{_field(manifest, 'adversary', 'version')}",
        file=stream,
    )
    print(
        f"verifier          = {_field(manifest, 'verifier', 'id')} "
        f"{_field(manifest, 'verifier', 'version')}",
        file=stream,
    )
    print(f"manifest digest   = {_field(witness, 'manifest_digest')}", file=stream)
    print(f"disposition       = {_field(result, 'disposition')}", file=stream)
    print(f"evidence digest   = {_field(result, 'evidence_digest')}", file=stream)
    print(f"sha256sums ok     = {sums['ok']} ({sums['checked']} files)", file=stream)
    for line in sums["detail"]:
        print(f"  detail: {line}", file=stream)
    print(f"claim ceiling     = {CLAIM_CEILING}", file=stream)
    _emit({"manifest": manifest, "verifier_result": result, "sha256sums": sums}, args.json, stream)
    return 0 if sums["ok"] else 5


RUN_DIR_NOTICE: str = """\
# METHOD_DEVELOPMENT_ONLY

```text
STATUS = METHOD_DEVELOPMENT_ONLY
CLAIM_BEARING_USE = PROHIBITED
CLAIM_BEARING_TRIAL_AUTHORIZED = FALSE
```

This directory is a generated development run package against a **synthetic**
reference boundary. It is not claim-bearing evidence, and no artifact in it may
be promoted into a claim-bearing trial: after the constitutional gates pass,
the applicable trial must be rerun from a newly frozen manifest.

Regenerate with `make demo`; check with `oat inspect` and `oat replay`.
"""


def cmd_demo(args: argparse.Namespace, stream: Any) -> int:
    run = run_scenario(args.scenario, out_dir=args.out)
    replay = replay_run(args.out, write=True)
    (Path(args.out) / "README_METHOD_DEVELOPMENT_ONLY.md").write_text(
        RUN_DIR_NOTICE, encoding="utf-8", newline="\n"
    )
    stripped = strip_runtime_from_run_dir(args.out)
    write_sha256sums(args.out)
    sums = verify_sha256sums(args.out)
    banner(stream)
    print(f"reference run     = {args.out}", file=stream)
    print(f"scenario          = {run['scenario_id']}", file=stream)
    print(f"disposition       = {run['verifier_result']['disposition']}", file=stream)
    print(f"replay ok         = {replay['replay_ok']}", file=stream)
    print(f"sha256sums ok     = {sums['ok']} ({sums['checked']} files)", file=stream)
    print(f"runtime stripped  = {len(stripped)} files (canonical evidence only)", file=stream)
    return 0 if replay["replay_ok"] and sums["ok"] else 6


def cmd_dryrun(args: argparse.Namespace, stream: Any) -> int:
    report = run_dry_run(args.vuln, args.control, out_dir=args.out)
    banner(stream)
    print(f"target            = {report['target']}", file=stream)
    print(f"transport         = {report['transport']}", file=stream)
    print(f"provider run      = {report['provider_run_occurred']}", file=stream)
    print(f"subject exposed   = {report['veip_subject_exposed']}", file=stream)
    for entry in report["checks"]:
        mark = "PASS" if entry["passed"] else "FAIL"
        print(f"  [{mark}] {entry['check']} -> {entry['observed']}", file=stream)
    print(f"dry run ok        = {report['dryrun_ok']}", file=stream)
    _emit(report, args.json, stream)
    return 0 if report["dryrun_ok"] else 7


# --- consequence-boundary commands -------------------------------------


def cmd_consequence_run(args: argparse.Namespace, stream: Any) -> int:
    """Execute a deterministic consequence-boundary scenario."""
    banner(stream)
    try:
        package = consequence_replay.run_scenario(args.scenario)
    except KeyError as exc:
        print(str(exc).strip('"'), file=stream)
        return 2
    verdict = package["verdict"]
    print(f"scenario    = {package['scenario']}", file=stream)
    print(f"disposition = {verdict['disposition']}", file=stream)
    print(f"reason      = {verdict['reason']}", file=stream)
    print(f"evidence    = {package['evidence_digest']}", file=stream)
    if args.out:
        target = consequence_replay.write_package(package, args.out)
        print(f"written     = {target}", file=stream)
    _emit(package, args.json, stream)
    return 0


def cmd_consequence_verify(args: argparse.Namespace, stream: Any) -> int:
    """Recompute the evidence digest of a stored consequence run."""
    banner(stream)
    package = consequence_replay.read_package(args.run)
    ok, detail = consequence_replay.verify_package(package)
    print(f"verify = {'PASS' if ok else 'FAIL'}", file=stream)
    print(detail, file=stream)
    _emit({"verify": ok, "detail": detail}, args.json, stream)
    return 0 if ok else 1


def cmd_consequence_replay(args: argparse.Namespace, stream: Any) -> int:
    """Replay a stored consequence run without any provider."""
    banner(stream)
    package = consequence_replay.read_package(args.run)
    ok, detail = consequence_replay.replay_scenario(package["scenario"], package)
    print(f"replay = {'PASS' if ok else 'FAIL'}", file=stream)
    print(detail, file=stream)
    _emit({"replay": ok, "detail": detail}, args.json, stream)
    return 0 if ok else 1


def cmd_paths_inspect(args: argparse.Namespace, stream: Any) -> int:
    """Show declared versus observed routes for a stored run."""
    banner(stream)
    package = consequence_replay.read_package(args.run)
    reconciliation = package["verdict"]["path_reconciliation"] or {}
    for key in (
        "declared_path_set",
        "observed_path_set",
        "unknown_observed_paths",
        "unexercised_declared_paths",
    ):
        values = reconciliation.get(key) or []
        print(f"{key:28} = {', '.join(values) if values else '(none)'}", file=stream)
    print(
        "\nA declared inventory is evidence about what the designers believed.\n"
        "It is not ground truth about what the agent can reach.",
        file=stream,
    )
    _emit(reconciliation, args.json, stream)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oat",
        description=(
            "Open Authority Trials — METHOD_DEVELOPMENT_ONLY instrument. "
            "Claim-bearing use is PROHIBITED."
        ),
    )
    parser.add_argument("--version", action="version", version=f"oat {__version__}")
    parser.add_argument("--json", action="store_true", help="also emit machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="run a frozen scenario end to end")
    run_parser.add_argument("scenario")
    run_parser.add_argument("--out", default=None, help="write the run package to this directory")
    run_parser.set_defaults(handler=cmd_run)

    verify_parser = sub.add_parser("verify", help="verify a witness or run package")
    verify_parser.add_argument("target")
    verify_parser.set_defaults(handler=cmd_verify)

    replay_parser = sub.add_parser("replay", help="deterministically replay a run package")
    replay_parser.add_argument("run")
    replay_parser.add_argument("--write", action="store_true", help="write replay-result.json")
    replay_parser.set_defaults(handler=cmd_replay)

    inspect_parser = sub.add_parser("inspect", help="inspect a run package")
    inspect_parser.add_argument("run")
    inspect_parser.set_defaults(handler=cmd_inspect)

    demo_parser = sub.add_parser("demo", help="regenerate the checked-in reference run")
    demo_parser.add_argument("--scenario", default=DEFAULT_DEMO_SCENARIO)
    demo_parser.add_argument("--out", default=DEFAULT_DEMO_OUT)
    demo_parser.set_defaults(handler=cmd_demo)

    dryrun_parser = sub.add_parser(
        "dryrun", help="synthetic plumbing dry run (no provider, no external subject)"
    )
    dryrun_parser.add_argument("--vuln", default="scenarios/rb001/VULN-A.json")
    dryrun_parser.add_argument("--control", default="scenarios/rb001/CONTROL.json")
    dryrun_parser.add_argument("--out", default=None)
    dryrun_parser.set_defaults(handler=cmd_dryrun)

    consequence_parser = sub.add_parser(
        "consequence", help="deterministic consequence-boundary instrument"
    )
    consequence_sub = consequence_parser.add_subparsers(dest="consequence_command", required=True)

    cons_run = consequence_sub.add_parser("run", help="run a consequence-boundary scenario")
    cons_run.add_argument("scenario", choices=sorted(CONSEQUENCE_SCENARIOS))
    cons_run.add_argument("--out", default=None, help="write the run package here")
    cons_run.set_defaults(handler=cmd_consequence_run)

    cons_verify = consequence_sub.add_parser("verify", help="verify stored consequence evidence")
    cons_verify.add_argument("run")
    cons_verify.set_defaults(handler=cmd_consequence_verify)

    cons_replay = consequence_sub.add_parser("replay", help="replay a consequence run")
    cons_replay.add_argument("run")
    cons_replay.set_defaults(handler=cmd_consequence_replay)

    paths_parser = sub.add_parser("paths", help="declared versus actually observed routes")
    paths_sub = paths_parser.add_subparsers(dest="paths_command", required=True)
    paths_inspect = paths_sub.add_parser("inspect", help="inspect route reconciliation")
    paths_inspect.add_argument("run")
    paths_inspect.set_defaults(handler=cmd_paths_inspect)

    return parser


def main(argv: list[str] | None = None, stream: Any = None) -> int:
    """CLI entry point. Returns a process exit code."""
    out = stream if stream is not None else sys.stdout
    args = build_parser().parse_args(argv)
    handler: Any = args.handler
    code: int = handler(args, out)
    return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
