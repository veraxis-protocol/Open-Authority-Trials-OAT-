"""CLI surface: commands, exit codes, and machine-readable output."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from oat.cli import build_parser, main
from oat.manifest import read_json, write_json
from oat.pipeline import run_scenario
from tests.conftest import scenario_path


def run_cli(*argv: str) -> tuple[int, str]:
    stream = io.StringIO()
    code = main(list(argv), stream=stream)
    return code, stream.getvalue()


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("VULN-A", "COUNTEREXAMPLE_CONFIRMED"),
        ("VULN-B", "COUNTEREXAMPLE_CONFIRMED"),
        ("CONTROL", "NO_COUNTEREXAMPLE"),
    ],
)
def test_run_reports_the_expected_disposition(name: str, expected: str, tmp_path: Path) -> None:
    code, text = run_cli("run", str(scenario_path(name)), "--out", str(tmp_path / name))
    assert code == 0
    assert f"disposition       = {expected}" in text
    assert "evidence digest   = sha256:" in text


def test_run_without_out_writes_nothing(tmp_path: Path) -> None:
    code, text = run_cli("run", str(scenario_path("VULN-A")))
    assert code == 0
    assert "run package" not in text
    assert not list(tmp_path.iterdir())


def test_verify_accepts_a_run_directory(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-A"), out_dir=run_dir)
    code, text = run_cli("verify", str(run_dir))
    assert code == 0
    assert "COUNTEREXAMPLE_CONFIRMED" in text
    assert "predicate committed -> True" in text


def test_verify_accepts_a_bare_witness_file(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-A"), out_dir=run_dir)
    lone = tmp_path / "witness.json"
    lone.write_text((run_dir / "witness.json").read_text(encoding="utf-8"), encoding="utf-8")
    code, text = run_cli("verify", str(lone))
    assert code == 0
    assert "COUNTEREXAMPLE_CONFIRMED" in text


def test_verify_exits_nonzero_on_a_rejected_witness(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-A"), out_dir=run_dir)
    witness = read_json(run_dir / "witness.json")
    witness["falsifier"]["version"] = "9.9.9"
    write_json(run_dir / "witness.json", witness)

    code, text = run_cli("verify", str(run_dir))
    assert code == 3
    assert "FALSIFIER_VERSION_UNSUPPORTED" in text
    assert "detail:" in text


def test_replay_command_reports_success(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-A"), out_dir=run_dir)
    code, text = run_cli("replay", str(run_dir), "--write")
    assert code == 0
    assert "replay ok         = True" in text
    assert (run_dir / "replay-result.json").is_file()


def test_replay_exits_nonzero_when_a_run_no_longer_reproduces(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-A"), out_dir=run_dir)
    result = read_json(run_dir / "verifier-result.json")
    result["evidence_digest"] = "sha256:" + "3" * 64
    write_json(run_dir / "verifier-result.json", result)

    code, text = run_cli("replay", str(run_dir))
    assert code == 4
    assert "replay ok         = False" in text


def test_inspect_reports_identities_and_checksums(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-B"), out_dir=run_dir)
    code, text = run_cli("inspect", str(run_dir))
    assert code == 0
    assert "enforcement path  = STALE_PROPAGATION" in text
    assert "falsifier         = OAT-FALSIFIER-RB-001" in text
    assert "verifier          = OAT-V1" in text
    assert "sha256sums ok     = True" in text


def test_inspect_exits_nonzero_when_checksums_fail(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-A"), out_dir=run_dir)
    (run_dir / "witness.json").write_text("{}\n", encoding="utf-8")
    code, text = run_cli("inspect", str(run_dir))
    assert code == 5
    assert "sha256sums ok     = False" in text


def test_demo_regenerates_a_replayable_reference_run(tmp_path: Path) -> None:
    out = tmp_path / "reference-run"
    code, text = run_cli("demo", "--scenario", str(scenario_path("VULN-A")), "--out", str(out))
    assert code == 0
    assert "replay ok         = True" in text
    assert "sha256sums ok     = True" in text
    for name in (
        "manifest.json",
        "witness.json",
        "verifier-result.json",
        "replay-result.json",
        "SHA256SUMS.json",
    ):
        assert (out / name).is_file()


def test_json_flag_emits_parseable_output(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_scenario(scenario_path("VULN-A"), out_dir=run_dir)
    _, text = run_cli("--json", "inspect", str(run_dir))
    payload = json.loads(text[text.index("{") :])
    assert payload["sha256sums"]["ok"] is True
    assert payload["verifier_result"]["disposition"] == "COUNTEREXAMPLE_CONFIRMED"


def test_version_flag_reports_the_package_version() -> None:
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--version"])
    assert exc.value.code == 0


def test_a_command_is_required() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_main_defaults_to_stdout(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["run", str(scenario_path("CONTROL"))])
    assert code == 0
    assert "STATUS = METHOD_DEVELOPMENT_ONLY" in capsys.readouterr().out


def test_dryrun_command_reports_every_check(tmp_path: Path) -> None:
    code, text = run_cli("dryrun", "--out", str(tmp_path / "dry"))
    assert code == 0
    assert "dry run ok        = True" in text
    assert "provider run      = False" in text
    assert "[PASS] false_assertion_refused" in text
