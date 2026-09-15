from __future__ import annotations

import pytest

from oat.veip.falsifiers import EVALUATORS, evaluate


@pytest.mark.parametrize(
    ("fid", "negative", "positive"),
    [
        (
            "FALS-VEIP-P-02",
            {"decision_sequence": ["ALLOW", "ALLOW"]},
            {"decision_sequence": ["ALLOW", "DENY"]},
        ),
        (
            "FALS-VEIP-P-03",
            {
                "transition_table": {},
                "raised_exception": False,
                "undefined_producible_transition": False,
            },
            {
                "transition_table": {},
                "raised_exception": True,
                "undefined_producible_transition": True,
            },
        ),
        (
            "FALS-VEIP-P-05",
            {
                "replay_result": {"ok": False},
                "recomputed_decision": "ALLOW",
                "pack.decision.classification": "DENY",
            },
            {
                "replay_result": {"ok": True},
                "recomputed_decision": "ALLOW",
                "pack.decision.classification": "DENY",
            },
        ),
        (
            "FALS-VEIP-P-09",
            {"decision": "ESCALATE", "permitted_actions": [], "action_type": "x"},
            {"decision": "ALLOW", "permitted_actions": [], "action_type": "x"},
        ),
        (
            "FALS-VEIP-P-11",
            {
                "validation_outcome": {"ok": False},
                "missing_fields": ["x"],
                "emitted_by_generate_evidence": False,
            },
            {
                "validation_outcome": {"ok": True},
                "missing_fields": ["x"],
                "emitted_by_generate_evidence": False,
            },
        ),
        (
            "FALS-VEIP-P-12A",
            {"classification_sequence": ["ALLOW", "ALLOW"]},
            {"classification_sequence": ["ALLOW", "DENY"]},
        ),
        (
            "FALS-VEIP-P-14",
            {
                "schema_digest": "a",
                "pinned_schema_digest": "a",
                "raised_exception": False,
                "pack_schema_version": "0.1.0",
                "spec_version": "0.1.0",
                "replay_result": {"ok": True},
            },
            {
                "schema_digest": "a",
                "pinned_schema_digest": "b",
                "raised_exception": False,
                "pack_schema_version": "0.1.0",
                "spec_version": "0.1.0",
                "replay_result": {"ok": False},
            },
        ),
        ("FALS-VEIP-P-17", {"raised_exception": True}, {"raised_exception": False}),
        (
            "FALS-VEIP-P-18",
            {"action_id": "a", "recomputed_fingerprint": "b", "replay_result": {"ok": False}},
            {"action_id": "a", "recomputed_fingerprint": "b", "replay_result": {"ok": True}},
        ),
        (
            "FALS-VEIP-P-19",
            {"stored_binding": "a", "computed_binding": "b", "IntegrityResult": {"ok": False}},
            {"stored_binding": "a", "computed_binding": "b", "IntegrityResult": {"ok": True}},
        ),
        (
            "FALS-VEIP-P-20",
            {
                "http_status": 400,
                "stored_pack": None,
                "submitted_pack_valid": False,
                "stored_pack_valid": False,
            },
            {
                "http_status": 200,
                "stored_pack": {},
                "submitted_pack_valid": False,
                "stored_pack_valid": False,
            },
        ),
        (
            "FALS-VEIP-P-01S",
            {
                "transition_table": {},
                "reachability_paths": [["PROPOSED", "AUTHORIZED", "EXECUTED"]],
            },
            {"transition_table": {}, "reachability_paths": [["PROPOSED", "EXECUTED"]]},
        ),
        (
            "FALS-VEIP-P-07S",
            {"transition_table": {"SUPERVISORY": ["AUTHORIZED"]}},
            {"transition_table": {"SUPERVISORY": ["EXECUTED"]}},
        ),
    ],
)
def test_each_frozen_ready_predicate_has_negative_and_counterexample(fid, negative, positive):
    assert evaluate(fid, negative)["disposition"] == "NOT_A_COUNTEREXAMPLE"
    assert evaluate(fid, positive)["disposition"] == "COUNTEREXAMPLE_VALIDATED"


@pytest.mark.parametrize("fid", sorted(EVALUATORS))
def test_missing_observable_is_unevaluable(fid):
    assert evaluate(fid, {})["disposition"] == "UNEVALUABLE"
