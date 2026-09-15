"""Frozen public-surface adapter for the Experiment 001 VEIP baseline."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any


def _authority(data: dict[str, Any]) -> Any:
    from veip_sdk.veip_types import AuthorityEnvelope

    return AuthorityEnvelope(
        scope_id=str(data["scope_id"]),
        issuer=str(data["issuer"]),
        permitted_actions=[str(x) for x in data["permitted_actions"]],
        valid=bool(data.get("valid", True)),
    )


def _proposal(data: dict[str, Any]) -> Any:
    from veip_sdk.veip_types import ActionProposal

    return ActionProposal(action_type=str(data["action_type"]), payload=dict(data["payload"]))


def _decision(value: str) -> Any:
    from veip_sdk.veip_types import Decision

    return Decision(value)


def _result(value: Any) -> dict[str, Any]:
    return {"ok": bool(value[0]), "reason": str(value[1])}


def _paths(table: dict[str, list[str]], start: str = "PROPOSED") -> list[list[str]]:
    result: list[list[str]] = []
    pending = [[start]]
    while pending:
        path = pending.pop(0)
        result.append(path)
        if len(path) > len(table) + 2:
            continue
        for nxt in table.get(path[-1], []):
            if nxt not in path:
                pending.append([*path, nxt])
    return result


def invoke(falsifier_id: str, inputs: dict[str, Any]) -> dict[str, Any]:
    """Invoke only frozen public APIs and return a canonical observable trace."""
    from veip_sdk import VEIP_SPEC_VERSION, assert_spec_binding
    from veip_sdk.authorize import classify
    from veip_sdk.evidence import generate_evidence
    from veip_sdk.replay import replay_validate
    from veip_sdk.schema import validate_evidence_pack
    from veip_sdk.state_machine import StateMachine
    from veip_verifier_core.replay import compute_integrity_binding, verify_integrity_binding

    if falsifier_id == "FALS-VEIP-P-02":
        a, p = _authority(inputs["authority"]), _proposal(inputs["proposal"])
        return {"decision_sequence": [classify(a, p).value for _ in range(inputs["repetitions"])]}
    if falsifier_id == "FALS-VEIP-P-03":
        table = deepcopy(StateMachine.VALID_TRANSITIONS)
        target = {
            "ALLOW": "AUTHORIZED",
            "DENY": "DENIED",
            "ESCALATE": "ESCALATED",
            "SUPERVISORY": "SUPERVISORY",
        }
        reachable = {p[-1] for p in _paths(table)}
        undefined = any(
            s in table and d not in table[s] for s in reachable for d in target.values()
        )
        return {
            "transition_table": table,
            "raised_exception": undefined,
            "undefined_producible_transition": undefined,
        }
    if falsifier_id in {"FALS-VEIP-P-01S", "FALS-VEIP-P-07S"}:
        table = deepcopy(StateMachine.VALID_TRANSITIONS)
        return {"transition_table": table, "reachability_paths": _paths(table)}
    if falsifier_id == "FALS-VEIP-P-05":
        a, p, pack = (
            _authority(inputs["authority"]),
            _proposal(inputs["proposal"]),
            deepcopy(inputs["evidence_pack"]),
        )
        return {
            "replay_result": _result(replay_validate(pack, a, p)),
            "recomputed_decision": classify(a, p).value,
            "pack.decision.classification": pack.get("decision", {}).get("classification"),
        }
    if falsifier_id == "FALS-VEIP-P-09":
        a, p = _authority(inputs["authority"]), _proposal(inputs["proposal"])
        return {
            "decision": classify(a, p).value,
            "permitted_actions": list(a.permitted_actions),
            "action_type": p.action_type,
        }
    if falsifier_id == "FALS-VEIP-P-11":
        pack = deepcopy(inputs["evidence_pack"])
        try:
            validate_evidence_pack(pack)
            ok, reason = True, "OK"
        except Exception as exc:
            ok, reason = False, type(exc).__name__
        required = {
            "schema_version",
            "evidence_id",
            "created_at",
            "authority",
            "policy",
            "action",
            "decision",
            "execution",
            "provenance",
        }
        return {
            "validation_outcome": {"ok": ok, "reason": reason},
            "missing_fields": sorted(required - set(pack)),
            "emitted_by_generate_evidence": False,
        }
    if falsifier_id == "FALS-VEIP-P-12A":
        a, p, d = (
            _authority(inputs["authority"]),
            _proposal(inputs["proposal"]),
            _decision(inputs["decision"]),
        )
        packs = [generate_evidence(a, p, d) for _ in range(inputs["repetitions"])]
        return {"classification_sequence": [pack["decision"]["classification"] for pack in packs]}
    if falsifier_id == "FALS-VEIP-P-14":
        raw = inputs["schema_file"].encode()
        digest = hashlib.sha256(raw).hexdigest()
        try:
            assert_spec_binding()
            raised = False
        except Exception:
            raised = True
        a = _authority({"scope_id": "oat", "issuer": "oat", "permitted_actions": ["probe"]})
        p = _proposal({"action_type": "probe", "payload": {}})
        pack = generate_evidence(a, p, classify(a, p))
        pack["schema_version"] = inputs["pack.schema_version"]
        return {
            "schema_digest": digest,
            "pinned_schema_digest": inputs["pinned_sha256"],
            "raised_exception": raised,
            "pack_schema_version": pack["schema_version"],
            "spec_version": VEIP_SPEC_VERSION,
            "replay_result": _result(replay_validate(pack, a, p, validate_schema=False)),
        }
    if falsifier_id == "FALS-VEIP-P-17":
        try:
            StateMachine.validate_transition(inputs["current_state"], inputs["next_state"])
            raised = False
        except ValueError:
            raised = True
        return {"raised_exception": raised}
    if falsifier_id == "FALS-VEIP-P-18":
        pack, p = deepcopy(inputs["evidence_pack"]), _proposal(inputs["proposal"])
        classification = str(pack.get("decision", {}).get("classification", "ALLOW"))
        a = _authority(
            {
                "scope_id": str(pack.get("authority", {}).get("scope_id", "oat")),
                "issuer": str(pack.get("authority", {}).get("issuer", "oat")),
                "permitted_actions": [p.action_type] if classification == "ALLOW" else [],
                "valid": classification != "DENY",
            }
        )
        fingerprint = hashlib.sha256(
            json.dumps(
                {"action_type": p.action_type, "payload": p.payload},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        ).hexdigest()[:32]
        return {
            "action_id": pack.get("action", {}).get("action_id"),
            "recomputed_fingerprint": fingerprint,
            "replay_result": _result(replay_validate(pack, a, p, validate_schema=False)),
        }
    if falsifier_id == "FALS-VEIP-P-19":
        pack = deepcopy(inputs["evidence_pack"])
        result = verify_integrity_binding(pack)
        stored = str(
            pack.get("execution", {}).get("outcome", {}).get("result_ref", "")
        ).removeprefix("sha256:")
        return {
            "stored_binding": stored,
            "computed_binding": compute_integrity_binding(pack),
            "IntegrityResult": {"ok": result.ok, "reason": result.reason},
        }
    if falsifier_id == "FALS-VEIP-P-20":
        import veip_registry.app as registry
        from fastapi import HTTPException
        from veip_registry.schema import validate_evidence_pack as registry_validate
        from veip_registry.storage import InMemoryStore

        pack = deepcopy(inputs["http_request"].get("body", inputs["http_request"]))
        registry._store = InMemoryStore()
        try:
            registry_validate(pack)
            valid = True
        except Exception:
            valid = False
        stored_pack: Any = None
        try:
            response = registry.ingest_evidence(pack)
            status = response.status_code
            stored_pack = registry._store.get(str(pack.get("evidence_id")))
        except (HTTPException, KeyError) as exc:
            status = int(getattr(exc, "status_code", 500))
        try:
            registry_validate(stored_pack)
            stored_valid = True
        except Exception:
            stored_valid = False
        return {
            "http_status": status,
            "stored_pack": stored_pack,
            "submitted_pack_valid": valid,
            "stored_pack_valid": stored_valid,
        }
    raise KeyError(f"unsupported falsifier: {falsifier_id}")
