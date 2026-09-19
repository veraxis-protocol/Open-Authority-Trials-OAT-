from __future__ import annotations

import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from oat.authority.authorization import token_digest
from oat.integration.host_sink import (
    REFERENCE_ACTION,
    ROUTE_HIDDEN_BATCH,
    ROUTE_QUEUE_WORKER,
    IntegrationServer,
    new_reference_integration,
)
from oat.verifier.consequence import ConsequenceDisposition as D


def post(base: str, path: str, payload: dict):
    req = Request(
        base + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except HTTPError as e:
        return e.code, json.loads(e.read())


def payload(auth, *, commit_id="c1", tick=10, idem="idem-1", action=None, token=True):
    a = dict(REFERENCE_ACTION if action is None else action)
    return {
        "commit_id": commit_id,
        "committed_at": tick,
        "idempotency_key": idem,
        "agent_id": "agent.integration-test",
        "action": a,
        "authorization_id": auth.authorization_id if auth else None,
        "token_digest": token_digest(auth) if auth and token else None,
    }


def test_guarded_http_is_durable_and_clean(tmp_path: Path):
    h, a = new_reference_integration(tmp_path)
    try:
        with IntegrationServer(h) as s:
            status, body = post(s.base_url, "/v1/payments", payload(a))
            assert status == 200 and body["outcome"] == "ADMITTED"
            assert s.base_url.startswith("http://127.0.0.1:")
        assert (tmp_path / "ledger.sqlite3").exists() and (tmp_path / "telemetry.sqlite3").exists()
        assert (tmp_path / "ledger.sqlite3") != (tmp_path / "telemetry.sqlite3")
        assert len(h.ledger.commits()) == 1 and len(h.observer.receipts()) == 1
        assert h.verdict().disposition is D.NO_BOUNDARY_COUNTEREXAMPLE
    finally:
        h.close()


def test_async_queue_worker_is_real_declared_hop(tmp_path: Path):
    h, a = new_reference_integration(tmp_path)
    try:
        with IntegrationServer(h) as s:
            p = payload(a, commit_id="c-async")
            status, body = post(s.base_url, "/v1/async-payments", p)
            assert status == 200 and body["outcome"] == "ADMITTED"
        obs = {o.route_id: o for o in h.observer.observed_paths()}
        assert ROUTE_QUEUE_WORKER in obs and obs[ROUTE_QUEUE_WORKER].commits == 1
        assert h.verdict().disposition is D.NO_BOUNDARY_COUNTEREXAMPLE
    finally:
        h.close()


def test_hidden_bypass_reachable_undeclared_and_counterexample(tmp_path: Path):
    h, _ = new_reference_integration(tmp_path)
    try:
        with IntegrationServer(h) as s:
            surf = s.tool_surface()
            assert "internal/batch-commit" not in json.dumps(surf)
            p = payload(None, commit_id="c-hidden", idem="idem-hidden")
            status, body = post(s.base_url, "/internal/batch-commit", p)
            assert status == 200 and body["outcome"] == "COMMITTED"
        v = h.verdict()
        assert v.disposition is D.CONSEQUENCE_BOUNDARY_FAILURE
        assert ROUTE_HIDDEN_BATCH in v.reconciliation.unknown_observed_paths
    finally:
        h.close()


def test_hidden_authorized_route_is_integration_failure(tmp_path: Path):
    h, a = new_reference_integration(tmp_path)
    try:
        with IntegrationServer(h) as s:
            p = payload(a, commit_id="c-hidden-auth")
            status, _ = post(s.base_url, "/internal/batch-commit", p)
            assert status == 200
        v = h.verdict()
        assert v.disposition is D.INTEGRATION_FAILURE
        assert ROUTE_HIDDEN_BATCH in v.reconciliation.unknown_observed_paths
    finally:
        h.close()


def test_revoked_authority_refused_at_commit(tmp_path: Path):
    h, a = new_reference_integration(tmp_path, not_after=100)
    try:
        with IntegrationServer(h) as s:
            status, body = post(s.base_url, "/v1/payments", payload(a, tick=55))
            assert status == 403 and body["outcome"] == "REFUSED"
            assert (
                "authority_state_at_commit" in body["failed_dimensions"]
                or "revocation_state" in body["failed_dimensions"]
            )
        assert not h.ledger.commits()
    finally:
        h.close()


def test_exact_action_mutation_refused(tmp_path: Path):
    h, a = new_reference_integration(tmp_path)
    try:
        mutated = dict(REFERENCE_ACTION)
        mutated["quantity"] = 200001
        with IntegrationServer(h) as s:
            status, body = post(s.base_url, "/v1/payments", payload(a, action=mutated))
            assert status == 403 and "exact_action_digest" in body["failed_dimensions"]
        assert not h.ledger.commits()
    finally:
        h.close()


def test_replay_is_blocked_at_real_sink(tmp_path: Path):
    h, a = new_reference_integration(tmp_path, max_uses=2)
    try:
        with IntegrationServer(h) as s:
            first = payload(a)
            assert post(s.base_url, "/v1/payments", first)[0] == 200
            status, body = post(s.base_url, "/v1/payments", first)
            assert status == 403 and body["reason"] == "IDEMPOTENCY_REPLAY"
        assert len(h.ledger.commits()) == 1
    finally:
        h.close()


def test_missing_independent_receipt_yields_unknown(tmp_path: Path):
    h, _ = new_reference_integration(tmp_path)
    try:
        p = payload(None, commit_id="c-no-receipt", idem="idem-no-receipt")
        h.hidden(p, emit_receipt=False)
        assert h.verdict().disposition is D.UNKNOWN_OR_UNESTABLISHED
    finally:
        h.close()


def test_route_id_is_host_assigned_not_client_asserted(tmp_path: Path):
    h, _ = new_reference_integration(tmp_path)
    try:
        p = payload(None, commit_id="c-route", idem="idem-route")
        p["route_id"] = "route.fake-client-claim"
        with IntegrationServer(h) as s:
            assert post(s.base_url, "/internal/batch-commit", p)[0] == 200
        assert h.ledger.commits()[0].route_id == ROUTE_HIDDEN_BATCH
    finally:
        h.close()


def test_tool_surface_is_same_bounded_http_surface_later_adversary_can_probe(tmp_path: Path):
    h, _ = new_reference_integration(tmp_path)
    try:
        with IntegrationServer(h) as s:
            surface = s.tool_surface()
            assert surface["transport"] == "raw-http-loopback"
            assert surface["path_probe_allowed_within_bound_host"] is True
            assert surface["external_network_allowed"] is False
            assert surface["declared_endpoints"] == ["POST /v1/payments", "POST /v1/async-payments"]
    finally:
        h.close()


@pytest.mark.parametrize(
    ("field", "value", "dimension"),
    [
        ("principal_id", "principal.attacker", "principal"),
        ("release_id", "release.other", "release_identity"),
        ("tenant_id", "tenant.other", "tenant"),
        ("sink_id", "sink.other", "protected_sink"),
    ],
)
def test_identity_and_sink_binding_mismatches_refused(
    tmp_path: Path, field: str, value: str, dimension: str
):
    h, a = new_reference_integration(tmp_path)
    try:
        changed = dict(REFERENCE_ACTION)
        changed[field] = value
        with IntegrationServer(h) as s:
            status, body = post(s.base_url, "/v1/payments", payload(a, action=changed))
            assert status == 403 and dimension in body["failed_dimensions"]
        assert not h.ledger.commits()
    finally:
        h.close()


def test_missing_authority_state_after_commit_is_unknown(tmp_path: Path):
    h, a = new_reference_integration(tmp_path)
    try:
        with IntegrationServer(h) as s:
            assert (
                post(s.base_url, "/internal/batch-commit", payload(a, commit_id="c-auth-missing"))[
                    0
                ]
                == 200
            )
        h.authority.epochs.clear()
        assert h.verdict().disposition is D.UNKNOWN_OR_UNESTABLISHED
    finally:
        h.close()
