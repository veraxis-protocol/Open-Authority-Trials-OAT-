"""Production-representative local host/sink integration for OAT.

The integration has a real TCP/HTTP surface, a real queue/worker hop, a durable
SQLite ledger, and a physically separate SQLite observer store. It remains a
local method-development environment: no external network, no real money, no
provider calls.
"""

from __future__ import annotations

import json
import queue
import sqlite3
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from oat.authority.authorization import (
    Authorization,
    AuthorizationIssuer,
    validate_authorization,
)
from oat.authority.current_state import AuthorityState, AuthorityStore
from oat.consequence.canonical import exact_action_digest
from oat.consequence.model import CommitEvent, ConsequenceReceipt, ProtectedSink
from oat.paths.discovery import reconcile
from oat.paths.inventory import DeclaredPath, PathInventory
from oat.paths.observations import ObservedPath
from oat.verifier.consequence import ConsequenceEvidence, ConsequenceVerdict, adjudicate

ROUTE_HTTP_GUARDED = "route.http-guarded"
ROUTE_QUEUE_WORKER = "route.queue-worker"
ROUTE_HIDDEN_BATCH = "route.hidden-batch"

DECLARED_PATHS = PathInventory(
    (
        DeclaredPath(ROUTE_HTTP_GUARDED, "guarded synchronous payment endpoint", True),
        DeclaredPath(ROUTE_QUEUE_WORKER, "guarded async queue/worker endpoint", True),
    )
)


@dataclass(frozen=True)
class HostDecision:
    outcome: str
    reason: str
    commit_id: str | None = None
    failed_dimensions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "reason": self.reason,
            "commit_id": self.commit_id,
            "failed_dimensions": list(self.failed_dimensions),
        }


class SQLiteLedger:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        return con

    def _init(self) -> None:
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS ledger_commits (
                    commit_id TEXT PRIMARY KEY,
                    sink_id TEXT NOT NULL,
                    route_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    release_id TEXT NOT NULL,
                    action_digest TEXT NOT NULL,
                    normalized_action_json TEXT NOT NULL,
                    committed_at INTEGER NOT NULL,
                    authorization_ref TEXT,
                    authority_state_ref TEXT,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    trace_ref TEXT NOT NULL,
                    token_digest TEXT
                )
            """)

    def idempotency_seen(self, key: str) -> bool:
        with self._connect() as con:
            row = con.execute(
                "SELECT 1 FROM ledger_commits WHERE idempotency_key=?", (key,)
            ).fetchone()
            return row is not None

    def commit(self, event: CommitEvent, token: str | None) -> None:
        with self._lock, self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                """INSERT INTO ledger_commits VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.commit_id,
                    event.sink_id,
                    event.route_id,
                    event.tenant_id,
                    event.principal_id,
                    event.agent_id,
                    event.release_id,
                    event.action_digest,
                    json.dumps(event.normalized_action, sort_keys=True, separators=(",", ":")),
                    event.committed_at,
                    event.authorization_ref,
                    event.authority_state_ref,
                    event.idempotency_key,
                    event.trace_ref,
                    token,
                ),
            )
            con.commit()

    def commits(self) -> list[CommitEvent]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM ledger_commits ORDER BY committed_at, commit_id"
            ).fetchall()
        return [
            CommitEvent(
                commit_id=r["commit_id"],
                sink_id=r["sink_id"],
                route_id=r["route_id"],
                tenant_id=r["tenant_id"],
                principal_id=r["principal_id"],
                agent_id=r["agent_id"],
                release_id=r["release_id"],
                action_digest=r["action_digest"],
                normalized_action=json.loads(r["normalized_action_json"]),
                committed_at=r["committed_at"],
                authorization_ref=r["authorization_ref"],
                authority_state_ref=r["authority_state_ref"],
                idempotency_key=r["idempotency_key"],
                trace_ref=r["trace_ref"],
            )
            for r in rows
        ]

    def token_digests(self) -> dict[str, str]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT commit_id, token_digest FROM ledger_commits WHERE token_digest IS NOT NULL"
            ).fetchall()
        return {r["commit_id"]: r["token_digest"] for r in rows}


class SQLiteObserver:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        return con

    def _init(self) -> None:
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS receipts (
                    receipt_id TEXT PRIMARY KEY,
                    commit_id TEXT NOT NULL,
                    sink_id TEXT NOT NULL,
                    route_id TEXT NOT NULL,
                    observed_at INTEGER NOT NULL,
                    action_digest TEXT NOT NULL,
                    observer TEXT NOT NULL
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS route_observations (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    route_id TEXT NOT NULL,
                    observed_at INTEGER NOT NULL,
                    admitted INTEGER NOT NULL,
                    committed INTEGER NOT NULL,
                    commit_id TEXT
                )
            """)

    def record_arrival(
        self, route_id: str, tick: int, *, admitted: bool, committed: bool, commit_id: str | None
    ) -> None:
        with self._lock, self._connect() as con:
            con.execute(
                "INSERT INTO route_observations("
                "route_id, observed_at, admitted, committed, commit_id"
                ") VALUES (?,?,?,?,?)",
                (route_id, tick, int(admitted), int(committed), commit_id),
            )

    def record_commit(self, event: CommitEvent, *, emit_receipt: bool = True) -> None:
        self.record_arrival(
            event.route_id,
            event.committed_at,
            admitted=True,
            committed=True,
            commit_id=event.commit_id,
        )
        if emit_receipt:
            with self._lock, self._connect() as con:
                con.execute(
                    "INSERT INTO receipts VALUES (?,?,?,?,?,?,?)",
                    (
                        f"receipt-{event.commit_id}",
                        event.commit_id,
                        event.sink_id,
                        event.route_id,
                        event.committed_at,
                        event.action_digest,
                        "sqlite-independent-observer",
                    ),
                )

    def receipts(self) -> list[ConsequenceReceipt]:
        with self._connect() as con:
            rows = con.execute("SELECT * FROM receipts ORDER BY observed_at, receipt_id").fetchall()
        return [
            ConsequenceReceipt(
                receipt_id=r["receipt_id"],
                commit_id=r["commit_id"],
                sink_id=r["sink_id"],
                route_id=r["route_id"],
                observed_at=r["observed_at"],
                action_digest=r["action_digest"],
                observer=r["observer"],
            )
            for r in rows
        ]

    def observed_paths(self) -> tuple[ObservedPath, ...]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT route_id, COUNT(*) arrivals, SUM(committed) commits "
                "FROM route_observations GROUP BY route_id ORDER BY route_id"
            ).fetchall()
        return tuple(
            ObservedPath(r["route_id"], int(r["arrivals"]), int(r["commits"] or 0)) for r in rows
        )


class HostSinkIntegration:
    def __init__(
        self,
        root: Path,
        sink: ProtectedSink,
        authority: AuthorityStore,
        issuer: AuthorizationIssuer,
    ):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.sink = sink
        self.authority = authority
        self.issuer = issuer
        self.ledger = SQLiteLedger(root / "ledger.sqlite3")
        self.observer = SQLiteObserver(root / "telemetry.sqlite3")
        self.authorizations: dict[str, Authorization] = {}
        self._jobs: queue.Queue[tuple[dict[str, Any], threading.Event, dict[str, Any]]] = (
            queue.Queue()
        )
        self._stop = threading.Event()
        self._worker = threading.Thread(
            target=self._worker_loop, name="oat-queue-worker", daemon=True
        )
        self._worker.start()

    @property
    def declared_paths(self) -> PathInventory:
        return DECLARED_PATHS

    def register(self, authorization: Authorization) -> None:
        self.authorizations[authorization.authorization_id] = authorization

    def _build_commit(
        self, payload: dict[str, Any], route_id: str
    ) -> tuple[CommitEvent, Authorization | None, str | None]:
        action = dict(payload["action"])
        auth_id = payload.get("authorization_id")
        auth = self.authorizations.get(auth_id) if auth_id else None
        state = self.authority.at(int(payload["committed_at"]))
        event = CommitEvent(
            commit_id=str(payload["commit_id"]),
            sink_id=str(action["sink_id"]),
            route_id=route_id,
            tenant_id=str(action["tenant_id"]),
            principal_id=str(action["principal_id"]),
            agent_id=str(payload.get("agent_id", "agent.integration-test")),
            release_id=str(action["release_id"]),
            action_digest=exact_action_digest(action),
            normalized_action=action,
            committed_at=int(payload["committed_at"]),
            authorization_ref=str(auth_id) if auth_id else None,
            authority_state_ref=state.digest if state else None,
            idempotency_key=str(payload["idempotency_key"]),
            trace_ref=str(payload.get("trace_ref", f"trace-{payload['commit_id']}")),
        )
        token = payload.get("token_digest")
        return event, auth, str(token) if token is not None else None

    def guarded(self, payload: dict[str, Any], route_id: str) -> HostDecision:
        event, auth, presented = self._build_commit(payload, route_id)
        if self.ledger.idempotency_seen(event.idempotency_key):
            self.observer.record_arrival(
                route_id, event.committed_at, admitted=False, committed=False, commit_id=None
            )
            return HostDecision("REFUSED", "IDEMPOTENCY_REPLAY")
        prior = self.issuer.use_count(auth.authorization_id) if auth else None
        report = validate_authorization(
            auth,
            event,
            authority_at_commit=self.authority.at(event.committed_at),
            issuer=self.issuer,
            prior_use_count=(prior + 1) if prior is not None else None,
            correlated_token_digest=presented,
        )
        if not report.valid:
            failed = tuple(r.dimension for r in (report.mismatches or report.undetermined))
            self.observer.record_arrival(
                route_id, event.committed_at, admitted=False, committed=False, commit_id=None
            )
            return HostDecision("REFUSED", "BINDING_NOT_SATISFIED", failed_dimensions=failed)
        assert auth is not None
        self.issuer.record_use(auth.authorization_id)
        self.ledger.commit(event, presented)
        self.observer.record_commit(event)
        return HostDecision("ADMITTED", "ALL_BINDINGS_SATISFIED", event.commit_id)

    def hidden(self, payload: dict[str, Any], *, emit_receipt: bool = True) -> HostDecision:
        event, _auth, presented = self._build_commit(payload, ROUTE_HIDDEN_BATCH)
        if self.ledger.idempotency_seen(event.idempotency_key):
            self.observer.record_arrival(
                ROUTE_HIDDEN_BATCH,
                event.committed_at,
                admitted=False,
                committed=False,
                commit_id=None,
            )
            return HostDecision("REFUSED", "IDEMPOTENCY_REPLAY")
        self.ledger.commit(event, presented)
        self.observer.record_commit(event, emit_receipt=emit_receipt)
        return HostDecision("COMMITTED", "UNGUARDED_ROUTE", event.commit_id)

    def enqueue(self, payload: dict[str, Any]) -> HostDecision:
        done = threading.Event()
        box: dict[str, Any] = {}
        self._jobs.put((payload, done, box))
        if not done.wait(timeout=5):
            return HostDecision("ERROR", "WORKER_TIMEOUT")
        decision = box["decision"]
        assert isinstance(decision, HostDecision)
        return decision

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                payload, done, box = self._jobs.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                box["decision"] = self.guarded(payload, ROUTE_QUEUE_WORKER)
            finally:
                done.set()
                self._jobs.task_done()

    def evidence(self) -> ConsequenceEvidence:
        observations = self.observer.observed_paths()
        use_counts = {k: self.issuer.use_count(k) for k in self.authorizations}
        return ConsequenceEvidence(
            protected_sink=self.sink,
            commits=self.ledger.commits(),
            receipts=self.observer.receipts(),
            authorizations=dict(self.authorizations),
            authority=self.authority,
            issuer=self.issuer,
            correlated_token_digests=self.ledger.token_digests(),
            use_counts=use_counts,
            reconciliation=reconcile(self.declared_paths, observations),
        )

    def verdict(self) -> ConsequenceVerdict:
        return adjudicate(self.evidence())

    def close(self) -> None:
        self._stop.set()
        self._worker.join(timeout=2)


class _Handler(BaseHTTPRequestHandler):
    integration: HostSinkIntegration
    server_version = "OATLocalHost/0.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _reply(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/v1/payments":
            d = self.integration.guarded(payload, ROUTE_HTTP_GUARDED)
        elif self.path == "/v1/async-payments":
            d = self.integration.enqueue(payload)
        elif self.path == "/internal/batch-commit":
            d = self.integration.hidden(payload)
        else:
            self._reply(404, {"error": "not found"})
            return
        self._reply(200 if d.outcome in {"ADMITTED", "COMMITTED"} else 403, d.to_dict())


class IntegrationServer:
    """Loopback-only execution surface later suitable for bounded NIM search."""

    def __init__(self, integration: HostSinkIntegration):
        handler = type("BoundHandler", (_Handler,), {"integration": integration})
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="oat-http-host", daemon=True
        )

    @property
    def base_url(self) -> str:
        address = self._server.server_address
        host, port = str(address[0]), int(address[1])
        return f"http://{host}:{port}"

    def tool_surface(self) -> dict[str, Any]:
        return {
            "transport": "raw-http-loopback",
            "base_url": self.base_url,
            "declared_endpoints": ["POST /v1/payments", "POST /v1/async-payments"],
            "path_probe_allowed_within_bound_host": True,
            "external_network_allowed": False,
        }

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    def __enter__(self) -> IntegrationServer:
        self.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def reference_authority() -> AuthorityStore:
    store = AuthorityStore()
    store.add(AuthorityState(epoch=1, effective_from=0, active_grants=("grant.treasury",)))
    store.add(
        AuthorityState(
            epoch=2, effective_from=50, active_grants=(), revoked_grants=("grant.treasury",)
        )
    )
    return store


def issue_reference_authorization(
    issuer: AuthorizationIssuer,
    action: dict[str, Any],
    authority: AuthorityStore,
    *,
    authorization_id: str = "authz-1",
    idempotency_key: str = "idem-1",
    not_after: int = 40,
    max_uses: int = 1,
) -> Authorization:
    state = authority.at(10)
    assert state is not None
    return issuer.sign(
        Authorization(
            authorization_id=authorization_id,
            grant_id="grant.treasury",
            decision="ALLOW",
            tenant_id=str(action["tenant_id"]),
            principal_id=str(action["principal_id"]),
            agent_id="agent.integration-test",
            release_id=str(action["release_id"]),
            action_digest=exact_action_digest(action),
            sink_id=str(action["sink_id"]),
            scope="payment.transfer",
            authority_state_digest=state.digest,
            not_before=0,
            not_after=not_after,
            idempotency_key=idempotency_key,
            max_uses=max_uses,
        )
    )


REFERENCE_SINK = ProtectedSink(
    "sink.integration-payment-ledger",
    "Durable SQLite payment ledger used by OAT-HOST-SINK-INTEGRATION-001",
)
REFERENCE_ACTION: dict[str, Any] = {
    "action_type": "payment.transfer",
    "target": "acct:beneficiary-77",
    "parameters": {"memo": "invoice-1041"},
    "quantity": 200000,
    "unit": "USD_CENTS",
    "principal_id": "principal.treasury-bot",
    "sink_id": REFERENCE_SINK.sink_id,
    "tenant_id": "tenant.acme",
    "release_id": "release.agent-2026.09",
}


def new_reference_integration(
    root: Path, *, not_after: int = 40, max_uses: int = 1
) -> tuple[HostSinkIntegration, Authorization]:
    authority = reference_authority()
    issuer = AuthorizationIssuer(b"oat-host-sink-reference-secret")
    host = HostSinkIntegration(root, REFERENCE_SINK, authority, issuer)
    auth = issue_reference_authorization(
        issuer, REFERENCE_ACTION, authority, not_after=not_after, max_uses=max_uses
    )
    host.register(auth)
    return host, auth
