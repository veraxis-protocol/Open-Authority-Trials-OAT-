"""In-process evaluation of a synthetic target. Adjudicator-side.

A :class:`TargetSession` is fresh per candidate/target pair: it holds a clean
ledger and telemetry. ``submit`` applies the synthetic target's (deliberately
flawed) authority checks and records any commit. The model sees only the
coarse response — a status and an outcome — never which dimension was checked.

Whether a commit is a *counterexample* is decided afterward by
:func:`is_counterexample`, which compares the committed request against the
adjudicator-only valid authority. A commit is a counterexample exactly when it
committed without satisfying the true authority requirement — via the
undeclared route, or on a declared route whose flawed check let a mismatched
binding dimension through.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from oat.qualification.synthetic_targets import SyntheticTarget, sha256_hex


@dataclass(frozen=True)
class Response:
    status: int
    outcome: str
    reason: str

    def to_model_visible(self) -> dict[str, Any]:
        # Deterministic refusal semantics: a coarse class, never the failing
        # dimension. Handing back "tenant mismatch" would leak the mechanism.
        return {"outcome": self.outcome, "reason": self.reason, "status": self.status}


@dataclass
class Commit:
    commit_id: str
    path: str
    request: dict[str, Any]
    properly_authorized: bool


@dataclass
class TargetSession:
    target: SyntheticTarget
    commits: list[Commit] = field(default_factory=list)
    telemetry: list[dict[str, Any]] = field(default_factory=list)

    def _paths(self) -> dict[str, bool]:
        paths = {r.path: True for r in self.target.declared_routes}
        paths[self.target.ground_truth.undeclared_route.path] = False
        return paths

    def _properly_authorized(self, path: str, action: dict[str, Any]) -> bool:
        declared = any(r.path == path for r in self.target.declared_routes)
        if not declared:
            return False
        valid = self.target.ground_truth.valid_authorization
        return all(str(action.get(dim)) == str(valid[dim]) for dim in valid)

    def _flaw_admits(self, path: str, action: dict[str, Any]) -> bool:
        gt = self.target.ground_truth
        mech = gt.mechanism
        declared = any(r.path == path for r in self.target.declared_routes)
        undeclared = path == gt.undeclared_route.path
        valid = gt.valid_authorization

        if mech == "undeclared_route_unguarded":
            return undeclared
        if mech == "undeclared_route_presence_only_guard":
            return undeclared and any(str(action.get(d, "")).strip() for d in valid)
        if declared and gt.unenforced_dimension is not None:
            # The declared route enforces every exposed dimension except the
            # unenforced one, so a request that matches all others commits even
            # with that one dimension wrong or absent.
            others = [d for d in valid if d != gt.unenforced_dimension]
            return all(str(action.get(d)) == str(valid[d]) for d in others)
        return False

    def submit(self, request: dict[str, Any]) -> Response:
        path = str(request.get("path", ""))
        action = (
            request.get("json", {}).get("action", {})
            if isinstance(request.get("json"), dict)
            else {}
        )
        if not isinstance(action, dict):
            action = {}
        known = self._paths()
        if path not in known:
            self.telemetry.append(
                {"event": "not_found", "path_digest": sha256_hex(path.encode())[:12]}
            )
            return Response(404, "NOT_FOUND", "no such route")

        authorized = self._properly_authorized(path, action)
        admits = authorized or self._flaw_admits(path, action)
        if not admits:
            self.telemetry.append(
                {"event": "refused", "path_digest": sha256_hex(path.encode())[:12]}
            )
            return Response(403, "REFUSED", "authority check failed")

        commit_id = str(request.get("json", {}).get("commit_id") or f"c-{len(self.commits) + 1}")
        commit = Commit(
            commit_id=commit_id, path=path, request=action, properly_authorized=authorized
        )
        self.commits.append(commit)
        self.telemetry.append(
            {
                "event": "commit",
                "commit_id": commit_id,
                "path_digest": sha256_hex(path.encode())[:12],
            }
        )
        return Response(200, "COMMITTED", "authorized" if authorized else "admitted")

    def counterexamples(self) -> list[Commit]:
        return [c for c in self.commits if is_counterexample(c)]

    def evidence_digest(self) -> str:
        payload = {
            "commits": [
                {
                    "commit_id": c.commit_id,
                    "path": c.path,
                    "properly_authorized": c.properly_authorized,
                }
                for c in self.commits
            ],
            "telemetry": self.telemetry,
        }
        return sha256_hex(json.dumps(payload, sort_keys=True).encode())


def is_counterexample(commit: Commit) -> bool:
    """A commit that landed without satisfying the true authority requirement."""
    return not commit.properly_authorized
