"""A machine-readable chain from agent to disposition.

The graph exists so that a missing link is *detectable* rather than invisible.
Its audit does not decide dispositions -- the verifier does that -- but it
makes the shape of the evidence inspectable and proves which material edges
were actually present.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from oat.digest import digest_object

#: Material edges a complete consequence chain is expected to contain. A run
#: missing any of these cannot support a confident negative.
REQUIRED_EDGES: tuple[tuple[str, str], ...] = (
    ("agent", "principal"),
    ("principal", "route"),
    ("route", "attempted_action"),
    ("attempted_action", "authorization_decision"),
    ("authorization_decision", "authorization_artifact"),
    ("authorization_artifact", "authority_state_at_issue"),
    ("authority_state_at_issue", "authority_state_at_commit"),
    ("authority_state_at_commit", "sink_decision"),
    ("sink_decision", "committed_consequence"),
    ("committed_consequence", "independent_receipt"),
    ("independent_receipt", "verifier_trace"),
    ("verifier_trace", "disposition"),
)


@dataclass
class EvidenceGraph:
    """Typed nodes and edges for one commit chain."""

    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[tuple[str, str]] = field(default_factory=list)

    def add_node(self, kind: str, payload: dict[str, Any]) -> None:
        self.nodes[kind] = payload

    def add_edge(self, source: str, target: str) -> None:
        if (source, target) not in self.edges:
            self.edges.append((source, target))

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": {k: self.nodes[k] for k in sorted(self.nodes)},
            "edges": [list(e) for e in sorted(self.edges)],
        }

    @property
    def digest(self) -> str:
        return digest_object(self.to_dict())


@dataclass(frozen=True)
class GraphAudit:
    """Which material edges are present, and which are not."""

    present_edges: tuple[tuple[str, str], ...]
    missing_edges: tuple[tuple[str, str], ...]

    @property
    def complete(self) -> bool:
        return not self.missing_edges

    def to_dict(self) -> dict[str, Any]:
        return {
            "present_edges": [list(e) for e in self.present_edges],
            "missing_edges": [list(e) for e in self.missing_edges],
            "complete": self.complete,
        }


def audit(graph: EvidenceGraph) -> GraphAudit:
    """Report the material edges present and missing in ``graph``."""
    have = set(graph.edges)
    present = tuple(e for e in REQUIRED_EDGES if e in have)
    missing = tuple(e for e in REQUIRED_EDGES if e not in have)
    return GraphAudit(present, missing)


def build_graph(
    *,
    agent_id: str,
    principal_id: str,
    route_id: str,
    action_digest: str,
    authorization: dict[str, Any] | None,
    authority_at_issue: dict[str, Any] | None,
    authority_at_commit: dict[str, Any] | None,
    sink_decision: dict[str, Any] | None,
    commit: dict[str, Any] | None,
    receipt: dict[str, Any] | None,
    verifier_trace: dict[str, Any] | None,
    disposition: str | None,
) -> EvidenceGraph:
    """Assemble a graph, adding only the edges whose endpoints actually exist.

    A ``None`` payload means that evidence was not collected. The edge is then
    simply absent, which is exactly what :func:`audit` reports.
    """
    graph = EvidenceGraph()
    graph.add_node("agent", {"agent_id": agent_id})
    graph.add_node("principal", {"principal_id": principal_id})
    graph.add_node("route", {"route_id": route_id})
    graph.add_node("attempted_action", {"action_digest": action_digest})
    graph.add_edge("agent", "principal")
    graph.add_edge("principal", "route")
    graph.add_edge("route", "attempted_action")

    optional: list[tuple[str, dict[str, Any] | None]] = [
        (
            "authorization_decision",
            {"decision": authorization.get("decision")} if authorization else None,
        ),
        ("authorization_artifact", authorization),
        ("authority_state_at_issue", authority_at_issue),
        ("authority_state_at_commit", authority_at_commit),
        ("sink_decision", sink_decision),
        ("committed_consequence", commit),
        ("independent_receipt", receipt),
        ("verifier_trace", verifier_trace),
        ("disposition", {"disposition": disposition} if disposition else None),
    ]
    for kind, payload in optional:
        if payload is not None:
            graph.add_node(kind, payload)

    for source, target in REQUIRED_EDGES:
        if source in graph.nodes and target in graph.nodes:
            graph.add_edge(source, target)
    return graph
