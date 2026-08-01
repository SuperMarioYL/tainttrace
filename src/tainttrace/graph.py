"""The agent tool-call graph and label propagation across it.

A :class:`ToolCall` is one node: a single invocation of a tool the agent can
call, with its inputs, its result, and the taint labels flowing in and out. A
:class:`TaintGraph` is the ordered list of those calls plus the data-dependency
edges between them — call B depends on call A when B consumed A's result (or
some value A produced).

The interesting work is :meth:`TaintGraph.propagate`: walk the calls in
dependency order and, for each call, set ``out_labels`` to the union of every
predecessor's out-labels, the labels already attached to the call's own inputs,
and any source labels minted at this call's boundary. That is the
:func:`tainttrace.label.propagate` rule applied node-by-node across the graph,
and it is milestone m1 — once it holds, a downstream untrusted source's label
reaches every action it transitively influenced.

This module deliberately knows nothing about JSONL traces, quarantine, or the
CLI. It is the pure graph + propagation core that :mod:`tainttrace.tracker`,
:mod:`tainttrace.quarantine`, and :mod:`tainttrace.cli` build on.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Iterable, Iterator

from pydantic import BaseModel, ConfigDict, Field

from .label import (
    EMPTY,
    TaintSet,
    as_taint_set,
    is_tainted,
    propagate,
)


class ToolCall(BaseModel):
    """One node in the agent's tool-call graph.

    A recorded invocation of a tool. ``in_labels`` are the labels known to be on
    the call's inputs at record time (e.g. an explicitly marked untrusted web
    fetch); ``source_labels`` are labels minted *at* this call's boundary (the
    ``taint_source`` case). ``out_labels`` is computed by
    :meth:`TaintGraph.propagate` — it is empty until then.

    ``depends_on`` lists the ids of the calls whose output this call consumed.
    Those are the data-dependency edges the propagation walks; if the recorder
    cannot infer dependencies it may leave this empty and rely on
    :meth:`TaintGraph.infer_value_edges` instead.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(..., min_length=1, description="Unique id of this call within the run.")
    name: str = Field(..., min_length=1, description="Tool name, e.g. 'write_file'.")
    args: dict[str, Any] = Field(default_factory=dict, description="Call arguments.")
    result: Any = Field(default=None, description="Value the tool returned.")

    in_labels: TaintSet = Field(default=EMPTY, description="Labels on the inputs at record time.")
    source_labels: TaintSet = Field(
        default=EMPTY,
        description="Labels minted at this call's boundary (taint_source).",
    )
    out_labels: TaintSet = Field(default=EMPTY, description="Computed propagated labels.")

    depends_on: list[str] = Field(
        default_factory=list,
        description="Ids of calls whose output this call consumed (edges).",
    )
    side_effect: bool = Field(
        default=False,
        description="True if the call mutates external state (write/commit/send).",
    )
    ts: float | None = Field(default=None, description="Optional record timestamp.")

    # Pydantic v2 coerces incoming sets/lists into frozensets via the field type,
    # but JSONL-decoded payloads arrive as plain lists of dicts; normalise here so
    # the graph never sees a non-frozenset label container.
    def model_post_init(self, __context: Any) -> None:  # noqa: D105
        object.__setattr__(self, "in_labels", as_taint_set(self.in_labels))
        object.__setattr__(self, "source_labels", as_taint_set(self.source_labels))
        object.__setattr__(self, "out_labels", as_taint_set(self.out_labels))

    @property
    def is_tainted(self) -> bool:
        """True if this call's *output* carries any untrusted label."""
        return is_tainted(self.out_labels)

    @property
    def is_quarantine_candidate(self) -> bool:
        """A side-effecting call whose output is tainted — i.e. inside the blast radius."""
        return self.side_effect and self.is_tainted

    def local_in(self) -> TaintSet:
        """Labels intrinsic to this call before any predecessor flows in."""
        return propagate(self.in_labels, sources=self.source_labels)


class Edge(BaseModel):
    """A directed data-dependency edge: ``src`` produced a value ``dst`` consumed."""

    model_config = ConfigDict(frozen=True)

    src: str = Field(..., description="Producer call id.")
    dst: str = Field(..., description="Consumer call id.")


class TaintGraph(BaseModel):
    """An ordered list of tool calls plus data-flow edges, with propagation.

    Build one from recorded calls, then call :meth:`propagate` to fill in every
    node's ``out_labels``. Edges may be supplied explicitly (via each call's
    ``depends_on``) or inferred from value reuse (:meth:`infer_value_edges`).
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    calls: list[ToolCall] = Field(default_factory=list)
    extra_edges: list[Edge] = Field(
        default_factory=list,
        description="Edges added on top of each call's own depends_on.",
    )

    # ------------------------------------------------------------------ build

    @classmethod
    def from_calls(cls, calls: Iterable[ToolCall]) -> "TaintGraph":
        """Construct a graph from an iterable of :class:`ToolCall`."""
        return cls(calls=list(calls))

    def add_call(self, call: ToolCall) -> "TaintGraph":
        """Append a call (chainable)."""
        self.calls.append(call)
        return self

    def add_edge(self, src: str, dst: str) -> "TaintGraph":
        """Add a data-dependency edge ``src -> dst`` (chainable)."""
        self.extra_edges.append(Edge(src=src, dst=dst))
        return self

    # --------------------------------------------------------------- indexing

    def _by_id(self) -> dict[str, ToolCall]:
        index: dict[str, ToolCall] = {}
        for call in self.calls:
            if call.id in index:
                raise ValueError(f"Duplicate ToolCall id: {call.id!r}")
            index[call.id] = call
        return index

    def get(self, call_id: str) -> ToolCall:
        """Return the call with ``call_id`` or raise ``KeyError``."""
        for call in self.calls:
            if call.id == call_id:
                return call
        raise KeyError(call_id)

    def edges(self) -> list[Edge]:
        """All edges: each call's ``depends_on`` plus ``extra_edges``, deduped.

        Edges referencing unknown call ids are dropped (a trace may be partial).
        """
        known = {c.id for c in self.calls}
        seen: set[tuple[str, str]] = set()
        out: list[Edge] = []
        for call in self.calls:
            for src in call.depends_on:
                if src in known and (src, call.id) not in seen:
                    seen.add((src, call.id))
                    out.append(Edge(src=src, dst=call.id))
        for edge in self.extra_edges:
            if (
                edge.src in known
                and edge.dst in known
                and (edge.src, edge.dst) not in seen
            ):
                seen.add((edge.src, edge.dst))
                out.append(edge)
        return out

    def _adjacency(self) -> tuple[dict[str, list[str]], dict[str, int]]:
        """Return (successors, in-degree) over the current edge set."""
        succ: dict[str, list[str]] = defaultdict(list)
        indeg: dict[str, int] = {c.id: 0 for c in self.calls}
        for edge in self.edges():
            succ[edge.src].append(edge.dst)
            indeg[edge.dst] += 1
        return succ, indeg

    def predecessors(self, call_id: str) -> list[str]:
        """Ids of calls feeding directly into ``call_id``."""
        return [e.src for e in self.edges() if e.dst == call_id]

    # --------------------------------------------------- edge inference (heur)

    def infer_value_edges(self) -> "TaintGraph":
        """Infer edges from value reuse when ``depends_on`` was not recorded.

        Heuristic for m1: if a later call's args contain a string that appears in
        an earlier call's result (or vice-versa a recorded result is fed in), add
        a dependency edge. This lets a scripted agent that did not thread call ids
        still produce a connected graph for propagation. Explicit ``depends_on``
        always takes precedence and is never overwritten.
        """
        # Map a normalised result string -> producing call id, in record order.
        producers: list[tuple[str, str]] = []
        for call in self.calls:
            text = _stringify(call.result)
            if text:
                producers.append((call.id, text))

        for call in self.calls:
            arg_text = _stringify(call.args)
            if not arg_text:
                continue
            for producer_id, produced in producers:
                if producer_id == call.id:
                    continue
                if produced and produced in arg_text:
                    if producer_id not in call.depends_on:
                        # Only add if this producer comes before the consumer in
                        # record order, to keep the graph acyclic.
                        if self._record_index(producer_id) < self._record_index(call.id):
                            self.add_edge(producer_id, call.id)
        return self

    def _record_index(self, call_id: str) -> int:
        for i, call in enumerate(self.calls):
            if call.id == call_id:
                return i
        return -1

    # ------------------------------------------------------------ topo / order

    def topological_order(self) -> list[ToolCall]:
        """Calls in dependency order (Kahn). Falls back to record order on a cycle.

        If the edge set has a cycle (shouldn't happen for a real append-only
        agent run, but a malformed trace could), the remaining calls are appended
        in their original record order so propagation still terminates.
        """
        succ, indeg = self._adjacency()
        index = self._by_id()
        # Seed the queue in record order so independent calls keep a stable order.
        queue: deque[str] = deque(c.id for c in self.calls if indeg[c.id] == 0)
        ordered: list[ToolCall] = []
        visited: set[str] = set()

        while queue:
            cid = queue.popleft()
            if cid in visited:
                continue
            visited.add(cid)
            ordered.append(index[cid])
            for nxt in succ.get(cid, []):
                indeg[nxt] -= 1
                if indeg[nxt] == 0:
                    queue.append(nxt)

        if len(ordered) < len(self.calls):
            for call in self.calls:
                if call.id not in visited:
                    ordered.append(call)
        return ordered

    # -------------------------------------------------------------- propagate

    def propagate(self) -> "TaintGraph":
        """Fill every node's ``out_labels`` by the union rule, in dep order.

        For each call, in topological order::

            out = union(local_in, *predecessor.out_labels)

        where ``local_in`` is the call's own input + source labels. Because we
        walk in dependency order, each predecessor's ``out_labels`` is already
        final when a consumer reads it — so untrusted labels flow transitively to
        every downstream action. This mutates the calls in place and returns
        ``self`` for chaining. Idempotent: running it twice yields the same
        labels.
        """
        index = self._by_id()
        preds: dict[str, list[str]] = defaultdict(list)
        for edge in self.edges():
            preds[edge.dst].append(edge.src)

        for call in self.topological_order():
            incoming = [index[p].out_labels for p in preds.get(call.id, [])]
            out = propagate(call.local_in(), *incoming)
            object.__setattr__(call, "out_labels", out)
        return self

    # ---------------------------------------------------------- reachability

    def downstream(self, call_id: str) -> list[ToolCall]:
        """All calls transitively reachable from ``call_id`` along data edges.

        The forward blast set of a single call: every action its output could
        have influenced. Does not include ``call_id`` itself.
        """
        succ, _ = self._adjacency()
        index = self._by_id()
        seen: set[str] = set()
        stack = list(succ.get(call_id, []))
        while stack:
            cid = stack.pop()
            if cid in seen:
                continue
            seen.add(cid)
            stack.extend(succ.get(cid, []))
        # Return in record order for stable, readable output.
        return [c for c in self.calls if c.id in seen and c.id in index]

    def tainted_calls(self) -> list[ToolCall]:
        """Calls whose computed output carries an untrusted label (post-propagate)."""
        return [c for c in self.calls if c.is_tainted]

    def clean_calls(self) -> list[ToolCall]:
        """Calls proven clean (no untrusted label) after propagation."""
        return [c for c in self.calls if not c.is_tainted]

    # ------------------------------------------------------------- dunders

    def __iter__(self) -> Iterator[ToolCall]:  # type: ignore[override]
        return iter(self.calls)

    def __len__(self) -> int:
        return len(self.calls)


def _stringify(value: Any) -> str:
    """Best-effort flatten of a value to a string for edge inference.

    Used only by the value-reuse heuristic; never affects label algebra. Falls
    back to ``str(value)`` and tolerates anything.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        return " ".join(_stringify(v) for v in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return " ".join(_stringify(v) for v in value)
    try:
        return str(value)
    except Exception:  # pragma: no cover - defensive
        return ""


__all__ = [
    "ToolCall",
    "Edge",
    "TaintGraph",
]
