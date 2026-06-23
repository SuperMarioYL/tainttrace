"""The :class:`Tracker` facade — the one object you wire into a run.

:mod:`tainttrace.wrap` gives you the low-level ``@tracked`` / ``taint_source``
primitives plus an in-memory recorder; :mod:`tainttrace.graph`,
:mod:`tainttrace.label`, and :mod:`tainttrace.quarantine` give you the algebra.
This module ties them together so the common path is one import and one object:

    tracker = Tracker(path="run.jsonl")
    tracker.activate()
    ...run the agent with @tracked tools...
    report = tracker.blast_radius()

A :class:`Tracker` is a :class:`~tainttrace.wrap.Recorder`: it accumulates the
labeled :class:`~tainttrace.graph.ToolCall` objects ``@tracked`` emits, and — if
given a ``path`` — appends each one as a JSON line so the trace survives the
process (the ``run.jsonl`` of the happy path). After the run it can rebuild the
:class:`~tainttrace.graph.TaintGraph`, run propagation, and hand back a
:class:`~tainttrace.quarantine.QuarantineReport`.

The persistent format is JSONL: one self-describing JSON object per recorded
call, in record order. That keeps the trace append-only, greppable, diffable,
and replayable by :func:`load_graph` long after the agent has exited — which is
the whole post-incident-analysis premise (no DB, per the v0.1 scope).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Iterable

from .graph import TaintGraph, ToolCall
from .label import TaintLabel, TaintSet, as_taint_set
from .quarantine import QuarantineReport, blast_radius, quarantine_from_source
from . import wrap as _wrap


# --------------------------------------------------------------------------- #
# (De)serialisation of a ToolCall <-> a JSONL line.
# --------------------------------------------------------------------------- #


def _labels_to_json(labels: TaintSet) -> list[dict[str, Any]]:
    """Serialise a label set to a stable, sorted list of plain dicts."""
    return [
        {"source_id": lbl.source_id, "origin": lbl.origin, "reason": lbl.reason}
        for lbl in sorted(labels, key=lambda l: (l.source_id, l.origin))
    ]


def _labels_from_json(raw: Any) -> TaintSet:
    """Parse a serialised label list back into a :class:`TaintSet`."""
    if not raw:
        return frozenset()
    out: set[TaintLabel] = set()
    for item in raw:
        out.add(
            TaintLabel(
                source_id=item["source_id"],
                origin=item.get("origin", "untrusted"),
                reason=item.get("reason", ""),
            )
        )
    return frozenset(out)


def call_to_json(call: ToolCall) -> dict[str, Any]:
    """Serialise one :class:`ToolCall` to a JSON-ready dict (one JSONL row)."""
    return {
        "id": call.id,
        "name": call.name,
        "args": call.args,
        "result": call.result,
        "in_labels": _labels_to_json(call.in_labels),
        "source_labels": _labels_to_json(call.source_labels),
        "out_labels": _labels_to_json(call.out_labels),
        "depends_on": list(call.depends_on),
        "side_effect": call.side_effect,
        "ts": call.ts,
    }


def call_from_json(row: dict[str, Any]) -> ToolCall:
    """Rebuild a :class:`ToolCall` from a JSONL row produced by :func:`call_to_json`."""
    return ToolCall(
        id=row["id"],
        name=row["name"],
        args=row.get("args", {}) or {},
        result=row.get("result"),
        in_labels=_labels_from_json(row.get("in_labels")),
        source_labels=_labels_from_json(row.get("source_labels")),
        out_labels=_labels_from_json(row.get("out_labels")),
        depends_on=list(row.get("depends_on", []) or []),
        side_effect=bool(row.get("side_effect", False)),
        ts=row.get("ts"),
    )


# --------------------------------------------------------------------------- #
# The Tracker facade.
# --------------------------------------------------------------------------- #


class Tracker:
    """Top-level recorder + analysis facade.

    Acts as the active :class:`~tainttrace.wrap.Recorder` for ``@tracked`` while a
    run is in progress, optionally streaming each call to a JSONL trace file, and
    afterwards rebuilds the graph and computes the blast radius.

    Parameters
    ----------
    path:
        Where to append the JSONL trace. ``None`` keeps the run purely in memory
        (handy for tests/notebooks); a path makes it survivable for later
        ``tainttrace report --trace <path>``.
    reset:
        Truncate the trace file on construction (default ``True``) so each run
        starts clean instead of appending to a previous run.
    """

    def __init__(self, path: str | Path | None = None, *, reset: bool = True) -> None:
        self.path: Path | None = Path(path) if path is not None else None
        self.calls: list[ToolCall] = []
        self._counter = 0
        self._lock = threading.Lock()
        self._previous: _wrap.Recorder | None = None
        if self.path is not None and reset:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("", encoding="utf-8")

    # ------------------------------------------------------------- Recorder API

    def record(self, call: ToolCall) -> None:
        """Recorder protocol: accumulate a call and (if a path is set) persist it."""
        with self._lock:
            self.calls.append(call)
            if self.path is not None:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(call_to_json(call), ensure_ascii=False) + "\n")

    def next_id(self, name: str) -> str:
        """Mint a unique, readable call id within this run (``write_file-3``)."""
        with self._lock:
            self._counter += 1
            return f"{name}-{self._counter}"

    # ----------------------------------------------------------- activation

    def activate(self) -> "Tracker":
        """Make this the active recorder for ``@tracked`` (chainable).

        Remembers whatever recorder was active so :meth:`deactivate` can restore
        it. Also clears the taint registry and any process-recorder state so a
        previous run does not bleed into this one.
        """
        _wrap.reset_run()
        self._previous = _wrap.use_recorder(self)
        return self

    def deactivate(self) -> None:
        """Restore the previously active recorder (counterpart to :meth:`activate`)."""
        _wrap.use_recorder(self._previous)
        self._previous = None

    def __enter__(self) -> "Tracker":
        return self.activate()

    def __exit__(self, *exc: Any) -> None:
        self.deactivate()

    # --------------------------------------------------------------- analysis

    def graph(self) -> TaintGraph:
        """Rebuild the :class:`TaintGraph` from recorded calls (edges inferred)."""
        g = TaintGraph.from_calls(self.calls)
        g.infer_value_edges()
        g.propagate()
        return g

    def blast_radius(self) -> QuarantineReport:
        """Compute the full blast-radius / quarantine report for this run (m2)."""
        return blast_radius(self.graph())

    def quarantine_from_source(self, source_id: str) -> QuarantineReport:
        """Blast radius scoped to a single named injection source."""
        return quarantine_from_source(self.graph(), source_id)

    # --------------------------------------------------------------- dunders

    def __len__(self) -> int:
        return len(self.calls)

    def __iter__(self):  # type: ignore[override]
        return iter(self.calls)


# --------------------------------------------------------------------------- #
# Loading a persisted trace back for offline analysis (the CLI's `report`).
# --------------------------------------------------------------------------- #


def _iter_rows(path: str | Path) -> Iterable[dict[str, Any]]:
    """Yield each non-blank JSON object from a JSONL trace file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Trace file not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:  # pragma: no cover - defensive
                raise ValueError(f"{p}:{lineno}: invalid JSON line: {exc}") from exc


def load_graph(path: str | Path) -> TaintGraph:
    """Rebuild and propagate a :class:`TaintGraph` from a JSONL trace on disk.

    This is the offline replay path the CLI uses: ``tainttrace report --trace
    run.jsonl`` loads the trace written during the agent run, re-infers any
    missing data edges, and re-runs propagation so the labels are authoritative
    regardless of what was persisted.
    """
    calls = [call_from_json(row) for row in _iter_rows(path)]
    g = TaintGraph.from_calls(calls)
    g.infer_value_edges()
    g.propagate()
    return g


def load_report(path: str | Path) -> QuarantineReport:
    """Load a JSONL trace and return its :class:`QuarantineReport` (one call)."""
    return blast_radius(load_graph(path))


__all__ = [
    "Tracker",
    "call_to_json",
    "call_from_json",
    "load_graph",
    "load_report",
]
