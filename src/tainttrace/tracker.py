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
from .label import TaintLabel, TaintSet
from .quarantine import QuarantineReport, blast_radius, quarantine_from_source
from . import wrap as _wrap


# --------------------------------------------------------------------------- #
# (De)serialisation of a ToolCall <-> a JSONL line.
# --------------------------------------------------------------------------- #


def _labels_to_json(labels: TaintSet) -> list[dict[str, Any]]:
    """Serialise a label set to a stable, sorted list of plain dicts."""
    return [
        {"source_id": lbl.source_id, "origin": lbl.origin, "reason": lbl.reason}
        for lbl in sorted(labels, key=lambda item: (item.source_id, item.origin))
    ]


def _labels_from_json(raw: Any) -> TaintSet:
    """Parse a serialised label list back into a :class:`TaintSet`.

    Each label item's shape is validated *before* it is indexed: a malformed
    nested label array — ``raw`` itself not a list (a string, an int, a dict),
    or an item that is not a dict or is missing ``source_id`` — raises
    ``ValueError`` rather than an uncaught ``TypeError``/``KeyError``. Because
    the CLI's ``except ValueError`` handler renders the clean "Trace malformed"
    error and exits 2, this keeps the v0.3 malformed-trace path intact for
    nested labels too (v0.4 fix: ``fix-trace-nested-label-shape-crash``).
    :func:`_iter_rows` performs the same check during iteration and adds the
    file:line context for the CLI path; this guard is the last line of defence
    for callers that build a row by hand via :func:`call_from_json`.
    """
    if not raw:
        return frozenset()
    if not isinstance(raw, list):
        raise ValueError(
            f"malformed label array: expected a list, got {type(raw).__name__}"
        )
    out: set[TaintLabel] = set()
    for item in raw:
        if not isinstance(item, dict) or "source_id" not in item:
            raise ValueError(
                "malformed label item: expected an object with 'source_id'"
            )
        out.add(
            TaintLabel(
                source_id=item["source_id"],
                origin=item.get("origin", "untrusted"),
                reason=item.get("reason", ""),
            )
        )
    return frozenset(out)


def _label_array_detail(labels: Any, field: str) -> str | None:
    """Return a malformed-label-array detail string for ``field``, else ``None``.

    Mirrors the validation in :func:`_labels_from_json` so a bad nested label
    array is rejected during iteration — with file:line via :func:`_iter_rows` —
    instead of raising an uncaught ``TypeError``/``KeyError`` later in
    :func:`call_from_json` (v0.4 fix: ``fix-trace-nested-label-shape-crash``).
    Returns ``None`` for an absent/empty label field (no labels is not
    malformed).
    """
    if not labels:
        return None
    if not isinstance(labels, list):
        return f"field '{field}' must be a list of label objects"
    for item in labels:
        if not isinstance(item, dict) or "source_id" not in item:
            return (
                f"field '{field}' has a malformed label item "
                "(expected an object with 'source_id')"
            )
    return None


def _depends_on_detail(depends_on: Any) -> str | None:
    """Return a malformed-``depends_on`` detail string, else ``None``.

    Mirrors :func:`_label_array_detail` so a bad ``depends_on`` field is
    rejected during iteration — with file:line via :func:`_iter_rows` —
    instead of raising an uncaught ``TypeError`` later in
    :func:`call_from_json` (v0.6 fix: ``fix-trace-depends-on-scalar-crash``).
    :func:`call_from_json` did ``list(row.get("depends_on", []) or [])``: a
    non-list scalar like the int ``5`` makes ``list(5)`` raise ``TypeError:
    'int' object is not iterable`` (not ``ValueError``), bypassing the CLI's
    "Trace malformed" handler and exiting 1 with empty output, and a non-empty
    *string* ``depends_on`` is silently split to its characters by ``list()``
    so the edge is quietly dropped. Returns ``None`` for an absent/``null``
    field (no dependencies is not malformed).
    """
    if depends_on is None:
        return None
    if not isinstance(depends_on, list):
        return "field 'depends_on' must be a list of strings"
    for item in depends_on:
        if not isinstance(item, str):
            return "field 'depends_on' must contain only strings"
    return None


def _depends_on_from_json(raw: Any) -> list[str]:
    """Parse a serialised ``depends_on`` back into a list of call ids.

    Defensive guard mirroring :func:`_labels_from_json` so a direct caller
    that builds a row by hand via :func:`call_from_json` (bypassing
    :func:`_iter_rows`) is still protected from a non-list scalar raising an
    uncaught ``TypeError`` (v0.6 fix: ``fix-trace-depends-on-scalar-crash``).
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(
            "malformed depends_on: expected a list of strings, "
            f"got {type(raw).__name__}"
        )
    for item in raw:
        if not isinstance(item, str):
            raise ValueError(
                "malformed depends_on: expected a list of strings"
            )
    return list(raw)


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
        "error": call.error,
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
        depends_on=_depends_on_from_json(row.get("depends_on")),
        side_effect=bool(row.get("side_effect", False)),
        ts=row.get("ts"),
        error=row.get("error"),
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

        Note: :func:`tainttrace.wrap.use_recorder` returns the recorder you just
        set (not the previously-active one), so the prior recorder must be
        captured *before* swapping — otherwise ``deactivate`` would restore the
        tracker itself (v0.2 fix: ``fix-tracker-deactivate-restore``).
        """
        _wrap.reset_run()
        self._previous = _wrap.get_recorder()
        _wrap.use_recorder(self)
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


def _iter_rows(path: str | Path, *, strict: bool = False) -> Iterable[dict[str, Any]]:
    """Yield each non-blank JSON object from a JSONL trace file.

    A malformed line — invalid JSON, or valid JSON of the wrong shape (a list,
    a bare number, or a dict missing the required ``id``/``name`` keys) — raises
    ``ValueError`` naming the file + line number so the CLI can render a clean
    error instead of a bare traceback (v0.2: ``fix-cli-malformed-json-trace``
    for invalid JSON; v0.3: ``fix-cli-non-json-shape-trace-row`` for wrong-shape
    rows that previously raised an uncaught ``TypeError``/``KeyError``). When
    ``strict`` is set, the offending line's raw content is appended to the
    message for debugging.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Trace file not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                if strict:
                    raise ValueError(
                        f"{p}:{lineno}: invalid JSON line: {exc}\n  raw: {line!r}"
                    ) from exc
                raise ValueError(f"{p}:{lineno}: invalid JSON line: {exc}") from exc
            # A valid-JSON-but-wrong-shape row (list, number, or dict missing
            # id/name) would otherwise raise an uncaught TypeError/KeyError
            # deep in call_from_json. Validate here so the CLI's ValueError
            # handler renders the clean "Trace malformed" error (v0.3 fix).
            if not isinstance(row, dict) or "id" not in row or "name" not in row:
                detail = "expected a JSON object with 'id' and 'name'"
                if strict:
                    raise ValueError(
                        f"{p}:{lineno}: malformed trace row ({detail})\n  raw: {line!r}"
                    )
                raise ValueError(f"{p}:{lineno}: malformed trace row ({detail})")
            # A row that passes the shape check above can still carry a
            # malformed *nested* label array (in_labels/source_labels/
            # out_labels as a string/int/dict, or a list of non-dicts / dicts
            # missing source_id). That would raise an uncaught
            # TypeError/KeyError in call_from_json -> _labels_from_json (a
            # gap in the v0.3 fix, which validated only the top-level row).
            # Validate the nested label arrays here too so the same clean
            # file:line "Trace malformed" + exit 2 path fires (v0.4 fix:
            # fix-trace-nested-label-shape-crash).
            for _field in ("in_labels", "source_labels", "out_labels"):
                _detail = _label_array_detail(row.get(_field), _field)
                if _detail is not None:
                    if strict:
                        raise ValueError(
                            f"{p}:{lineno}: malformed trace row ({_detail})\n"
                            f"  raw: {line!r}"
                        )
                    raise ValueError(
                        f"{p}:{lineno}: malformed trace row ({_detail})"
                    )
            # A row that passes the label checks can still carry a non-list
            # ``depends_on`` (e.g. the int ``5`` or a bare string). That would
            # raise an uncaught ``TypeError`` (not ``ValueError``) deep in
            # call_from_json via ``list(depends_on)`` — bypassing the CLI's
            # "Trace malformed" handler and exiting 1 with empty output; a
            # string ``depends_on`` is silently split to chars by ``list()``
            # so the edge is dropped. Validate it here too so the same clean
            # file:line "Trace malformed" + exit 2 path fires (v0.6 fix:
            # fix-trace-depends-on-scalar-crash).
            _detail = _depends_on_detail(row.get("depends_on"))
            if _detail is not None:
                if strict:
                    raise ValueError(
                        f"{p}:{lineno}: malformed trace row ({_detail})\n"
                        f"  raw: {line!r}"
                    )
                raise ValueError(
                    f"{p}:{lineno}: malformed trace row ({_detail})"
                )
            yield row


def load_graph(path: str | Path, *, strict: bool = False) -> TaintGraph:
    """Rebuild and propagate a :class:`TaintGraph` from a JSONL trace on disk.

    This is the offline replay path the CLI uses: ``tainttrace report --trace
    run.jsonl`` loads the trace written during the agent run, re-infers any
    missing data edges, and re-runs propagation so the labels are authoritative
    regardless of what was persisted. ``strict`` forwards to :func:`_iter_rows`
    to surface the raw offending line on a malformed trace.
    """
    calls = [call_from_json(row) for row in _iter_rows(path, strict=strict)]
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
