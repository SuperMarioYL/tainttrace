"""TaintTrace — dynamic taint tracking for an agent's tool-call graph.

When a prompt injection lands inside an autonomous agent, the failure verb is
*propagation*: one poisoned token silently influences a chain of downstream tool
calls, file writes, and memory updates. TaintTrace imports **dynamic taint
tracking** from security dataflow analysis into the agent runtime — every
untrusted value (a fetched web page, an external tool result) carries a taint
label that propagates through the tool graph, so after an incident you can
mechanically enumerate the *blast radius*: exactly which actions the injection
touched, and which are proven clean.

Quickstart
----------
Decorate the tools your agent can call, mark untrusted inputs, run as usual,
then compute the blast radius from the recorded trace::

    from tainttrace import Tracker, tracked, taint_source, blast_radius

    tracker = Tracker(path="run.jsonl")
    tracker.activate()

    @tracked(side_effect=True)
    def write_file(path, body): ...

    page = taint_source(fetch(url), source_id="web:blog", reason="fetched page")
    write_file("notes.md", summarize(page))

    report = tracker.blast_radius()
    print(report.headline())   # e.g. "4 of 11 actions tainted, 7 proven clean"

The public surface is intentionally small: a :class:`Tracker` facade plus the
``@tracked`` / ``taint_source`` primitives. Everything else (label algebra,
graph propagation, quarantine) is available for advanced use but rarely needed.
"""

from __future__ import annotations

from .graph import Edge, TaintGraph, ToolCall
from .label import (
    EMPTY,
    Origin,
    TaintLabel,
    TaintSet,
    TaintTag,
    is_tainted,
    make_label,
    propagate,
    source_ids,
    taint,
    union,
    untrusted_labels,
)
from .quarantine import (
    QuarantineReport,
    TaintedAction,
    blast_radius,
    quarantine_from_source,
)
from .tracker import Tracker, load_graph, load_report
from .wrap import (
    MemoryRecorder,
    Recorder,
    get_recorder,
    labels_of,
    mark_trusted,
    reset_run,
    taint_source,
    tracked,
    use_recorder,
)

__version__ = "0.2.0"

__all__ = [
    "__version__",
    # label algebra
    "TaintLabel",
    "TaintTag",
    "TaintSet",
    "Origin",
    "EMPTY",
    "make_label",
    "taint",
    "propagate",
    "union",
    "is_tainted",
    "untrusted_labels",
    "source_ids",
    # graph
    "ToolCall",
    "Edge",
    "TaintGraph",
    # quarantine / blast radius
    "TaintedAction",
    "QuarantineReport",
    "blast_radius",
    "quarantine_from_source",
    # wrapper primitives
    "tracked",
    "taint_source",
    "mark_trusted",
    "labels_of",
    "Recorder",
    "MemoryRecorder",
    "get_recorder",
    "use_recorder",
    "reset_run",
    # top-level facade
    "Tracker",
    "load_graph",
    "load_report",
]
