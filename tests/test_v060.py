"""v0.6.0 milestones — 2 bug-hunt fixes + 1 audit-trail feature over v0.5.0.

Covers:
  - fix-result-container-member-taint-lost (MEDIUM): when a ``@tracked`` tool
    returns a container, mark each member recursively (with a cycle guard) so a
    downstream tool that receives an *extracted member* (the common "tool
    returns a list, agent indexes out one element" pattern) still records the
    upstream taint in its in_labels. Before the fix the top-level container was
    the only thing registered, so a poisoned member passed to a side-effecting
    write recorded in_labels=empty and was dropped from quarantine (a soundness
    false-negative symmetric to the v0.4 input-side container-args fix).
  - fix-trace-depends-on-scalar-crash (MEDIUM): validate that a trace row's
    ``depends_on`` is a list of strings so a non-list scalar (e.g. the int ``5``)
    renders the clean "Trace malformed" + exit 2 error instead of an uncaught
    ``TypeError`` (``list(5)``) with empty output and exit 1; a string
    ``depends_on`` is no longer silently split to its characters by ``list()``.
  - m6_record_failed_tool_calls (feature): a ``@tracked`` tool that raises is
    now recorded with ``result=None`` plus an optional ``error`` field
    (type+message) before the exception is re-raised, so a side-effecting tool
    that failed mid-execution no longer vanishes from run.jsonl / the
    blast-radius report.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from tainttrace import (
    MemoryRecorder,
    blast_radius,
    reset_run,
    taint_source,
    tracked,
    use_recorder,
)
from tainttrace.cli import app
from tainttrace.tracker import (
    _depends_on_detail,
    _depends_on_from_json,
    call_from_json,
    call_to_json,
)
from tainttrace.wrap import _mark_value

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolate_run():
    reset_run()
    yield
    reset_run()


# A well-formed trace row used as the "good" baseline in the malformed-trace
# tests (it must parse cleanly through _iter_rows).
_GOOD_ROW = (
    '{"id":"a","name":"fetch","args":{},"result":"ok","in_labels":[],'
    '"source_labels":[],"out_labels":[],"depends_on":[],'
    '"side_effect":false,"ts":null,"error":null}'
)


# --------------------------------------------------------------------------- #
# fix-result-container-member-taint-lost
# --------------------------------------------------------------------------- #


def test_tainted_member_extracted_from_list_result_is_marked_and_quarantined():
    """A poisoned member indexed out of a @tracked list result must carry its
    taint into a downstream side-effecting write and quarantine it.

    Before the fix, @tracked marked only the top-level list result (by id),
    never its members, so ``write_file("out", container[0])`` recorded
    in_labels=empty and the poisoned write was classified proven-clean and
    dropped from quarantine (a soundness false-negative).
    """
    rec = use_recorder(MemoryRecorder())

    @tracked
    def split_words(text):
        return [text.upper(), text.lower()]

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    poisoned = taint_source("evil", source_id="web:member", reason="poisoned")
    container = split_words(poisoned)
    # The common "tool returns a list, agent indexes out one element" pattern.
    member = container[0]
    write_file("out.txt", member)

    write_call = next(c for c in rec.calls if c.name == "write_file")
    reached = {lbl.source_id for lbl in write_call.in_labels}
    assert "web:member" in reached, (
        f"extracted member missing from in_labels: {reached}"
    )

    report = blast_radius(rec.graph())
    quarantined = {a.name for a in report.quarantine}
    assert "write_file" in quarantined, (
        f"side-effecting write of an extracted member should be quarantined: "
        f"{quarantined}"
    )
    use_recorder(None)


def test_tainted_member_extracted_from_dict_result_is_marked():
    """The dict-result case: a member extracted from a dict value carries the
    upstream taint into the next @tracked tool."""
    rec = use_recorder(MemoryRecorder())

    @tracked
    def build_map(text):
        return {"upper": text.upper(), "lower": text.lower()}

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    poisoned = taint_source("exfil", source_id="web:dict-out", reason="poisoned")
    result_map = build_map(poisoned)
    write_file("o.txt", result_map["upper"])

    write_call = next(c for c in rec.calls if c.name == "write_file")
    assert "web:dict-out" in {lbl.source_id for lbl in write_call.in_labels}

    report = blast_radius(rec.graph())
    assert "write_file" in {a.name for a in report.quarantine}
    use_recorder(None)


def test_mark_value_terminates_on_cyclic_container():
    """The recursive mark walks a self-referential container without
    recursing without bound, and still marks a tainted member alongside the
    cycle (mirrors the _labels_in_value cycle guard)."""
    from tainttrace.label import taint

    labels = taint("web:cyc", reason="poisoned")
    poisoned = "cycle poison"
    container: list = []
    container.append(container)  # self-reference -> a cycle
    container.append(poisoned)  # plus the tainted member
    # Must not raise RecursionError.
    _mark_value(container, labels)
    use_recorder(None)


def test_clean_container_result_members_not_falsely_tainted():
    """A container result with no tainted members must not taint a downstream
    write (no false positive introduced by the recursive mark)."""
    rec = use_recorder(MemoryRecorder())

    @tracked
    def make_pair():
        return ["clean-a", "clean-b"]

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    pair = make_pair()
    write_file("clean.txt", pair[0])

    write_call = next(c for c in rec.calls if c.name == "write_file")
    assert write_call.in_labels == frozenset(), (
        f"clean extracted member should have empty in_labels: {write_call.in_labels}"
    )
    report = blast_radius(rec.graph())
    assert "write_file" not in {a.name for a in report.quarantine}
    use_recorder(None)


def test_async_container_result_member_taint_preserved():
    """The output-side member marking applies to the async wrapper too: a
    member extracted from an async @tracked tool's list result carries taint
    into the next await'd @tracked write."""
    import asyncio

    rec = use_recorder(MemoryRecorder())

    @tracked
    async def split_words(text):
        return [text.upper(), text.lower()]

    @tracked(side_effect=True)
    async def write_file(path, body):
        return f"wrote {path}"

    async def run():
        poisoned = taint_source("evil", source_id="web:async-out", reason="p")
        container = await split_words(poisoned)
        await write_file("out.md", container[0])

    asyncio.run(run())

    write_call = next(c for c in rec.calls if c.name == "write_file")
    assert "web:async-out" in {lbl.source_id for lbl in write_call.in_labels}

    report = blast_radius(rec.graph())
    assert "write_file" in {a.name for a in report.quarantine}
    use_recorder(None)


# --------------------------------------------------------------------------- #
# fix-trace-depends-on-scalar-crash
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw",
    [
        5,              # int -> list(5) raises TypeError (the crash case)
        3.14,           # float scalar
        True,           # bool scalar -> list(True) raises TypeError
        "foo",          # string -> silently split to ['f','o','o'] by list()
        {"k": "v"},     # dict, not a list
        [1, 2],         # list of non-strings (int elements)
        ["ok", 5],      # one good then one bad element
    ],
)
def test_depends_on_detail_flags_non_list_or_non_string_elements(raw):
    """A non-list or non-string-element depends_on is flagged as malformed
    (returns a detail string), so _iter_rows raises a ValueError (not an
    uncaught TypeError) that the CLI renders as 'Trace malformed' + exit 2."""
    assert _depends_on_detail(raw) is not None


@pytest.mark.parametrize("raw", [None, [], ["a"], ["a", "b-c"]])
def test_depends_on_detail_accepts_absent_empty_or_string_lists(raw):
    """Absent/null/empty and lists of strings are NOT malformed."""
    assert _depends_on_detail(raw) is None


@pytest.mark.parametrize(
    "raw", [5, 3.14, True, "foo", {"k": "v"}, [1, 2], ["ok", 5]]
)
def test_depends_on_from_json_raises_valueerror_not_typeerror(raw):
    """The defensive guard in call_from_json raises ValueError (which the CLI's
    'Trace malformed' handler catches) — NOT an uncaught TypeError — so direct
    callers that bypass _iter_rows are also protected."""
    with pytest.raises(ValueError):
        _depends_on_from_json(raw)


def test_depends_on_from_json_accepts_well_formed():
    """Sanity: well-formed and absent inputs parse cleanly."""
    assert _depends_on_from_json(None) == []
    assert _depends_on_from_json([]) == []
    assert _depends_on_from_json(["a", "b"]) == ["a", "b"]


def test_report_non_list_depends_on_int_exits_2_clean(tmp_path):
    """A trace row whose depends_on is a non-list scalar (the int 5) must
    render the clean 'Trace malformed' error (with file:line) and exit 2,
    not exit 1 with an uncaught TypeError traceback.

    Before the fix, list(5) raised TypeError, bypassing the CLI's ValueError
    handler.
    """
    trace = tmp_path / "bad_depends_int.jsonl"
    bad_row = (
        '{"id":"b","name":"write_file","args":{},"result":"ok","in_labels":[],'
        '"source_labels":[],"out_labels":[],"depends_on":5,'
        '"side_effect":true,"ts":null,"error":null}'
    )
    trace.write_text(f"{_GOOD_ROW}\n{bad_row}\n", encoding="utf-8")
    result = runner.invoke(app, ["report", "--trace", str(trace)])
    assert result.exit_code == 2
    out = result.output.lower()
    assert "traceback" not in out
    assert "malformed" in out
    assert "depends_on" in result.output
    assert "bad_depends_int.jsonl" in result.output
    assert ":2" in result.output or "line 2" in out


def test_report_string_depends_on_exits_2_clean(tmp_path):
    """A string depends_on is no longer silently split to its characters by
    list(); it now renders the clean 'Trace malformed' + exit 2 error."""
    trace = tmp_path / "string_depends.jsonl"
    bad_row = (
        '{"id":"b","name":"write_file","args":{},"result":"ok","in_labels":[],'
        '"source_labels":[],"out_labels":[],"depends_on":"foo",'
        '"side_effect":true,"ts":null,"error":null}'
    )
    trace.write_text(f"{_GOOD_ROW}\n{bad_row}\n", encoding="utf-8")
    result = runner.invoke(app, ["report", "--trace", str(trace)])
    assert result.exit_code == 2
    assert "traceback" not in result.output.lower()
    assert "malformed" in result.output.lower()
    assert "depends_on" in result.output


def test_report_strict_depends_on_surfaces_raw_line(tmp_path):
    """--strict surfaces the raw offending line for a malformed depends_on."""
    trace = tmp_path / "strict_depends.jsonl"
    bad_row = (
        '{"id":"b","name":"write_file","args":{},"result":"ok","in_labels":[],'
        '"source_labels":[],"out_labels":[],"depends_on":5,'
        '"side_effect":true,"ts":null,"error":null}'
    )
    trace.write_text(f"{_GOOD_ROW}\n{bad_row}\n", encoding="utf-8")
    result = runner.invoke(app, ["report", "--trace", str(trace), "--strict"])
    assert result.exit_code == 2
    assert "depends_on" in result.output
    # The raw offending line is appended under --strict.
    assert "5" in result.output


# --------------------------------------------------------------------------- #
# m6_record_failed_tool_calls
# --------------------------------------------------------------------------- #


def test_tracked_tool_that_raises_is_recorded_with_error_and_reraised():
    """A @tracked tool that raises is still recorded (with result=None and an
    error field) and then re-raises so the agent loop sees the original
    failure.

    Before the fix the wrapper did result=func(*args) BEFORE recorder.record,
    so a raising tool was never recorded (rec.calls stayed empty) and the
    side-effecting failure vanished from the trace.
    """
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def risky_write(path, body):
        raise RuntimeError("disk full")

    with pytest.raises(RuntimeError, match="disk full"):
        risky_write("out.txt", "payload")

    # The raising call was still recorded (audit-trail completeness).
    assert len(rec.calls) == 1
    call = rec.calls[0]
    assert call.result is None
    assert call.error is not None
    assert call.error["type"] == "RuntimeError"
    assert "disk full" in call.error["message"]
    assert call.name == "risky_write"
    assert call.side_effect is True
    use_recorder(None)


def test_failed_side_effecting_tool_with_tainted_input_is_quarantined():
    """A side-effecting tool that raises on a tainted input must appear in the
    blast-radius quarantine set (it may have partially mutated external state
    before raising). Before the fix it was not recorded at all, so it was
    invisible in the report."""
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def risky_write(path, body):
        raise OSError("disk full")

    poisoned = taint_source("evil", source_id="web:fail", reason="poisoned")
    with pytest.raises(OSError):
        risky_write("out.txt", poisoned)

    call = rec.calls[0]
    assert call.error is not None
    assert call.error["type"] == "OSError"
    assert "web:fail" in {lbl.source_id for lbl in call.in_labels}

    report = blast_radius(rec.graph())
    quarantined = {a.name for a in report.quarantine}
    assert "risky_write" in quarantined, (
        f"failed side-effecting tool on a tainted input should be quarantined: "
        f"{quarantined}"
    )
    use_recorder(None)


def test_successful_call_has_no_error_field():
    """The success path must not set the error field (regression: the new
    try/except must not change the recorded shape of a normal call)."""
    rec = use_recorder(MemoryRecorder())

    @tracked
    def echo(text):
        return text

    out = echo("ok")
    assert out == "ok"
    assert len(rec.calls) == 1
    call = rec.calls[0]
    assert call.error is None
    assert call.result == "ok"
    use_recorder(None)


def test_failed_call_error_field_round_trips_through_jsonl():
    """The error field survives call_to_json -> call_from_json so a failed call
    recorded to run.jsonl reloads with its audit-trail intact."""
    from tainttrace.graph import ToolCall
    from tainttrace.label import taint

    call = ToolCall(
        id="boom-1",
        name="risky_write",
        args={"arg0": "out.txt"},
        result=None,
        in_labels=taint("web:x", reason="poisoned"),
        out_labels=taint("web:x"),
        depends_on=[],
        side_effect=True,
        ts=None,
        error={"type": "RuntimeError", "message": "disk full"},
    )
    row = call_to_json(call)
    assert row["error"] == {"type": "RuntimeError", "message": "disk full"}
    assert row["result"] is None
    # The row is plain JSON-serialisable (what run.jsonl persists).
    encoded = json.dumps(row, ensure_ascii=False)
    assert "RuntimeError" in encoded

    restored = call_from_json(json.loads(encoded))
    assert restored.error == {"type": "RuntimeError", "message": "disk full"}
    assert restored.result is None
    assert restored.id == "boom-1"


def test_failed_tracked_call_persists_to_jsonl_and_reloads(tmp_path):
    """A raising @tracked tool is persisted to run.jsonl with its error field
    and reloads into the graph (the offline post-incident-analysis path)."""
    import asyncio

    from tainttrace import Tracker

    trace = tmp_path / "failed_run.jsonl"
    tracker = Tracker(path=trace).activate()

    @tracked(side_effect=True)
    def risky_write(path, body):
        raise RuntimeError("boom")

    async def run():
        await risky_write("out.md", "payload")

    try:
        with pytest.raises(RuntimeError):
            asyncio.run(run())
    finally:
        tracker.deactivate()

    # The failed call was persisted to run.jsonl.
    lines = [ln for ln in trace.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["result"] is None
    assert row["error"]["type"] == "RuntimeError"
    assert "boom" in row["error"]["message"]

    # And it reloads cleanly via load_graph (the CLI's report path).
    from tainttrace.tracker import load_graph

    graph = load_graph(trace)
    assert len(graph.calls) == 1
    assert graph.calls[0].error is not None
    assert graph.calls[0].error["type"] == "RuntimeError"


def test_async_tracked_tool_that_raises_is_recorded():
    """The async wrapper records a raising tool too (not just the sync one)."""
    import asyncio

    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    async def risky_write(path, body):
        raise RuntimeError("async boom")

    async def run():
        await risky_write("a.md", "payload")

    with pytest.raises(RuntimeError, match="async boom"):
        asyncio.run(run())

    assert len(rec.calls) == 1
    call = rec.calls[0]
    assert call.result is None
    assert call.error is not None
    assert call.error["type"] == "RuntimeError"
    assert "async boom" in call.error["message"]
    use_recorder(None)
