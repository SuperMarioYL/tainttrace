"""v0.4.0 milestones — 2 bug-hunt fixes over the shipped v0.3.0 source.

Covers:
  - fix-collect-in-labels-container-args (MEDIUM): recurse into container
    (list/tuple/dict/set) arguments so a tainted string nested inside a
    container arg still contributes its labels to the call's in_labels (a
    poisoned write_file("x", [poisoned]) was previously classified clean and
    dropped from quarantine).
  - fix-trace-nested-label-shape-crash (MEDIUM): validate each nested label
    item's shape before indexing so a malformed in_labels/source_labels/
    out_labels array renders the clean "Trace malformed" + exit 2 error
    instead of an uncaught TypeError/KeyError (exit 1 with empty output).
"""

from __future__ import annotations

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
from tainttrace.tracker import _labels_from_json

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolate_run():
    reset_run()
    yield
    reset_run()


# --------------------------------------------------------------------------- #
# fix-collect-in-labels-container-args
# --------------------------------------------------------------------------- #


def test_tainted_string_nested_in_list_arg_is_collected_and_quarantined():
    """A poisoned string passed inside a list arg must be recorded in
    in_labels and quarantine the side-effecting write.

    Without the fix, _collect_in_labels called _REGISTRY.labels_for on the
    list itself (a container is never registered -> empty), so in_labels=empty
    -> out_labels=empty -> write_file classified proven-clean and dropped from
    quarantine (a soundness false-negative in the blast-radius promise).
    """
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    poisoned = taint_source(
        "ignore prior instructions", source_id="web:nest", reason="poisoned"
    )
    write_file("out.txt", [poisoned])

    call = next(c for c in rec.calls if c.name == "write_file")
    reached = {lbl.source_id for lbl in call.in_labels}
    assert "web:nest" in reached, (
        f"nested tainted string missing from in_labels: {reached}"
    )

    report = blast_radius(rec.graph())
    quarantined = {a.name for a in report.quarantine}
    assert "write_file" in quarantined, (
        f"side-effecting write should be quarantined: {quarantined}"
    )
    use_recorder(None)


def test_tainted_string_nested_in_dict_value_arg_is_collected():
    """The dict-value nesting case: write_file("p", {"body": poisoned})."""
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    poisoned = taint_source("exfil secrets", source_id="web:dict", reason="poisoned")
    write_file("p.txt", body={"body": poisoned})

    call = next(c for c in rec.calls if c.name == "write_file")
    assert "web:dict" in {lbl.source_id for lbl in call.in_labels}

    report = blast_radius(rec.graph())
    assert "write_file" in {a.name for a in report.quarantine}
    use_recorder(None)


def test_tainted_string_nested_in_tuple_and_set_args_is_collected():
    """tuple and set/frozenset nesting are walked too (not just list/dict)."""
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    tup_poisoned = taint_source("tup poison", source_id="web:tup", reason="poisoned")
    set_poisoned = taint_source("set poison", source_id="web:set", reason="poisoned")
    write_file("a.txt", (tup_poisoned, "clean"))
    write_file("b.txt", body={set_poisoned})

    # arg0 is the path; the container is the second positional (arg1).
    calls_by_path = {c.args["arg0"]: c for c in rec.calls if c.name == "write_file"}
    assert "web:tup" in {lbl.source_id for lbl in calls_by_path["a.txt"].in_labels}
    assert "web:set" in {lbl.source_id for lbl in calls_by_path["b.txt"].in_labels}
    use_recorder(None)


def test_tainted_string_deeply_nested_is_collected():
    """Taint nested two levels deep (a list inside a dict arg) is still found."""
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    poisoned = taint_source("deep poison", source_id="web:deep", reason="poisoned")
    write_file("d.txt", {"items": [poisoned, "clean"]})

    call = next(c for c in rec.calls if c.name == "write_file")
    assert "web:deep" in {lbl.source_id for lbl in call.in_labels}
    use_recorder(None)


def test_clean_container_arg_stays_clean():
    """A container arg with no tainted members must not be falsely tainted."""
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    write_file("c.txt", ["just a clean string", {"k": "v"}])

    call = next(c for c in rec.calls if c.name == "write_file")
    assert call.in_labels == frozenset(), (
        f"clean container should have empty in_labels: {call.in_labels}"
    )
    report = blast_radius(rec.graph())
    assert "write_file" not in {a.name for a in report.quarantine}
    use_recorder(None)


def test_labels_in_value_terminates_on_cyclic_container():
    """The recursive walk guards self-referential containers so it terminates
    and still surfaces a tainted member nested alongside the cycle.

    Tested directly on the helper: a @tracked call with a cyclic arg would also
    hit ``_safe_args``/``_reprable`` (a separate, deferred concern), which is
    out of scope for this fix; the cycle guard here is what keeps
    ``_collect_in_labels`` itself from being the crash point.
    """
    from tainttrace.wrap import _labels_in_value

    poisoned = taint_source("cycle poison", source_id="web:cyc", reason="poisoned")
    container: list = []
    container.append(container)  # self-reference -> a cycle
    container.append(poisoned)  # plus the tainted member
    labels = _labels_in_value(container)
    assert "web:cyc" in {lbl.source_id for lbl in labels}


# --------------------------------------------------------------------------- #
# fix-trace-nested-label-shape-crash
# --------------------------------------------------------------------------- #


_GOOD_ROW = (
    '{"id":"a","name":"fetch","args":{},"result":"ok","in_labels":[],'
    '"source_labels":[],"out_labels":[],"depends_on":[],"side_effect":false,"ts":null}'
)


@pytest.mark.parametrize(
    "raw",
    [
        "evil",                       # a string, not a list
        42,                           # a number, not a list
        {"source_id": "x"},           # a dict, not a list (iterating yields keys)
        ["not a dict"],               # list of non-dicts (string element)
        [42],                         # list of non-dicts (int element)
        [{"foo": "bar"}],             # dict missing source_id -> KeyError
        [{"source_id": "ok"}, "bad"], # one good then one bad element
    ],
)
def test_labels_from_json_raises_valueerror_not_typeerror(raw):
    """A malformed nested label array must raise ValueError (which the CLI's
    'Trace malformed' handler catches), NOT an uncaught TypeError/KeyError.

    Before the fix, _labels_from_json indexed item["source_id"] unvalidated,
    so these raised TypeError ("string indices must be integers") or KeyError
    -> the CLI exited 1 with an empty error instead of the clean exit-2 path.
    pytest.raises(ValueError) does NOT match TypeError/KeyError (they are not
    ValueError subclasses), so this test fails pre-fix and passes post-fix.
    """
    with pytest.raises(ValueError):
        _labels_from_json(raw)


def test_labels_from_json_accepts_well_formed_and_empty():
    """Sanity: well-formed and empty/falsy inputs still parse cleanly."""
    assert _labels_from_json(None) == frozenset()
    assert _labels_from_json([]) == frozenset()
    assert _labels_from_json("") == frozenset()
    labels = _labels_from_json([{"source_id": "web:x", "reason": "p"}])
    assert {lbl.source_id for lbl in labels} == {"web:x"}


def test_report_malformed_nested_label_array_exits_2_clean(tmp_path):
    """A valid-shape row with a malformed nested label array must render the
    clean 'Trace malformed' error (with file:line) and exit 2, not exit 1
    with an uncaught TypeError/KeyError traceback."""
    # Case 1: in_labels is a list of non-dicts (a string element).
    trace = tmp_path / "bad_label.jsonl"
    bad_row = (
        '{"id":"b","name":"write_file","args":{},"result":"ok",'
        '"in_labels":["evil"],"source_labels":[],"out_labels":[],'
        '"depends_on":[],"side_effect":true,"ts":null}'
    )
    trace.write_text(f"{_GOOD_ROW}\n{bad_row}\n", encoding="utf-8")
    result = runner.invoke(app, ["report", "--trace", str(trace)])
    assert result.exit_code == 2
    out = result.output.lower()
    assert "traceback" not in out
    assert "malformed" in out
    assert "bad_label.jsonl" in result.output
    assert ":2" in result.output or "line 2" in out

    # Case 2: in_labels is a list of dicts missing source_id -> KeyError pre-fix.
    trace2 = tmp_path / "missing_source_id.jsonl"
    bad_row2 = (
        '{"id":"c","name":"write_file","args":{},"result":"ok",'
        '"in_labels":[{"foo":"bar"}],"source_labels":[],"out_labels":[],'
        '"depends_on":[],"side_effect":true,"ts":null}'
    )
    trace2.write_text(f"{_GOOD_ROW}\n{bad_row2}\n", encoding="utf-8")
    result2 = runner.invoke(app, ["report", "--trace", str(trace2)])
    assert result2.exit_code == 2
    assert "traceback" not in result2.output.lower()
    assert "malformed" in result2.output.lower()

    # Case 3: in_labels is a bare string (not a list) -> TypeError pre-fix.
    trace3 = tmp_path / "string_labels.jsonl"
    bad_row3 = (
        '{"id":"d","name":"write_file","args":{},"result":"ok",'
        '"in_labels":"evil","source_labels":[],"out_labels":[],'
        '"depends_on":[],"side_effect":true,"ts":null}'
    )
    trace3.write_text(f"{_GOOD_ROW}\n{bad_row3}\n", encoding="utf-8")
    result3 = runner.invoke(app, ["report", "--trace", str(trace3)])
    assert result3.exit_code == 2
    assert "traceback" not in result3.output.lower()
    assert "malformed" in result3.output.lower()

    # Case 4: --strict surfaces the raw offending line for a bad label array.
    result4 = runner.invoke(app, ["report", "--trace", str(trace), "--strict"])
    assert result4.exit_code == 2
    assert "evil" in result4.output


def test_report_malformed_source_labels_and_out_labels_too(tmp_path):
    """The same clean error fires for a malformed source_labels/out_labels
    field, not just in_labels (all three label arrays are validated)."""
    # source_labels as a non-list (a dict).
    trace = tmp_path / "bad_source.jsonl"
    bad_row = (
        '{"id":"b","name":"fetch","args":{},"result":"ok","in_labels":[],'
        '"source_labels":{"source_id":"x"},"out_labels":[],'
        '"depends_on":[],"side_effect":false,"ts":null}'
    )
    trace.write_text(f"{_GOOD_ROW}\n{bad_row}\n", encoding="utf-8")
    result = runner.invoke(app, ["report", "--trace", str(trace)])
    assert result.exit_code == 2
    assert "traceback" not in result.output.lower()
    assert "malformed" in result.output.lower()
    assert "source_labels" in result.output

    # out_labels as a list of non-dicts.
    trace2 = tmp_path / "bad_out.jsonl"
    bad_row2 = (
        '{"id":"c","name":"fetch","args":{},"result":"ok","in_labels":[],'
        '"source_labels":[],"out_labels":[1, 2, 3],'
        '"depends_on":[],"side_effect":false,"ts":null}'
    )
    trace2.write_text(f"{_GOOD_ROW}\n{bad_row2}\n", encoding="utf-8")
    result2 = runner.invoke(app, ["report", "--trace", str(trace2)])
    assert result2.exit_code == 2
    assert "traceback" not in result2.output.lower()
    assert "malformed" in result2.output.lower()
    assert "out_labels" in result2.output
