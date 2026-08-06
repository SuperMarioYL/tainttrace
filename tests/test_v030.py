"""v0.3.0 milestones — 4 bug-hunt fixes over the shipped v0.2.0 source.

Covers:
  - fix-hops-zero-on-wrapper-traces (MEDIUM): correct hop distances on
    @tracked wrapper traces (source-node detection must not conflate minted
    vs inherited taint).
  - fix-cli-non-json-shape-trace-row (MEDIUM): catch valid-JSON-but-wrong-shape
    trace rows (list / dict missing id|name) instead of an uncaught
    TypeError/KeyError with exit 1.
  - fix-registry-scalar-value-collision (MEDIUM): stop value-keying
    int/float/bool taint so coincidental-equal scalars are not falsely tainted.
  - fix-side-effect-verb-substring-false-positive (MEDIUM): match side-effect
    verbs on word boundaries so input_parser/compute_hash/asset_lookup are not
    wrongly flagged side_effecting.
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

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolate_run():
    reset_run()
    yield
    reset_run()


# --------------------------------------------------------------------------- #
# fix-hops-zero-on-wrapper-traces
# --------------------------------------------------------------------------- #


def test_hops_nonzero_on_wrapper_trace():
    """A @tracked wrapper trace must yield real hop distances, not all-zero.

    The @tracked wrapper records taint inherited from a predecessor's marked
    result into ``in_labels``. The old source-node detector treated any call
    with a tainted ``local_in()`` (in_labels ∪ source_labels) as an origin
    node, so every tainted call on a wrapper trace was classified hop 0.
    With the fix, only calls that *mint* taint at their boundary (source_labels)
    or carry in_labels no predecessor's out_labels explained are origins.
    """
    rec = use_recorder(MemoryRecorder())

    @tracked
    def fetch(url):
        return "POISON_BODY"

    @tracked
    def summarize(text):
        return "summary of " + text

    @tracked(side_effect=True)
    def write_file(path, body):
        return "wrote " + path

    page = taint_source(fetch("http://evil"), source_id="web:evil", reason="poisoned")
    summary = summarize(page)
    write_file("out.md", summary)

    report = blast_radius(rec.graph())
    by_name = {a.name: a.hops for a in report.tainted}
    # summarize is where the registry-minted taint enters the trace (hop 0);
    # write_file inherits it via a data edge (hop 1). Without the fix, both
    # are 0 because every tainted call is a "source node".
    assert by_name["summarize"] == 0, f"summarize should be the origin (hop 0), got {by_name}"
    assert by_name["write_file"] == 1, f"write_file should be 1 hop downstream, got {by_name}"
    use_recorder(None)


# --------------------------------------------------------------------------- #
# fix-cli-non-json-shape-trace-row
# --------------------------------------------------------------------------- #


_GOOD_ROW = (
    '{"id":"a","name":"fetch","args":{},"result":"ok","in_labels":[],'
    '"source_labels":[],"out_labels":[],"depends_on":[],"side_effect":false,"ts":null}'
)


def test_report_wrong_shape_rows_exits_2_clean(tmp_path):
    """A valid-JSON-but-wrong-shape row (a list, or a dict missing id/name)
    must not abort with an uncaught TypeError/KeyError and exit 1; it must
    render the clean 'Trace malformed' error and exit 2 (and --strict must
    echo the raw offending line)."""
    # Case 1: a list row — TypeError on row["id"] without the fix.
    trace = tmp_path / "list_row.jsonl"
    trace.write_text(f"{_GOOD_ROW}\n[1, 2, 3]\n", encoding="utf-8")
    result = runner.invoke(app, ["report", "--trace", str(trace)])
    assert result.exit_code == 2
    out = result.output.lower()
    assert "traceback" not in out
    assert "malformed" in out
    assert "list_row.jsonl" in result.output

    # Case 2: a dict missing the required 'id' key — KeyError without the fix.
    trace2 = tmp_path / "missing_id.jsonl"
    trace2.write_text('{"name":"fetch","args":{}}\n', encoding="utf-8")
    result2 = runner.invoke(app, ["report", "--trace", str(trace2)])
    assert result2.exit_code == 2
    assert "traceback" not in result2.output.lower()
    assert "malformed" in result2.output.lower()

    # Case 3: --strict surfaces the raw offending line for a wrong-shape row.
    result3 = runner.invoke(app, ["report", "--trace", str(trace), "--strict"])
    assert result3.exit_code == 2
    assert "[1, 2, 3]" in result3.output


# --------------------------------------------------------------------------- #
# fix-registry-scalar-value-collision
# --------------------------------------------------------------------------- #


def test_scalar_value_collision_not_tainted():
    """taint_source on a scalar must not taint every coincidental-equal scalar
    arg (value-keying is sound for strings only; identity tracking covers the
    same object). Without the fix, _is_value_keyable returned True for
    int/float/bool, so taint_source(99999) tainted every later 99999."""
    rec = use_recorder(MemoryRecorder())

    @tracked
    def lookup(code):
        return f"result-{code}"

    @tracked(side_effect=True)
    def write_file(path, body):
        return "wrote"

    # Mark an int as untrusted — only the SAME object should carry the taint.
    poisoned = taint_source(99999, source_id="web:evil", reason="poisoned int")
    lookup(poisoned)

    # A *different* int object with the same value — no data flow, no identity.
    coincidental = int("99999")
    assert coincidental == 99999 and coincidental is not poisoned
    write_file("clean.md", coincidental)

    report = blast_radius(rec.graph())
    tainted_names = {a.name for a in report.tainted}
    assert "lookup" in tainted_names          # identity match -> tainted
    assert "write_file" not in tainted_names  # value-only match -> NOT tainted
    use_recorder(None)


# --------------------------------------------------------------------------- #
# fix-side-effect-verb-substring-false-positive
# --------------------------------------------------------------------------- #


def test_side_effect_verb_word_boundary():
    """Side-effect verbs must match on word boundaries, not bare substring —
    input_parser/compute_hash/asset_lookup contain 'put'/'set' as substrings
    but are read-only, while write_file/commit_changes are genuinely
    side-effecting. Without the fix, the substring test wrongly flagged the
    read-only tools as side_effecting (over-quarantine/roll-back)."""
    rec = use_recorder(MemoryRecorder())

    @tracked
    def input_parser(text):
        return "parsed"

    @tracked
    def compute_hash(data):
        return "hashed"

    @tracked
    def asset_lookup(key):
        return "looked up"

    @tracked
    def write_file(path, body):
        return "wrote"

    input_parser("x")
    compute_hash("y")
    asset_lookup("z")
    write_file("a", "b")

    by_name = {c.name: c for c in rec.calls}
    # False positives: substring match wrongly flagged these as side-effecting.
    assert by_name["input_parser"].side_effect is False
    assert by_name["compute_hash"].side_effect is False
    assert by_name["asset_lookup"].side_effect is False
    # True positive: 'write' is a token of 'write_file'.
    assert by_name["write_file"].side_effect is True
    use_recorder(None)
