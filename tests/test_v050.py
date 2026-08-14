"""v0.5.0 milestones — 1 bug-hunt fix over the shipped v0.4.0 source.

Covers:
  - fix-reprable-container-crash (HIGH): harden ``_reprable`` so a mixed-type
    set or a cyclic container argument/result never crashes the ``@tracked``
    recording path. Before the fix, the set/frozenset branch did a bare
    ``sorted(_reprable(v) for v in value)`` with no key, so a heterogeneous set
    (``{1, 'a'}``, ``{200, 'ok', None}``) raised ``TypeError`` comparing
    int/str/None; and the list/tuple/dict branches recursed with no cycle guard,
    so a self-referential container raised ``RecursionError``. Both crashed the
    wrapper *before* the call was recorded (zero recorded calls), killing the
    agent run. The shipped v0.4 test suite documented ``_safe_args``/``_reprable``
    as "a separate, deferred concern" — this version folds it.
"""

from __future__ import annotations

import pytest

from tainttrace import (
    MemoryRecorder,
    reset_run,
    tracked,
    use_recorder,
)
from tainttrace.wrap import _reprable, _safe_args, _safe_result


@pytest.fixture(autouse=True)
def _isolate_run():
    reset_run()
    yield
    reset_run()


# --------------------------------------------------------------------------- #
# fix-reprable-container-crash — heterogeneous-set serialisation
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value",
    [
        {1, "a"},
        {"active", None},
        {200, "ok", None},
        frozenset({1, 2.0, "x"}),
        {True, "True", 0},  # bool/int/str mix
    ],
)
def test_reprable_heterogeneous_set_does_not_crash(value):
    """A mixed-type set must serialise to a JSON-friendly list, not raise
    ``TypeError`` from a bare ``sorted()``.

    Before the fix, ``sorted([1, 'a'])`` raised
    ``TypeError: '<' not supported between instances of 'str' and 'int'``.
    """
    result = _reprable(value)
    assert isinstance(result, list)
    # Every member is a JSON primitive (no container sneaks in for a flat set).
    assert all(m is None or isinstance(m, (str, int, float, bool)) for m in result)
    # The output is stable / orderable (re-running never raises).
    assert _reprable(value) == result


def test_reprable_homogeneous_set_still_sorted():
    """A homogeneous set still produces a deterministically sorted list."""
    assert _reprable({"b", "a", "c"}) == ["a", "b", "c"]
    assert _reprable({3, 1, 2}) == [1, 2, 3]


def test_reprable_preserves_strings_for_edge_inference():
    """The fix must not munge intact strings (the value-reuse edge heuristic
    depends on them) — a set of strings still yields a list of those strings."""
    assert _reprable({"poisoned", "clean"}) == ["clean", "poisoned"]


# --------------------------------------------------------------------------- #
# fix-reprable-container-crash — cyclic-container termination
# --------------------------------------------------------------------------- #


def test_reprable_cyclic_list_terminates():
    """A self-referential list must terminate (was ``RecursionError``), with the
    cycle site rendered as a ``"<cyclic>"`` placeholder."""
    cyc: list = []
    cyc.append(cyc)
    cyc.append("payload")
    result = _reprable(cyc)
    assert result[0] == "<cyclic>"
    assert result[1] == "payload"


def test_reprable_cyclic_dict_terminates():
    """A self-referential dict terminates with a ``"<cyclic>"`` placeholder."""
    d: dict = {}
    d["self"] = d
    d["leaf"] = "x"
    result = _reprable(d)
    assert result["self"] == "<cyclic>"
    assert result["leaf"] == "x"


def test_reprable_mutual_cycle_terminates():
    """A mutual cycle (two containers referencing each other) terminates too."""
    a: list = []
    b: list = [a]
    a.append(b)
    a.append("leaf")
    # Must not raise; the cycle site collapses to "<cyclic>".
    result = _reprable(a)
    assert "leaf" in result
    assert "<cyclic>" in result or isinstance(result[0], list)


# --------------------------------------------------------------------------- #
# fix-reprable-container-crash — end-to-end @tracked recording path
# --------------------------------------------------------------------------- #


def test_tracked_tool_returning_heterogeneous_set_records_call():
    """A ``@tracked`` tool that returns a mixed-type set must record the call
    (the wrapper's ``_safe_result`` / ``_reprable`` no longer raises), so the
    agent run does not die with zero recorded calls.

    Before the fix this raised ``TypeError`` from inside the wrapper, the call
    was never recorded (``rec.calls`` stayed empty), and the agent loop died.
    """
    rec = use_recorder(MemoryRecorder())

    @tracked
    def statuses(code):
        return {code, "ok", None}

    out = statuses(200)
    assert out == {200, "ok", None}
    call = next(c for c in rec.calls if c.name == "statuses")
    # The mixed-type result was serialised to a JSON-friendly list, no crash.
    assert isinstance(call.result, list)
    assert set(call.result) == {200, "ok", None}
    use_recorder(None)


def test_tracked_tool_with_heterogeneous_set_arg_records_call():
    """A ``@tracked`` call receiving a mixed-type set argument records the call
    (``_safe_args`` / ``_reprable`` on the arg no longer raises)."""
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def apply_tags(tags):
        return "applied"

    out = apply_tags({1, "urgent", None})
    assert out == "applied"
    call = next(c for c in rec.calls if c.name == "apply_tags")
    assert isinstance(call.args["arg0"], list)
    use_recorder(None)


def test_tracked_tool_with_cyclic_arg_records_call():
    """A ``@tracked`` call receiving a self-referential container records the
    call instead of raising ``RecursionError``."""
    rec = use_recorder(MemoryRecorder())

    @tracked
    def consume(graph):
        return "ok"

    cyc: list = []
    cyc.append(cyc)
    assert consume(cyc) == "ok"
    assert len(rec.calls) == 1
    use_recorder(None)


def test_safe_args_and_safe_result_never_raise_on_exotic_inputs():
    """Regression guard: ``_safe_args`` / ``_safe_result`` (the two ``_reprable``
    entry points in the wrapper) tolerate every exotic input shape without
    raising — the contract the v0.4 test suite flagged as deferred."""
    exotic = [
        {1, "a", None},
        frozenset({200, "ok"}),
        {"k": {1, "a"}},
        [{1, "a"}, {"nested": {True, 0}}],
    ]
    for value in exotic:
        # Must not raise.
        assert _safe_result(value) is not None
    assert _safe_args(({1, "a"},), {"k": {200, "ok"}}) is not None
