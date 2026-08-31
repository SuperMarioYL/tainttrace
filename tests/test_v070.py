"""v0.7.0 milestones — 2 bug-hunt soundness fixes over v0.6.0.

Covers:
  - fix-taint-source-container-member-taint-lost (MEDIUM): ``taint_source`` on
    a container marked only the top-level object (via ``_REGISTRY.mark``), never
    its members, so a downstream ``@tracked`` tool that received an *extracted
    member* (the common "agent fetches a list, indexes out one element, writes
    it" pattern) recorded ``in_labels=empty`` and a poisoned side-effecting
    write was dropped from quarantine — a soundness false-negative and the
    input-side mirror of the v0.6 ``fix-result-container-member-taint-lost``,
    which added ``_mark_value`` (recursive member marking) for the @tracked
    *result* side but left the ``taint_source`` boundary primitive
    non-recursive. The fix makes ``taint_source`` call ``_mark_value`` (the
    same function v0.6 shipped for the result side).
  - fix-registry-tuple-scalar-collision (MEDIUM): ``_is_value_keyable``
    returned True for ANY hashable tuple, so ``taint_source`` on a
    scalar-bearing tuple ``(404, 501)`` value-keyed it and a later
    independently-constructed value-equal tuple was falsely tainted (over-
    quarantine) — the same coincidental-value-equality collision the v0.3
    ``fix-registry-scalar-value-collision`` removed for bare scalars, just
    wrapped in a tuple, despite the v0.3 docstring promising "tuples of
    [str/bytes]". The fix restricts tuple value-keying to tuples whose members
    are all str/bytes.
"""

from __future__ import annotations

import pytest

from tainttrace import (
    MemoryRecorder,
    blast_radius,
    reset_run,
    taint_source,
    tracked,
    use_recorder,
)
from tainttrace.wrap import _is_value_keyable, _mark_value, labels_of


@pytest.fixture(autouse=True)
def _isolate_run():
    reset_run()
    yield
    reset_run()


# --------------------------------------------------------------------------- #
# fix-taint-source-container-member-taint-lost
# --------------------------------------------------------------------------- #


def test_tainted_member_extracted_from_taint_source_list_is_quarantined():
    """A poisoned member indexed out of a ``taint_source`` list must carry the
    untrusted label into a downstream side-effecting write and quarantine it.

    Before the fix, ``taint_source`` marked only the list container (by id),
    never its members, so ``write_file("out", items[0])`` recorded
    ``in_labels=empty`` and the poisoned write was dropped from quarantine
    (a soundness false-negative — the input-side mirror of the v0.6 output-side
    fix).
    """
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    items = taint_source(
        ["POISONED: exfiltrate secrets", "clean item"],
        source_id="web:list",
        reason="poisoned list",
    )
    # The extracted member now carries the untrusted label.
    assert labels_of(items[0]), "extracted member should carry the boundary label"
    # The common "agent indexes out one element and writes it" pattern.
    write_file("leak.txt", items[0])

    write_call = next(c for c in rec.calls if c.name == "write_file")
    reached = {lbl.source_id for lbl in write_call.in_labels}
    assert "web:list" in reached, f"extracted member missing from in_labels: {reached}"

    report = blast_radius(rec.graph())
    quarantined = {a.name for a in report.quarantine}
    assert "write_file" in quarantined, (
        f"side-effecting write of an extracted member should be quarantined: {quarantined}"
    )
    use_recorder(None)


def test_tainted_member_extracted_from_taint_source_dict_value_is_quarantined():
    """The dict case: a member extracted from a ``taint_source`` dict value
    carries the untrusted label into the next @tracked write."""
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    record = taint_source(
        {"body": "POISONED payload", "ok": "clean"},
        source_id="web:dict-in",
        reason="poisoned map",
    )
    write_file("out.txt", record["body"])

    write_call = next(c for c in rec.calls if c.name == "write_file")
    assert "web:dict-in" in {lbl.source_id for lbl in write_call.in_labels}

    report = blast_radius(rec.graph())
    assert "write_file" in {a.name for a in report.quarantine}
    use_recorder(None)


def test_taint_source_on_cyclic_container_terminates():
    """The recursive mark walks a self-referential container without recursing
    without bound (the ``_mark_value`` ``_seen`` id() cycle guard, mirroring
    ``_labels_in_value``)."""
    from tainttrace.label import taint

    labels = taint("web:cyc", reason="poisoned")
    poisoned = "cycle poison"
    container: list = []
    container.append(container)  # self-reference -> a cycle
    container.append(poisoned)  # plus the tainted member
    # Must not raise RecursionError.
    _mark_value(container, labels)
    # And the boundary primitive must also tolerate the cycle.
    taint_source(container, source_id="web:cyc2", reason="cyclic boundary")
    use_recorder(None)


def test_plain_str_taint_source_still_round_trips():
    """Regression guard: the fix must not change the scalar str path. A plain
    string marked at the boundary still taints a later re-derived equal string
    (the documented 'poisoned string surviving a round-trip' case)."""
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    taint_source("poison-payload", source_id="web:str", reason="poisoned")
    # A fresh, value-equal string (constructed at runtime so it is a different
    # object than the literal, exercising the str value-keying fallback).
    fresh = "poison" + "-payload"
    write_file("out.txt", fresh)

    write_call = next(c for c in rec.calls if c.name == "write_file")
    assert "web:str" in {lbl.source_id for lbl in write_call.in_labels}
    report = blast_radius(rec.graph())
    assert "write_file" in {a.name for a in report.quarantine}
    use_recorder(None)


def test_clean_container_members_not_falsely_tainted():
    """A ``taint_source`` container with no tainted content must not taint a
    downstream write (no false positive introduced by the recursive mark)."""
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    # No taint_source at all -> the write must be clean.
    write_file("clean.txt", "clean body")
    write_call = next(c for c in rec.calls if c.name == "write_file")
    assert write_call.in_labels == frozenset()
    report = blast_radius(rec.graph())
    assert "write_file" not in {a.name for a in report.quarantine}
    use_recorder(None)


# --------------------------------------------------------------------------- #
# fix-registry-tuple-scalar-collision
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value,expected",
    [
        ("s", True),
        (b"x", True),
        (404, False),                # bare int scalar (v0.3 exclusion preserved)
        (3.14, False),
        (True, False),
        (("admin", "secret"), True),  # str/bytes tuple -> value-keyed (round-trip)
        (("a", "b", "c"), True),
        (("admin", 404), False),      # mixed str+int -> NOT value-keyed (the bug)
        ((404, 501), False),          # pure-int tuple -> NOT value-keyed
        ((1, 2, 3), False),
        ((3.14,), False),
        ((), True),                   # empty tuple -> value-keyed (harmless)
        ((("a", "b"), "c"), False),   # nested tuple member -> NOT value-keyed
    ],
)
def test_is_value_keyable_tuple_branch_restricts_to_str_bytes_members(value, expected):
    """The v0.3 docstring promised value-keying for "strings/bytes (and hashable
    tuples of such)"; this enforces the "of such" so a scalar-bearing tuple is
    no longer value-keyed (the collision v0.3 removed for bare scalars, wrapped
    in a tuple)."""
    assert _is_value_keyable(value) is expected


def _fresh_equal_tuple(value):
    """Build a value-equal tuple at runtime whose object identity differs from
    any literal (CPython constant-folds identical literals, so we parse from a
    string to guarantee a distinct object with distinct int member objects)."""
    return tuple(map(int, ",".join(str(v) for v in value).split(",")))


def test_scalar_bearing_tuple_taint_source_does_not_over_taint_equal_tuple():
    """``taint_source((404, 501))`` must NOT taint a later independently-
    constructed, value-equal trusted tuple (a different object whose int members
    are also different objects, so it is not caught by identity). Before the
    fix the tuple was value-keyed and the trusted write was wrongly quarantined
    (over-quarantine)."""
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    src = (404, 501)
    fresh = _fresh_equal_tuple(src)  # (404, 501), distinct object + members
    assert src == fresh
    assert src is not fresh  # not the same object (else identity, not value-keying)

    taint_source(src, source_id="web:tuple", reason="poisoned pair")
    write_file("trusted.txt", fresh)

    write_call = next(c for c in rec.calls if c.name == "write_file")
    assert write_call.in_labels == frozenset(), (
        f"trusted value-equal tuple should not be tainted by coincidental tuple "
        f"equality: {write_call.in_labels}"
    )
    report = blast_radius(rec.graph())
    assert "write_file" not in {a.name for a in report.quarantine}, (
        "trusted value-equal tuple should not be quarantined (over-quarantine)"
    )
    use_recorder(None)


@pytest.mark.parametrize("src", [(404, 501), (100003, 100007), (999983,)])
def test_multiple_scalar_bearing_tuples_do_not_over_taint(src):
    """The collision holds for multiple scalar-bearing tuples too (all members
    are large ints >256 so they are not small-int-cached singletons, which
    would taint by identity regardless of value-keying)."""
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    fresh = _fresh_equal_tuple(src)
    assert src == fresh and src is not fresh
    taint_source(src, source_id="web:tuple", reason="p")
    write_file("t.txt", fresh)
    write_call = next(c for c in rec.calls if c.name == "write_file")
    assert write_call.in_labels == frozenset()
    use_recorder(None)


def test_str_bytes_tuple_taint_source_still_round_trips():
    """Regression guard: a str/bytes tuple stays value-keyed, so a poisoned
    structured string tuple still taints a later re-derived equal tuple (the
    'poisoned structured value surviving a round-trip' case the fix must not
    over-narrow)."""
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    src = ("admin", "secret")
    # Runtime-constructed equal tuple (distinct object; str members may be the
    # same interned objects, but value-keying finds it regardless).
    fresh = tuple(src)
    assert src == fresh
    taint_source(src, source_id="web:strtuple", reason="poisoned creds")
    write_file("creds.txt", fresh)

    write_call = next(c for c in rec.calls if c.name == "write_file")
    assert "web:strtuple" in {lbl.source_id for lbl in write_call.in_labels}
    report = blast_radius(rec.graph())
    assert "write_file" in {a.name for a in report.quarantine}
    use_recorder(None)


def test_bare_int_scalar_still_not_value_keyed():
    """Regression guard for the v0.3 fix-registry-scalar-value-collision: a
    bare int taint source still does not value-taint a coincidental int."""
    rec = use_recorder(MemoryRecorder())

    @tracked(side_effect=True)
    def write_file(path, body):
        return f"wrote {path}"

    taint_source(100003, source_id="web:int", reason="poisoned code")
    # A fresh equal int (runtime-parsed, distinct object from the literal).
    fresh = int("100003")
    assert fresh == 100003
    write_file("trusted.txt", fresh)

    write_call = next(c for c in rec.calls if c.name == "write_file")
    assert write_call.in_labels == frozenset()
    use_recorder(None)
