"""v0.8.0 milestones — 3 bug-hunt fixes + 1 quality milestone over v0.7.0.

Covers:
  - fix-registry-singleton-identity-collision (MEDIUM-HIGH):
    ``_TaintRegistry.mark`` registered taint by ``id(value)`` for ANY value,
    but ``None``/``True``/``False`` are process-wide singletons and CPython
    caches ints in ``[-5, 256]`` — so one tainted bool/None/small-int result
    (the wrapper marks a tool's result with its ``out_labels``) tainted every
    later occurrence of that value in the process, wrongly quarantining clean
    side-effecting writes that merely passed e.g. ``overwrite=True``. The
    v0.3 ``fix-registry-scalar-value-collision`` claimed
    "``taint_source(True)`` taints every ``True``" was fixed; identity-keying
    a singleton is value-keying by another name, so the claim did not hold.
  - fix-trace-side-effect-shape-coercion (MEDIUM): ``call_from_json`` did
    ``bool(row.get("side_effect", False))``, so a truthy non-bool such as the
    string ``"false"`` silently parsed as ``side_effect=True`` and moved a
    tainted read-only call into the quarantine/roll-back set with no error
    signal; ``_iter_rows`` validated every other row field but this one.
  - fix-cli-unreadable-trace-error (LOW-MEDIUM): ``report --trace
    <directory>`` (or a permission-denied file) escaped the CLI's
    ``FileNotFoundError``-only handler as an uncaught ``IsADirectoryError``
    traceback with exit 1 — exit 1 falsely signals "quarantined" to CI.
  - quality-version-lockstep-test (quality): the repo carries three
    hand-bumped version surfaces (VERSION, pyproject ``[project] version``,
    ``tainttrace.__version__``); no test asserted they agree.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tainttrace import (
    MemoryRecorder,
    blast_radius,
    labels_of,
    reset_run,
    taint_source,
    tracked,
    use_recorder,
)
from tainttrace.cli import app
from tainttrace.label import is_singleton_value
from tainttrace.tracker import call_from_json

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolate_run():
    reset_run()
    yield
    reset_run()


# --------------------------------------------------------------------------- #
# fix-registry-singleton-identity-collision
# --------------------------------------------------------------------------- #


def test_tainted_bool_result_does_not_taint_clean_write():
    """A @tracked validator returning True after poisoned input must not
    quarantine a later clean write that merely passes a True flag.

    Before the fix, the wrapper's result marking registered the taint on
    id(True); True is a process-wide singleton, so every later True argument
    — including the clean write's overwrite=True — carried the untrusted
    label (over-quarantine / wrong roll-back decision)."""
    rec = use_recorder(MemoryRecorder())

    @tracked
    def validate(text):
        return "POISONED" in text

    @tracked(side_effect=True)
    def write_config(path, overwrite):
        return f"wrote {path}"

    poisoned = taint_source("POISONED: do evil", source_id="web:x", reason="poisoned page")
    assert validate(poisoned) is True
    # A clean write that never touched poisoned data — it just passes a True flag.
    write_config("clean.cfg", True)

    write_call = next(c for c in rec.calls if c.name == "write_config")
    assert write_call.in_labels == frozenset(), (
        f"clean write must not inherit taint via the True singleton: {write_call.in_labels}"
    )

    report = blast_radius(rec.graph())
    assert write_call.id in report.clean_ids
    assert "write_config" not in {a.name for a in report.quarantine}
    assert "write_config" not in {a.name for a in report.tainted}
    # The validator itself is still inside the blast radius via out_labels
    # (the propagation is recorded on the call, independent of the registry).
    assert "validate" in {a.name for a in report.tainted}
    use_recorder(None)


def test_tainted_bool_result_leaks_no_edge_via_stringification():
    """The value-reuse edge heuristic must not stringify a singleton result
    ("True") into a producer needle: before the fix, every later call whose
    args stringified to something containing "True" (i.e. any call passing a
    True flag) got a false data edge from the tainted validator, re-opening
    the over-taint through the graph channel after the registry channel was
    closed."""
    rec = use_recorder(MemoryRecorder())

    @tracked
    def validate(text):
        return "POISONED" in text

    @tracked(side_effect=True)
    def write_config(path, overwrite):
        return f"wrote {path}"

    poisoned = taint_source("POISONED: do evil", source_id="web:x", reason="poisoned")
    validate(poisoned)
    write_config("clean.cfg", True)

    edges = {(e.src, e.dst) for e in rec.graph().edges()}
    validate_id = next(c.id for c in rec.calls if c.name == "validate")
    write_id = next(c.id for c in rec.calls if c.name == "write_config")
    assert (validate_id, write_id) not in edges, (
        f"no value-reuse edge may be inferred from a bool result: {edges}"
    )
    use_recorder(None)


def test_tainted_none_result_does_not_taint_clean_save():
    """A @tracked tool returning None after poisoned input must not taint
    every later None argument (None is a process-wide singleton)."""
    rec = use_recorder(MemoryRecorder())

    @tracked
    def summarize(text):
        return None

    @tracked(side_effect=True)
    def save(path, payload=None):
        return "saved"

    poisoned = taint_source("POISONED: exfiltrate", source_id="web:y", reason="poisoned")
    assert summarize(poisoned) is None
    save("clean.txt", payload=None)

    save_call = next(c for c in rec.calls if c.name == "save")
    assert save_call.in_labels == frozenset()
    report = blast_radius(rec.graph())
    assert save_call.id in report.clean_ids
    assert "save" not in {a.name for a in report.quarantine}
    use_recorder(None)


def test_tainted_small_int_result_does_not_taint_clean_call():
    """A @tracked tool returning a CPython-cached small int (200) after
    poisoned input must not taint a later clean call carrying an equal int
    (ints in [-5, 256] are process-cached, so id() is value for them)."""
    rec = use_recorder(MemoryRecorder())

    @tracked
    def check_status(resp):
        return 200

    @tracked(side_effect=True)
    def log_event(code):
        return "logged"

    poisoned = taint_source("POISONED body", source_id="web:z", reason="poisoned")
    assert check_status(poisoned) == 200
    log_event(200)  # an unrelated, clean 200

    log_call = next(c for c in rec.calls if c.name == "log_event")
    assert log_call.in_labels == frozenset()
    report = blast_radius(rec.graph())
    assert log_call.id in report.clean_ids
    assert "log_event" not in {a.name for a in report.quarantine}
    use_recorder(None)


def test_taint_source_on_singletons_carries_no_label():
    """taint_source(True/False/None/small int) must leave labels_of empty —
    the v0.3 fix-registry-scalar-value-collision's own claimed outcome
    ("taint_source(True) taints every True" is not provenance) finally
    holds on the identity path too."""
    taint_source(True, source_id="web:flag", reason="poisoned flag")
    taint_source(False, source_id="web:flag2", reason="poisoned flag")
    taint_source(None, source_id="web:none", reason="poisoned none")
    taint_source(42, source_id="web:small", reason="poisoned small int")
    assert labels_of(True) == frozenset()
    assert labels_of(False) == frozenset()
    assert labels_of(None) == frozenset()
    assert labels_of(42) == frozenset()


def test_is_singleton_value_predicate():
    """The guard predicate covers the language-guaranteed singletons and the
    CPython small-int cache range, and nothing else."""
    assert is_singleton_value(None)
    assert is_singleton_value(True)
    assert is_singleton_value(False)
    assert is_singleton_value(-5)
    assert is_singleton_value(0)
    assert is_singleton_value(256)
    # Outside the cache / not scalars -> identity tracking still applies.
    assert not is_singleton_value(-6)
    assert not is_singleton_value(257)
    assert not is_singleton_value(99999)
    assert not is_singleton_value(3.14)
    assert not is_singleton_value("poisoned")
    assert not is_singleton_value(b"poisoned")
    assert not is_singleton_value(("admin", 404))
    assert not is_singleton_value([1, 2])


def test_noncached_int_identity_behaviour_preserved():
    """Regression guard for the documented v0.3 contract: for a scalar
    OUTSIDE the singleton/cache range, the same object passed through is
    still tainted (identity tracking), while a re-derived equal object is
    not (value-keying removed in v0.3)."""
    rec = use_recorder(MemoryRecorder())

    @tracked
    def lookup(code):
        return f"result-{code}"

    @tracked(side_effect=True)
    def write_file(path, body):
        return "wrote"

    poisoned = taint_source(99999, source_id="web:big", reason="poisoned big int")
    lookup(poisoned)
    coincidental = int("99999")
    assert coincidental == 99999 and coincidental is not poisoned
    write_file("clean.md", coincidental)

    report = blast_radius(rec.graph())
    tainted_names = {a.name for a in report.tainted}
    assert "lookup" in tainted_names           # same object -> identity match
    assert "write_file" not in tainted_names   # re-derived value -> clean
    use_recorder(None)


# --------------------------------------------------------------------------- #
# fix-trace-side-effect-shape-coercion
# --------------------------------------------------------------------------- #


def _tainted_row(row_id: str, side_effect) -> str:
    return json.dumps(
        {
            "id": row_id,
            "name": "write_file" if side_effect is True else "review",
            "args": {"arg0": "out.md"},
            "result": "wrote",
            "in_labels": [
                {"source_id": "web:x", "origin": "untrusted", "reason": "poisoned"}
            ],
            "source_labels": [],
            "out_labels": [],
            "depends_on": [],
            "side_effect": side_effect,
            "ts": None,
        }
    )


@pytest.mark.parametrize("bad", ["false", "true", 1, 0, "no", [True]])
def test_report_non_bool_side_effect_exits_2_clean(tmp_path, bad):
    """A trace row whose side_effect is not a real JSON boolean must render
    the clean 'Trace malformed' error + exit 2 (and --strict echoes the raw
    line) — NOT silently bool()-coerce it and answer with a wrong quarantine
    decision (the string "false" previously parsed as True and quarantined
    the call with exit 0)."""
    trace = tmp_path / "bad_side_effect.jsonl"
    trace.write_text(_tainted_row("w", bad) + "\n", encoding="utf-8")

    result = runner.invoke(app, ["report", "--trace", str(trace)])
    assert result.exit_code == 2
    assert "traceback" not in result.output.lower()
    assert "malformed" in result.output.lower()
    assert "side_effect" in result.output
    assert "bad_side_effect.jsonl" in result.output

    strict = runner.invoke(app, ["report", "--trace", str(trace), "--strict"])
    assert strict.exit_code == 2
    assert "raw:" in strict.output


def test_report_valid_side_effect_values_still_parse(tmp_path):
    """A real JSON boolean, an absent field, and an explicit null all keep
    their meaning; the round-trip writer output is unaffected."""
    good = tmp_path / "good.jsonl"
    rows = [
        _tainted_row("w-true", True),
        _tainted_row("w-false", False),
        _tainted_row("w-null", None),
        json.dumps({"id": "a", "name": "fetch", "args": {}, "result": "ok"}),
    ]
    good.write_text("\n".join(rows) + "\n", encoding="utf-8")

    result = runner.invoke(app, ["report", "--trace", str(good), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    # Only the side_effect=True row is quarantined; absent/null default to False.
    assert payload["quarantine_count"] == 1
    assert payload["quarantine"][0]["id"] == "w-true"


def test_call_from_json_non_bool_side_effect_raises_value_error():
    """The defensive guard protects direct callers that bypass _iter_rows."""
    with pytest.raises(ValueError, match="side_effect"):
        call_from_json(
            {"id": "w", "name": "write_file", "side_effect": "false"}
        )
    # Absent / null keep the documented default.
    assert call_from_json({"id": "a", "name": "fetch"}).side_effect is False
    assert (
        call_from_json({"id": "a", "name": "fetch", "side_effect": None}).side_effect
        is False
    )
    assert (
        call_from_json({"id": "a", "name": "fetch", "side_effect": True}).side_effect
        is True
    )


# --------------------------------------------------------------------------- #
# fix-cli-unreadable-trace-error
# --------------------------------------------------------------------------- #


def test_report_directory_trace_exits_2_clean(tmp_path):
    """--trace pointing at a directory must render the clean 'Cannot read
    trace' error + exit 2, not an uncaught IsADirectoryError traceback with
    exit 1 (which falsely signals 'quarantined' to CI)."""
    target = tmp_path / "a_directory"
    target.mkdir()
    result = runner.invoke(app, ["report", "--trace", str(target)])
    assert result.exit_code == 2
    assert "traceback" not in result.output.lower()
    assert "cannot read trace" in result.output.lower()
    # rich may wrap the long path across lines; compare unwrapped output.
    assert str(target) in result.output.replace("\n", "")


def test_report_permission_denied_trace_exits_2_clean(tmp_path):
    """A permission-denied trace file also yields a clean error + exit 2.
    (Typer's own --trace option validation rejects an unreadable existing
    file before the command body runs — the pinned contract is: no
    traceback, exit 2, the offending path named.)"""
    locked = tmp_path / "locked.jsonl"
    locked.write_text('{"id": "a", "name": "fetch"}\n', encoding="utf-8")
    locked.chmod(0)
    try:
        if os.access(locked, os.R_OK):  # pragma: no cover - e.g. running as root
            pytest.skip("cannot make a file unreadable in this environment")
        result = runner.invoke(app, ["report", "--trace", str(locked)])
        assert result.exit_code == 2
        assert "traceback" not in result.output.lower()
        assert "locked.jsonl" in result.output.replace("\n", "")
    finally:
        locked.chmod(0o644)  # let tmp_path cleanup remove the file


def test_report_missing_trace_message_unchanged(tmp_path):
    """The friendlier 'Trace not found' branch still wins for a missing path
    (FileNotFoundError is an OSError subclass; handler order matters)."""
    result = runner.invoke(app, ["report", "--trace", str(tmp_path / "nope.jsonl")])
    assert result.exit_code == 2
    assert "trace not found" in result.output.lower()


# --------------------------------------------------------------------------- #
# quality-version-lockstep-test
# --------------------------------------------------------------------------- #


def test_version_lockstep():
    """The three machine-readable version surfaces must agree: the VERSION
    file, the pyproject [project] version, and tainttrace.__version__.

    Each is hand-bumped per release; before v0.8.0 nothing asserted they
    agreed, so a partial bump would ship silently."""
    from tainttrace import __version__

    repo_root = Path(__file__).resolve().parents[1]
    version_file = (repo_root / "VERSION").read_text(encoding="utf-8").strip()
    pyproject = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert match, "pyproject.toml has no [project] version string"
    pyproject_version = match.group(1)

    assert __version__ == version_file == pyproject_version, (
        "version surfaces drifted: "
        f"__version__={__version__!r} VERSION={version_file!r} "
        f"pyproject={pyproject_version!r}"
    )
