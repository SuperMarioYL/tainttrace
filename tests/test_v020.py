"""v0.2.0 milestones — bug fixes + features over the shipped v0.1.0 source.

Covers:
  - fix-tracker-deactivate-restore (HIGH): context-manager save/restore.
  - fix-cli-malformed-json-trace (MEDIUM): clean error on a bad JSONL line.
  - m4_async_tracked (feature): @tracked supports async def tools.
  - m5_source_filter_cli (feature): tainttrace report --source <id>.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from tainttrace import (
    MemoryRecorder,
    Tracker,
    get_recorder,
    reset_run,
    taint_source,
    tracked,
    use_recorder,
)
from tainttrace.cli import app
from tainttrace.wrap import _PROCESS_RECORDER


runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolate_run():
    reset_run()
    yield
    reset_run()


# --------------------------------------------------------------------------- #
# fix-tracker-deactivate-restore
# --------------------------------------------------------------------------- #


def test_deactivate_restores_explicit_previous_recorder():
    """activate()/deactivate() must restore the recorder active before activate()."""
    prev = use_recorder(MemoryRecorder())
    try:
        tracker = Tracker().activate()
        assert get_recorder() is tracker
        tracker.deactivate()
        # The previously-active explicit recorder is restored, NOT the tracker.
        assert get_recorder() is prev
        assert get_recorder() is not tracker
    finally:
        use_recorder(None)


def test_with_tracker_context_restores_previous_recorder():
    prev = use_recorder(MemoryRecorder())
    try:
        with Tracker() as tracker:
            assert get_recorder() is tracker
        assert get_recorder() is prev
    finally:
        use_recorder(None)


def test_deactivate_restores_default_when_no_explicit_previous():
    """When no explicit recorder was active, deactivate falls back to the default."""
    use_recorder(None)  # _ACTIVE = None -> default process recorder
    tracker = Tracker().activate()
    assert get_recorder() is tracker
    tracker.deactivate()
    restored = get_recorder()
    assert restored is not tracker
    # The default recorder is the process-wide MemoryRecorder.
    assert restored is _PROCESS_RECORDER


def test_nested_trackers_restore_in_order():
    outer = use_recorder(MemoryRecorder())
    try:
        t1 = Tracker().activate()
        t2 = Tracker().activate()
        assert get_recorder() is t2
        t2.deactivate()
        assert get_recorder() is t1
        t1.deactivate()
        assert get_recorder() is outer
    finally:
        use_recorder(None)


# --------------------------------------------------------------------------- #
# fix-cli-malformed-json-trace
# --------------------------------------------------------------------------- #


def _bad_trace(path) -> None:
    path.write_text(
        '{"id":"a","name":"fetch","args":{},"result":"ok","in_labels":[],'
        '"source_labels":[],"out_labels":[],"depends_on":[],"side_effect":false,"ts":null}\n'
        "{this is not valid json}\n",
        encoding="utf-8",
    )


def test_report_malformed_json_exits_2_with_clean_error(tmp_path):
    trace = tmp_path / "bad.jsonl"
    _bad_trace(trace)
    result = runner.invoke(app, ["report", "--trace", str(trace)])
    assert result.exit_code == 2
    out = result.output.lower()
    # Clean, human-readable error — NOT a Python traceback.
    assert "traceback" not in out
    assert "malformed" in out or "invalid json" in out
    # The offending file + line number are surfaced.
    assert "bad.jsonl" in result.output
    assert ":2" in result.output or "line 2" in result.output.lower()


def test_report_strict_surfaces_raw_offending_line(tmp_path):
    trace = tmp_path / "bad.jsonl"
    _bad_trace(trace)
    result = runner.invoke(app, ["report", "--trace", str(trace), "--strict"])
    assert result.exit_code == 2
    # --strict echoes the raw offending line content for debugging.
    assert "this is not valid json" in result.output


# --------------------------------------------------------------------------- #
# m4_async_tracked
# --------------------------------------------------------------------------- #


def test_async_tracked_propagates_taint_across_await_hops(tmp_path):
    import asyncio

    rec = use_recorder(MemoryRecorder())

    @tracked
    async def fetch(url):
        return "POISON_ASYNC_BODY"

    @tracked
    async def summarize(text):
        return "summary of " + text

    @tracked(side_effect=True)
    async def write_file(path, body):
        return "wrote " + path

    async def run():
        page = taint_source(
            await fetch("http://evil"),
            source_id="web:evil",
            reason="poisoned async fetch",
        )
        summary = await summarize(page)
        await write_file("a.md", summary)

    asyncio.run(run())

    graph = rec.graph()
    graph.propagate()
    tainted = {c.name for c in graph.tainted_calls()}
    # The taint flows from the marked page through summarize into the write.
    assert "summarize" in tainted
    assert "write_file" in tainted
    # A clean async tool sharing no tainted value stays clean.
    assert "fetch" not in tainted
    use_recorder(None)


def test_async_tracked_records_to_jsonl_and_reloads(tmp_path):
    import asyncio

    from tainttrace.tracker import load_graph

    trace = tmp_path / "async_run.jsonl"
    tracker = Tracker(path=trace).activate()

    @tracked
    async def fetch(url):
        return "ASYNC_POISON"

    @tracked(side_effect=True)
    async def write_file(path, body):
        return "wrote " + path

    async def run():
        page = taint_source(await fetch("http://evil"), source_id="web:evil", reason="x")
        await write_file("a.md", page)

    try:
        asyncio.run(run())
    finally:
        tracker.deactivate()

    assert trace.exists()
    reloaded = load_graph(trace)
    tainted = {c.name for c in reloaded.tainted_calls()}
    assert "write_file" in tainted
    assert len(reloaded) == len(tracker)


# --------------------------------------------------------------------------- #
# m5_source_filter_cli
# --------------------------------------------------------------------------- #


def _two_source_trace(path) -> None:
    """Build a trace with two independent injection sources (web:a, web:b)."""
    tracker = Tracker(path=path).activate()

    @tracked
    def fetch_a():
        return "AAA"

    @tracked
    def fetch_b():
        return "BBB"

    @tracked(side_effect=True)
    def write_a(x):
        return "wa"

    @tracked(side_effect=True)
    def write_b(x):
        return "wb"

    try:
        a = taint_source(fetch_a(), source_id="web:a", reason="pa")
        b = taint_source(fetch_b(), source_id="web:b", reason="pb")
        write_a(a)
        write_b(b)
    finally:
        tracker.deactivate()


def test_report_source_scopes_to_one_injection(tmp_path):
    trace = tmp_path / "two.jsonl"
    _two_source_trace(trace)

    result = runner.invoke(
        app, ["report", "--trace", str(trace), "--source", "web:a", "--json"]
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    quarantined_names = {q["name"] for q in data["quarantine"]}
    # Only the web:a branch's write is quarantined; web:b's write is "clean" here.
    assert quarantined_names == {"write_a"}
    assert data["sources"] == ["web:a"]


def test_report_source_unknown_errors_cleanly(tmp_path):
    trace = tmp_path / "two.jsonl"
    _two_source_trace(trace)

    result = runner.invoke(
        app, ["report", "--trace", str(trace), "--source", "web:nope"]
    )
    assert result.exit_code == 2
    assert "no untrusted source" in result.output.lower()
    assert "traceback" not in result.output.lower()


def test_report_without_source_returns_full_blast_radius(tmp_path):
    trace = tmp_path / "two.jsonl"
    _two_source_trace(trace)

    result = runner.invoke(app, ["report", "--trace", str(trace), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    quarantined_names = {q["name"] for q in data["quarantine"]}
    # Without --source, both writes are quarantined.
    assert quarantined_names == {"write_a", "write_b"}
    assert set(data["sources"]) == {"web:a", "web:b"}
