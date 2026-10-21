"""v0.9.0 milestones — 4 bug-hunt fixes + 1 quality milestone over v0.8.0.

Covers:
  - fix-release-workflow-pypi-job-not-optional (HIGH): ``release.yml``'s
    ``pypi`` job is commented "Skipped if unconfigured" but its gate
    (``if: startsWith(github.ref, 'refs/tags/v')``) is true on every tag, so
    with no PyPI Trusted Publisher configured it failed with
    ``invalid-publisher`` on every release — four consecutive red ``release``
    runs (v0.5.0..v0.8.0). The job is now gated on the ``PYPI_PUBLISH``
    repository variable so an unconfigured repo genuinely skips it.
  - fix-release-assets-never-attached (HIGH): the ``build`` job built the
    wheel/sdist/checksums and then only called ``actions/upload-artifact``,
    which is a 90-day workflow artifact, not a release asset — so ALL EIGHT
    GitHub Releases carried zero downloadable assets. ``release.yml`` now
    attaches ``dist/*`` to the Release.
  - fix-cli-trace-error-path-hard-wrapped (MEDIUM): rich hard-folded the
    absolute trace path mid-token at the console width, so the CLI's "clean"
    trace error did not contain the literal filename (reproduced at
    COLUMNS=80) — which is why the shipped v0.8.0 tag's ``ci`` run was red.
    The path-bearing detail line is now printed with ``soft_wrap`` so it stays
    contiguous.
  - fix-reprable-shared-substructure-false-cyclic (LOW-MEDIUM):
    ``_reprable``'s cycle guard was a global visited set with no removal, so a
    shared-but-acyclic container was recorded in the trace as the literal
    string ``"<cyclic>"``.
  - quality-version-lockstep-all-release-surfaces (quality): the v0.8.0
    lockstep test guarded three version surfaces; ``web/site.json``
    ``meta.content_version`` and ``docs/demo-results.json`` ``version`` are
    hand-bumped every release and were unguarded.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tainttrace import (
    MemoryRecorder,
    reset_run,
    tracked,
    use_recorder,
)
from tainttrace.cli import app
from tainttrace.wrap import _reprable

REPO_ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolate_run():
    reset_run()
    yield
    reset_run()


# --------------------------------------------------------------------------- #
# fix-release-workflow-pypi-job-not-optional / fix-release-assets-never-attached
#
# The release pipeline is not unit-testable (it only runs on GitHub), but its
# CONTRACT is: parse the workflow's job map with the stdlib (the repo has no
# pyyaml dependency) and assert the two properties the v0.8.0 runs violated.
# --------------------------------------------------------------------------- #


def _release_workflow_text() -> str:
    return (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )


def _workflow_jobs(text: str) -> dict[str, list[str]]:
    """Split a workflow into ``{job_id: [lines]}`` by the YAML indentation.

    Job ids sit at indent 2 under the top-level ``jobs:`` key; their bodies are
    deeper. Comment-only lines are skipped so the explanatory comment above a
    job is never mistaken for a job id.
    """
    lines = text.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.rstrip() == "jobs:")
    except StopIteration:  # pragma: no cover - the workflow always has jobs
        raise AssertionError("workflow has no top-level `jobs:` block") from None
    jobs: dict[str, list[str]] = {}
    current: str | None = None
    for ln in lines[start + 1:]:
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip())
        if indent == 0:
            break  # left the jobs block
        if indent == 2:
            current = stripped.rstrip(":")
            jobs.setdefault(current, [])
        elif current is not None:
            jobs[current].append(ln)
    return jobs


def test_release_workflow_pypi_job_is_gated_on_a_repo_variable():
    """An unconfigured repo must SKIP the PyPI job, not fail the whole
    workflow: the gate has to depend on something the maintainer sets, not
    only on the ref being a version tag (which is always true on a release)."""
    jobs = _workflow_jobs(_release_workflow_text())
    assert "pypi" in jobs, "release.yml must still define the pypi job"
    gates = [ln for ln in jobs["pypi"] if re.match(r"^\s*if:\s", ln)]
    assert gates, "the pypi job must carry an if: gate"
    assert any("vars.PYPI_PUBLISH" in ln for ln in gates), (
        "the pypi job must be gated on vars.PYPI_PUBLISH so an unconfigured "
        f"repo skips it instead of failing the release; gates={gates}"
    )


def test_release_workflow_attaches_assets_to_the_github_release():
    """Every release shipped zero assets because nothing uploaded dist/ to the
    Release — the build job's artifacts were workflow-artifacts only."""
    jobs = _workflow_jobs(_release_workflow_text())
    uploaders = {
        name: body
        for name, body in jobs.items()
        if any(
            "gh release upload" in ln or "action-gh-release" in ln
            for ln in body
        )
    }
    assert uploaders, (
        "no release.yml job attaches the built artifacts to the GitHub "
        f"Release; jobs={sorted(jobs)}"
    )
    for name, body in uploaders.items():
        text = "\n".join(body)
        assert "dist" in text, f"job {name!r} uploads to the release but never names dist/"
        assert any(
            re.match(r"^\s*if:", ln) and "refs/tags" in ln for ln in body
        ), f"job {name!r} must be gated to version tags"


# --------------------------------------------------------------------------- #
# fix-cli-trace-error-path-hard-wrapped
# --------------------------------------------------------------------------- #


def _long_nested_path(tmp_path: Path, filename: str) -> Path:
    """A path comfortably longer than an 80-column console line.

    Reproduces the CI condition (GH runners report 80 columns) without relying
    on the ambient terminal width: the absolute path alone exceeds the line.
    """
    deep = tmp_path / ("deeply" * 12)
    deep.mkdir()
    return deep / filename


def test_malformed_trace_error_keeps_the_filename_contiguous(tmp_path):
    """The one thing a user must act on — the offending file:line — must be
    readable and copyable, not folded mid-filename."""
    trace = _long_nested_path(tmp_path, "bad_side_effect.jsonl")
    trace.write_text(
        json.dumps(
            {
                "id": "a-1",
                "name": "w",
                "side_effect": "false",
                "args": {},
                "result": "x",
                "depends_on": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app, ["report", "--trace", str(trace)], env={"COLUMNS": "80", "TERM": "dumb"}
    )

    assert result.exit_code == 2
    assert "malformed" in result.output.lower()
    assert "side_effect" in result.output
    # No newline-stripping: the path must survive verbatim in the raw output.
    assert "bad_side_effect.jsonl" in result.output, (
        "the trace path was folded mid-token; raw output was:\n" + result.output
    )
    assert str(trace) in result.output


def test_unreadable_trace_error_keeps_the_path_contiguous(tmp_path):
    """Same contract for the 'Cannot read trace' branch (a directory path)."""
    target = _long_nested_path(tmp_path, "a_directory")
    target.mkdir()

    result = runner.invoke(
        app, ["report", "--trace", str(target)], env={"COLUMNS": "80", "TERM": "dumb"}
    )

    assert result.exit_code == 2
    assert "traceback" not in result.output.lower()
    assert "cannot read trace" in result.output.lower()
    assert str(target) in result.output, (
        "the trace path was folded mid-token; raw output was:\n" + result.output
    )


# --------------------------------------------------------------------------- #
# fix-reprable-shared-substructure-false-cyclic
# --------------------------------------------------------------------------- #


def test_reprable_keeps_a_shared_acyclic_container():
    """Sharing a container is not a cycle: both references must be serialised."""
    shared = [1, 2]
    assert _reprable([shared, shared]) == [[1, 2], [1, 2]]
    shared_dict = {"k": "v"}
    assert _reprable([shared_dict, shared_dict]) == [{"k": "v"}, {"k": "v"}]
    # Nested sharing too: the inner list is referenced from two different keys.
    assert _reprable({"a": shared, "b": shared}) == {"a": [1, 2], "b": [1, 2]}


def test_reprable_still_marks_true_cycles():
    """The placeholder must survive for real cycles — that is what it is for."""
    cyc: list = []
    cyc.append(cyc)
    cyc.append("payload")
    assert _reprable(cyc) == ["<cyclic>", "payload"]

    d: dict = {}
    d["self"] = d
    assert _reprable(d) == {"self": "<cyclic>"}

    a: list = []
    b: list = [a]
    a.append(b)
    assert _reprable(a) == [["<cyclic>"]]


def test_tracked_trace_keeps_a_shared_container_argument():
    """End-to-end: the JSONL row must carry both copies of a shared value.

    A tool called with the same list under two keys is an ordinary shape
    (e.g. ``write_file(p, {"new": rows, "old": rows})``); recording one of them
    as ``"<cyclic>"`` corrupts the trace the whole product exists to produce.
    """
    rec = use_recorder(MemoryRecorder())
    shared = [1, 2]

    @tracked(side_effect=True)
    def write_file(path, body):
        return "ok"

    try:
        write_file("p", {"new": shared, "old": shared})
    finally:
        use_recorder(None)

    assert len(rec.calls) == 1
    assert rec.calls[0].args["arg1"] == {"new": [1, 2], "old": [1, 2]}
