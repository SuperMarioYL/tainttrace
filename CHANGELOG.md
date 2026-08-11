# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-11

Fix-only bump over v0.3.0. Two high-confidence bug-hunt fixes over the shipped
source; no new product features.

### Fixed
- **`@tracked` collects taint nested inside container arguments**
  (`fix-collect-in-labels-container-args`, MEDIUM). `_collect_in_labels` only
  looked up each top-level argument by identity/value, so a poisoned string
  nested inside a list/tuple/dict/set argument (`write_file("x", [poisoned])`,
  `write_file("p", {"body": poisoned})`) was never registered or looked up →
  `in_labels=∅` → the side-effecting write was classified proven-clean and
  dropped from the quarantine list (a soundness false-negative in the core
  blast-radius promise). Container arguments are now walked recursively (with a
  cycle guard) so a tainted member one or more levels deep still contributes its
  labels to the call's `in_labels`.
- **`tainttrace report` renders a clean error on a malformed nested label
  array** (`fix-trace-nested-label-shape-crash`, MEDIUM). The v0.3 fix
  validated only the top-level trace-row shape; `_labels_from_json` still
  indexed `item["source_id"]` unvalidated, so a row carrying a malformed
  `in_labels`/`source_labels`/`out_labels` field (a string, an int, a dict, or
  a list of non-dicts / dicts missing `source_id`) raised an uncaught
  `TypeError`/`KeyError` — not a `ValueError` — bypassing the "Trace malformed"
  handler and exiting 1 with an empty error. Each nested label item's shape is
  now validated (in `_iter_rows` with file:line, and as a defensive guard in
  `_labels_from_json`) so the CLI renders "Trace malformed" + exit 2, the
  intended clean path.

[0.4.0]: https://github.com/SuperMarioYL/tainttrace/releases/tag/v0.4.0

## [0.2.0] - 2026-08-01

Iteration over v0.1.0. File-only demand (0 open GitHub issues/PRs); milestones
anchored on bug-hunt defects over the shipped source plus self-proposed
in-scope optimizations, not external prescription.

### Fixed
- **`Tracker.activate()`/`deactivate()` restore the previous recorder**
  (`fix-tracker-deactivate-restore`, HIGH). `use_recorder(X)` returns the recorder
  you just set, so `activate()` previously captured `self` as `_previous` and
  `deactivate()` left the tracker active, never restoring the prior recorder.
  Now captures the active recorder *before* swapping. The documented
  `use_recorder(X) -> X` contract is preserved.
- **`tainttrace report` handles malformed JSONL lines** (`fix-cli-malformed-json-trace`,
  MEDIUM). A single corrupt/truncated line (a killed-process partial write)
  raised an uncaught `ValueError` traceback. The CLI now catches it, prints a
  bold-red file:line error, and exits 2. `--strict` surfaces the raw offending
  line content.

### Added
- **`@tracked` supports `async def` tools** (`m4_async_tracked`). v0.1 called
  `func(*args)` synchronously, so an `async def` tool's body never ran and its
  result was recorded as `repr(coroutine)`, losing the taint. `@tracked` now
  detects coroutine functions and emits an `async` wrapper that `await`s the
  tool, propagates taint on the awaited result, and records the call. No new
  dependencies — async agents (httpx/aiohttp) now work out of the box.
- **`tainttrace report --source <id>`** (`m5_source_filter_cli`). Exposes the
  existing `quarantine_from_source` API from the CLI, scoping the blast radius
  to a single named injection. Composes with `--json`; an unknown source renders
  the "No untrusted source" error cleanly.

[0.2.0]: https://github.com/SuperMarioYL/tainttrace/releases/tag/v0.2.0

## [0.1.0] - 2026-06-23

First public release — the m1 + m2 + m3 milestones of the MVP.

### Added
- **Taint label primitive** (`tainttrace.label`): immutable `TaintLabel` /
  `TaintSet` with the monotone union propagation rule
  (`out = union(inputs) ∪ explicit_sources`).
- **Tool-call graph** (`tainttrace.graph`): `ToolCall` / `TaintGraph` with
  explicit `depends_on` edges, value-reuse edge inference, topological
  propagation, and downstream reachability.
- **Drop-in wrapper** (`tainttrace.wrap`): `@tracked` decorator and
  `taint_source()` boundary helper; records labeled calls on a pluggable
  recorder; side-effect inference from the tool name.
- **Blast radius / quarantine** (`tainttrace.quarantine`): `blast_radius()` and
  `quarantine_from_source()` partition a run into tainted, quarantine
  (tainted + side-effecting), and proven-clean sets, with hop distances and
  provenance.
- **Tracker facade** (`tainttrace.Tracker`): one object that records a run to a
  JSONL trace and computes its blast radius; `load_graph` / `load_report`
  replay a persisted trace offline.
- **CLI** (`tainttrace`): `report --trace run.jsonl` renders a red quarantine
  list with rich; `--json` emits a machine-readable blast radius; `demo` runs
  the bundled scenario end to end.
- **Example**: `examples/poisoned_web_demo.py` — a sub-60-second poisoned-web run
  yielding "4 of 11 actions tainted, 7 proven clean".

[0.1.0]: https://github.com/SuperMarioYL/tainttrace/releases/tag/v0.1.0
