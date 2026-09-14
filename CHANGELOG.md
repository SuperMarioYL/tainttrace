# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-09-14

Fix-only bump over v0.7.0. Three reproduced bug-hunt fixes (one soundness
over-taint with two leak channels, one silent wrong-quarantine trace-parsing
gap, one CLI error-path gap) plus one quality milestone; no new product
features, no new deps. File-only demand persists (0 gh issues); anchored on
bug-hunt fixes matching the v0.2–v0.7 precedent.

### Fixed
- **singleton values no longer carry taint through either channel**
  (`fix-registry-singleton-identity-collision`, MEDIUM-HIGH). `_TaintRegistry.mark`
  registered taint by `id(value)` for ANY value, but `None`/`True`/`False` are
  process-wide singletons and CPython caches ints in `[-5, 256]` — their
  identity IS their value, so identity-keying them was value-keying by another
  name, the exact coincidental-equality collision the v0.3
  `fix-registry-scalar-value-collision` claimed to have removed (its own
  example, "taint_source(True) taints every True", still fired). The `@tracked`
  wrapper marks a tool's result with its `out_labels`, so any validator
  returning a bool flag, any in-place mutator returning `None`, or any status
  check returning a small int after consuming poisoned input tainted every
  later call passing that same singleton (`overwrite=True`, `payload=None`,
  a 200) — wrongly quarantining clean side-effecting writes (a soundness
  false-positive producing wrong roll-back decisions, reproduced four ways).
  A new `is_singleton_value` predicate in `label.py` (the taint-granularity
  leaf module) now guards BOTH channels: `_TaintRegistry.mark` skips singleton
  registration, and `TaintGraph.infer_value_edges` skips singleton results as
  value-reuse producer needles (a bool result stringified to "True" and
  substring-matched every later call passing a True flag, re-opening the
  over-taint through the graph edge channel after the registry channel was
  closed — verified while building the fix). No provenance is lost: for a
  singleton there is no "same object" case distinct from "same value";
  `ToolCall.out_labels` still records the propagation for the report, and
  non-cached scalars (e.g. `99999`) keep the documented v0.3 identity
  behaviour. `src/tainttrace/label.py`, `src/tainttrace/wrap.py`,
  `src/tainttrace/graph.py`.
- **a non-boolean `side_effect` in a trace row is now rejected instead of
  silently coerced** (`fix-trace-side-effect-shape-coercion`, MEDIUM).
  `call_from_json` did `bool(row.get("side_effect", False))`, so a truthy
  non-bool such as the string `"false"` silently parsed as `side_effect=True`
  and moved a tainted read-only call into the quarantine/roll-back set with no
  error signal (reproduced: `report --json` exited 0 with the clean call
  listed under quarantine). `_iter_rows` validated every other row field —
  JSON validity (v0.2), row shape (v0.3), nested label arrays (v0.4),
  `depends_on` (v0.6) — but not this one. A non-bool `side_effect` now raises
  a file:line `ValueError` (with the `--strict` raw line) rendered as the
  clean "Trace malformed" error + exit 2, plus a defensive
  `_side_effect_from_json` guard for direct `call_from_json` callers; absent/
  null still defaults to `False`. `src/tainttrace/tracker.py`.
- **`report --trace <directory>` renders a clean error + exit 2 instead of an
  uncaught `IsADirectoryError` traceback + exit 1**
  (`fix-cli-unreadable-trace-error`, LOW-MEDIUM). The CLI's trace-loading
  handler caught only `FileNotFoundError`; a directory path (an easy
  tab-completion mistake that typer's option validation passes through)
  escaped as a raw traceback with exit 1 — and exit 1 falsely signals
  "quarantined" to a CI gate. A new `OSError` branch (ordered after
  `FileNotFoundError`, its subclass) renders a bold-red "Cannot read trace"
  message with the OS detail and exits 2. `src/tainttrace/cli.py`.

### Added
- **version-lockstep test** (`quality-version-lockstep-test`, quality).
  The repo carries three hand-bumped version surfaces (`VERSION`,
  `pyproject.toml` `[project] version`, `tainttrace.__version__`) and no test
  asserted they agree; a partial bump would ship silently.
  `tests/test_v080.py::test_version_lockstep` now fails on any drift.

## [0.7.0] - 2026-09-01

Fix-only bump over v0.6.0. Two HIGH-confidence MEDIUM bug-hunt soundness
fixes over the shipped source; no new product features, no new deps. File-only
demand persists (0 gh issues, the repo has never had an issue); anchored on
bug-hunt fixes matching the v0.2–v0.6 precedent.

### Fixed
- **`taint_source` on a container now marks each member so an extracted member
  still carries the untrusted label** (`fix-taint-source-container-member-taint-lost`,
  MEDIUM). `taint_source` marked only the top-level object via
  `_REGISTRY.mark(value, labels)`; a container is never value-keyable, so only
  the container's own `id()` carried the label. A downstream `@tracked` tool
  that received an *extracted member* (the common "agent fetches a list,
  indexes out one element, writes it" pattern) got `in_labels=empty` and a
  poisoned side-effecting write was dropped from quarantine — a soundness
  false-negative in the core blast-radius promise, and the input-side mirror of
  the v0.6 `fix-result-container-member-taint-lost`, which added `_mark_value`
  (recursive member marking) for the `@tracked` *result* side but left the
  `taint_source` boundary primitive non-recursive. `taint_source` now calls
  `_mark_value` (the same function v0.6 shipped for the result side, with the
  `_seen` `id()` cycle guard); for a non-container value it is identical to
  `_REGISTRY.mark`, so the scalar str/bytes path is unchanged. `src/tainttrace/
  wrap.py` (`taint_source`, using the existing `_mark_value`).
- **tuple value-keying restricted to str/bytes members so a scalar-bearing tuple
  no longer over-taints every value-equal tuple**
  (`fix-registry-tuple-scalar-collision`, MEDIUM). `_is_value_keyable` returned
  `True` for ANY hashable tuple, so `taint_source((404, 501))` value-keyed the
  tuple and a later independently-constructed, value-equal tuple was falsely
  tainted (over-quarantine) — the same coincidental-value-equality collision the
  v0.3 `fix-registry-scalar-value-collision` removed for bare scalars, just
  wrapped in a tuple, despite the v0.3 docstring promising "tuples of
  [str/bytes]". A tuple is now value-keyed only when every member is str/bytes;
  a str/bytes tuple (`("admin", "secret")`) still round-trips, and identity
  tracking (`id()`) still covers any tuple object passed through.
  `src/tainttrace/wrap.py` (`_is_value_keyable`).

## [0.5.0] - 2026-08-14

Fix-only bump over v0.4.0. One high-confidence bug-hunt fix over the shipped
source; no new product features. Folds the v0.4.0-deferred
`fix-reprable-heterogeneous-set-crash`, re-confirmed at high confidence and
broadened to also cover the cyclic-container `RecursionError` in the same
function.

### Fixed
- **`_reprable` no longer crashes the `@tracked` recording path on a mixed-type
  set or a cyclic container** (`fix-reprable-container-crash`, HIGH).
  `_reprable` is called by `_safe_args`/`_safe_result` inside every `@tracked`
  wrapper, before the call is recorded. Two real inputs made it raise an
  uncaught exception that killed the agent run with **zero recorded calls** (the
  recorder never received the `ToolCall`):
  - *Heterogeneous/unorderable set members* — the set/frozenset branch did
    `sorted(_reprable(v) for v in value)` with no key, so a set like `{1, 'a'}`,
    `{'active', None}`, or `{200, 'ok', None}` raised
    `TypeError: '<' not supported between instances of 'str' and 'int'`. A
    `@tracked` tool returning a mixed-type set (a status code + message, a
    parsed token set) crashed the wrapper before recording.
  - *Cyclic/self-referential container* — the list/tuple/dict branches recursed
    with no cycle guard, so a self-referential list (`l = []; l.append(l)`) or
    dict raised `RecursionError`. `_labels_in_value` already guarded cycles via
    a `_seen` set of `id()`s; `_reprable` did not.
  The fix adds a `_seen` set-of-`id()`s cycle guard (mirroring
  `_labels_in_value`, returning a `"<cyclic>"` placeholder on a repeat) and
  replaces the bare `sorted(...)` with a total-key sort
  `sorted(..., key=lambda v: (type(v).__name__, str(v)))` so heterogeneous
  member types are never compared directly. Verified end-to-end: a `@tracked`
  tool returning `{200, 'ok', None}` now records the call (`rec.calls == 1`)
  instead of raising `TypeError` with `rec.calls == 0`. The shipped v0.4 test
  suite itself documented `_safe_args`/`_reprable` as "a separate, deferred
  concern".

[0.5.0]: https://github.com/SuperMarioYL/tainttrace/releases/tag/v0.5.0

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
