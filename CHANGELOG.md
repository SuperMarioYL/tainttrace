# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-10-21

Fix-only bump over v0.8.0. Four reproduced bug-hunt fixes (two in the release
pipeline, two in the CLI/trace output path) plus one quality milestone; no new
product features, no new deps. File-only demand persists (0 gh issues, ever);
anchored on bug-hunt fixes matching the v0.2-v0.8 precedent. The two release
fixes matter most: the `release` workflow had failed on four consecutive tags
and every GitHub Release carried zero downloadable assets, so the project was
not installable from its own releases.

### Fixed
- **the `release` workflow no longer fails on every tag**
  (`fix-release-workflow-pypi-job-not-optional`, HIGH). The `pypi` job was
  commented "Optional PyPI trusted publishing … Skipped if unconfigured" but
  its gate was `if: startsWith(github.ref, 'refs/tags/v')` — true on every
  version tag — so with no Trusted Publisher configured on PyPI it always ran
  and always failed with `invalid-publisher: valid token, but no corresponding
  publisher`, taking the whole workflow down. Reproduced from live GitHub:
  `release` = failure on the tag commits of v0.5.0 (1bd8809), v0.6.0 (7f819de),
  v0.7.0 (759cc22) and v0.8.0 (ac2d607); the failed run 34807824052 names the
  cause. The job is now gated on the repository variable
  `vars.PYPI_PUBLISH == 'true'`, so an unconfigured repo genuinely skips it
  while publishing stays available to anyone who configures both the PyPI
  Trusted Publisher and that variable. `.github/workflows/release.yml`.
- **every release now carries its downloadable artifacts**
  (`fix-release-assets-never-attached`, HIGH). The `build` job built the wheel
  + sdist + `checksums.txt` and then only called `actions/upload-artifact@v4` —
  a 90-day workflow artifact retrievable from the Actions UI, not a release
  asset — and nothing in the workflow ever touched the GitHub Release.
  Reproduced: `gh api repos/SuperMarioYL/tainttrace/releases` returned
  `assets: []` for ALL EIGHT releases (v0.1.0 … v0.8.0). `publish_repo.sh`
  delegates this step to the tagged CI run ("release.yml will attach them on
  the tagged CI run") because it has no local `dist/`, so the delegation had
  been silently unfulfilled since v0.1.0. A new `github-release` job
  downloads the artifact and attaches `dist/*` via the preinstalled `gh` CLI
  (`gh release view … || gh release create …`, then `gh release upload
  --clobber`), which is idempotent and correct whether or not `publish_repo.sh`
  created the release first. `.github/workflows/release.yml`.
- **the trace error now names a readable, copyable path**
  (`fix-cli-trace-error-path-hard-wrapped`, MEDIUM). The CLI concatenated the
  path-bearing detail into ordinary wrapping prose, so rich hard-folded a long
  absolute path mid-token at the console width (80 on GitHub runners) and the
  literal filename did not appear in the output at all (reproduced at
  `COLUMNS=80`: `…bad_side_effect.j\nsonl:1: malformed trace row (…)`). That is
  why the shipped v0.8.0 tag's own `ci` run was red (run 34807818405, head
  ac2d607); the follow-up commit 4b85545 normalised newlines in the *test*
  instead, a band-aid already required in four assertions
  (tests/test_v060.py, tests/test_v080.py) and valid only while rich's fold
  inserts no characters at the break. The path-bearing detail line is now
  printed with `soft_wrap=True` (verified to keep the path contiguous at width
  80), the message is split into headline / detail / hint, and the four
  band-aids are reverted to plain substring assertions.
  `src/tainttrace/cli.py`.
- **a shared-but-acyclic container is no longer recorded as `"<cyclic>"`**
  (`fix-reprable-shared-substructure-false-cyclic`, LOW-MEDIUM). `_reprable`'s
  cycle guard was a global visited set with no removal, so sharing was
  indistinguishable from cyclicity: `write_file("p", {"a": shared, "b":
  shared})` recorded `{"a": [1, 2], "b": "<cyclic>"}` and
  `_reprable([shared, shared])` returned `[[1, 2], '<cyclic>']` — a fabricated
  cycle in the JSONL trace, the artifact the product exists to produce, which
  also defeated `infer_value_edges` for the dropped value. The guard is now an
  ancestor-path set (added on entry, discarded after the members are
  serialised), so only a container that contains itself on the current path
  yields the placeholder; true self-referential and mutual cycles still
  terminate with it. `src/tainttrace/wrap.py`.

### Added
- **version-lockstep guard extended to every release surface**
  (`quality-version-lockstep-all-release-surfaces`, quality). The v0.8.0
  guard asserted only three surfaces (`VERSION`, pyproject `[project] version`,
  `tainttrace.__version__`), while the release process also hand-bumps
  `web/site.json` (`meta.content_version` and the footer tag — what the live
  Pages site renders) and `docs/demo-results.json` (`version`). Both were
  bumped by hand in the v0.8.0 release commit and neither was asserted, so a
  partial bump still shipped silently on the two surfaces a user sees outside
  the package. `tests/test_v080.py::test_version_lockstep` now asserts all
  five surfaces agree and that `web/site.json` carries no other stale release
  version. `tests/test_v080.py`.

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
