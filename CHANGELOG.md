# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
