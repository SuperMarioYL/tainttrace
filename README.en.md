<div align="right"><sub><b>English</b>&nbsp;&nbsp;⇄&nbsp;&nbsp;<a href="./README.md">简体中文</a></sub></div>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/hero-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="./assets/hero-light.svg">
  <img src="./assets/hero-light.svg" width="880" alt="TaintTrace — dynamic taint tracking that computes a Prompt Injection's blast radius across an Agent's tool graph">
</picture>

<p><sub>TaintTrace is the taint-tracking tool that computes a Prompt Injection's blast radius across an Agent's tool-call graph.</sub></p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-black.svg" alt="License"></a>
  <a href="https://github.com/SuperMarioYL/tainttrace/releases"><img src="https://img.shields.io/github/v/release/SuperMarioYL/tainttrace" alt="Release"></a>
  <a href="https://github.com/SuperMarioYL/tainttrace/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/SuperMarioYL/tainttrace/ci.yml?branch=main&label=ci" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.12-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Prompt%20Injection-blast%20radius-E5484D.svg" alt="Prompt Injection">
  <img src="https://img.shields.io/badge/Agent-taint%20propagation-5E5CE6.svg" alt="Agent">
</p>

**Guardrails block at the boundary; once an injection slips through, you need a propagation model to find every action it tainted — that's TaintTrace.**

When a Prompt Injection or role-confusion exploit lands inside an autonomous Agent, the hard failure verb is *propagation*: a single poisoned token doesn't just produce one bad output, it silently influences a chain of downstream tool calls, file writes, and memory updates. Today a security engineer who knows an injection happened has no mechanical way to answer "which of the last 200 agent actions did it taint?" — they read logs by hand and guess. TaintTrace imports **dynamic taint tracking** from security dataflow analysis into the agent runtime: every untrusted token (web content, tool output) carries a taint label that propagates through the tool-call graph, so after the fact you can identify and quarantine every action it influenced. It is the exact mental model the [role-confusion.github.io](https://role-confusion.github.io) writeup (HN 164 pts) pointed at — treating injection as a *trust-propagation* problem, not a string-filtering one — made mechanical.

## Table of contents

- [Architecture](#architecture)
- [Install](#install)
- [Quickstart](#quickstart)
- [Usage](#usage)
- [Demo](#demo)
- [Why this exists](#why-this-exists)
- [vs Ponytrail](#vs-ponytrail)
- [Roadmap](#roadmap)
- [License](#license)

<h2 id="architecture"><img src="https://api.iconify.design/tabler:topology-star-3.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Architecture</h2>

One Python library + one CLI. No services, no database. At runtime you mark untrusted content at the boundary with `taint_source()` and record each tool call with `@tracked`; afterwards the CLI rebuilds the tool-call graph from `run.jsonl`, runs propagation, and prints the quarantine list.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./assets/atlas-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="./assets/atlas-light.svg">
  <img src="./assets/atlas-light.svg" width="880" alt="Architecture: untrusted web content → @tracked tools → taint labels → tool-call graph → blast radius / quarantine list">
</picture>

| Module | Responsibility |
|---|---|
| `label.py` | Taint label / set + the union propagation primitive |
| `wrap.py` | `@tracked` decorator + `taint_source()` boundary helper |
| `graph.py` | Rebuild the tool-call graph + topological propagation |
| `quarantine.py` | Transitive closure + side-effect classification → blast radius |
| `tracker.py` | Top-level facade: record a JSONL trace, compute the blast radius |
| `cli.py` | `report` / `demo` commands (typer + rich) |

<h2 id="install"><img src="https://api.iconify.design/tabler:rocket.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Install</h2>

```bash
git clone https://github.com/SuperMarioYL/tainttrace.git
cd tainttrace
pip install -e ".[dev]"        # or: uv pip install -e ".[dev]"
```

<h2 id="quickstart"><img src="https://api.iconify.design/tabler:player-play.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Quickstart</h2>

From a cold clone to the red quarantine list in three commands:

```bash
python examples/poisoned_web_demo.py        # run a poisoned web fetch end to end
tainttrace report --trace run.jsonl --graph # render the tool graph + quarantine list
tainttrace report --trace run.jsonl --json  # machine-readable blast radius (CI / tooling)
```

<details><summary>sample output</summary>

```
╭────────────────────────────────────────────────────────────────╮
│ 4 of 11 actions tainted  ·  2 to quarantine  ·  7 proven clean │
╰────────────────────────────────────────────────────────────────╯
Untrusted sources: web:cve-blog

      Quarantine list — side-effecting actions to roll back
 #  call id        tool         hops  tainted by     why
 1  write_file-7   write_file       0  web:cve-blog   poisoned web page (prompt injection)
 2  git_commit-9   git_commit       0  web:cve-blog   poisoned web page (prompt injection)
```

</details>

<h2 id="usage"><img src="https://api.iconify.design/tabler:terminal-2.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Usage</h2>

Wiring TaintTrace into an existing agent is two steps: add `@tracked` to each tool, and wrap untrusted content in `taint_source()` where it enters.

```python
from tainttrace import Tracker, tracked, taint_source

tracker = Tracker(path="run.jsonl").activate()

@tracked                       # read-only tool, side-effect inferred as False
def web_fetch(url): ...

@tracked(side_effect=True)     # a write is a side effect → eligible for quarantine
def write_file(path, body): ...

# mark untrusted content at the boundary
page = taint_source(web_fetch(url), source_id="web:blog", reason="fetched page")
write_file("notes.md", summarize(page))   # taint propagates along data deps to this write

report = tracker.blast_radius()
print(report.headline())       # "4 of 11 actions tainted, 7 proven clean"
```

Common commands and APIs:

- `tainttrace report --trace run.jsonl` — render the red quarantine list.
- `tainttrace report --trace run.jsonl --json` — emit the blast-radius JSON (exit code 1 when the quarantine set is non-empty, so it gates CI).
- `tainttrace demo` — run the bundled poisoned-web scenario, no files needed.
- `Tracker.quarantine_from_source(source_id)` — scope the blast radius to one named injection source.

See the full worked example in [`examples/poisoned_web_demo.py`](./examples/poisoned_web_demo.py).

<h2 id="demo"><img src="https://api.iconify.design/tabler:photo.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Demo</h2>

Inject a poisoned web result → watch the taint label propagate through the tool-call graph → see the red quarantine list light up (4 of 11 actions tainted, 7 proven clean).

![demo](assets/demo.gif)

<h2 id="why-this-exists"><img src="https://api.iconify.design/tabler:bulb.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Why this exists</h2>

Guardrails and input filters do one thing: block suspicious input at the boundary. They are stateless and boundary-local — no propagation model — so the instant something slips through they offer nothing for the post-breach question. Audit logs (like Ponytrail) record *what happened* but log trusted-origin and injection-origin actions as one undifferentiated stream, so you cannot separate them after the fact. TaintTrace closes exactly that gap: attach a trust label at each datum's *source* and carry it forward through the tool graph, so once an injection lands, blast-radius computation goes from manual archaeology to a deterministic query — return the exact set of actions to roll back.

<h2 id="vs-ponytrail">vs Ponytrail</h2>

[Ponytrail](https://github.com/0xroylee/ponytrail) is the closest adjacent project — a local audit trail for agent edits. The two are complementary, and honestly Ponytrail is the smoother tool for a human-readable timeline.

| Capability | TaintTrace | Ponytrail |
|---|:---:|:---:|
| Records the sequence of agent actions | ✓ | ✓ |
| Distinguishes trusted vs injection origin | ✓ | — |
| Taint propagation across the tool graph | ✓ | — |
| Computes an injection's transitive blast radius | ✓ | — |
| Ready-made human-readable edit-timeline UI | partial | ✓ |

<h2 id="roadmap"><img src="https://api.iconify.design/tabler:map-2.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> Roadmap</h2>

- [x] **m1** — taint labels attach to untrusted inputs and propagate through the recorded tool graph
- [x] **m2** — given an incident, compute the transitive set of tainted actions and emit a quarantine report
- [x] **m3** — drop-in wrapper + sub-60s poisoned-web example producing a red quarantine list
- [ ] Auto-instrumentation of popular agent frameworks (LangChain / LlamaIndex tool-call layer)
- [ ] Multi-agent fleet attribution + cross-session diff
- [ ] Incident-review dashboard (taint-graph visualization)

<h2 id="license"><img src="https://api.iconify.design/tabler:license.svg?color=%230071E3&width=24" height="22" align="absmiddle" alt=""> License</h2>

MIT, fully open source — no paywall, no hosted tier. File an issue (a real attached trace is gold) on the [issue tracker](https://github.com/SuperMarioYL/tainttrace/issues), or open a PR.

## Share this

```
TaintTrace — compute a Prompt Injection's blast radius across your Agent's tool graph. Drop in @tracked + taint_source(), replay the trace, get a red quarantine list. MIT, OSS. https://github.com/SuperMarioYL/tainttrace
```

<p align="center"><sub><a href="./LICENSE">MIT</a> © 2026 SuperMarioYL</sub></p>
