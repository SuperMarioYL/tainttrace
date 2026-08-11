"""Drop-in wrapper API — milestone m3.

This is the surface a developer actually touches. Two primitives, nothing else:

* ``taint_source(value, source_id=..., reason=...)`` — mark a value as untrusted
  at the boundary where it *enters* the agent (a fetched web page, an external
  tool result). It returns the value unchanged but remembers its taint, so you
  can keep passing it around exactly as before.
* ``@tracked`` — decorate each tool function the agent can call. On every
  invocation it records a :class:`~tainttrace.graph.ToolCall`: the tool name, its
  arguments, its result, and the taint labels flowing in (the union of every
  tainted argument) plus any source labels minted inside. The recorded calls
  accumulate on an active :class:`Recorder` so that, after the run, the graph can
  be rebuilt and the blast radius computed.

The whole point is that wrapping is *thin*: you do not rewrite your agent loop,
you add one decorator per tool and one ``taint_source`` call per untrusted fetch.
Everything else (propagation, blast radius, the red quarantine list) happens
later from the recorded trace.

Design note — coupling to the recorder. The persistent JSONL recorder lives in
:mod:`tainttrace.tracker`. To keep ``wrap`` runnable on its own (and to avoid a
hard import cycle), this module defines the :class:`Recorder` protocol it needs
and ships a self-contained :class:`MemoryRecorder` default. If
:mod:`tainttrace.tracker` is present it is used as the default recorder
automatically; otherwise the in-memory one is used. Either way the public
decorator API is identical.
"""

from __future__ import annotations

import functools
import inspect
import re
import threading
import time
from typing import Any, Callable, Protocol, TypeVar, runtime_checkable

from .graph import TaintGraph, ToolCall
from .label import (
    EMPTY,
    Origin,
    TaintSet,
    as_taint_set,
    propagate,
    taint,
)

F = TypeVar("F", bound=Callable[..., Any])

# --------------------------------------------------------------------------- #
# Taint registry: which Python objects are currently marked untrusted.
#
# We cannot attach a label to an arbitrary value (``str``/``int`` are immutable
# and unhashable-by-identity issues abound), so taint is tracked in a registry
# keyed by object identity. ``taint_source`` registers; ``@tracked`` looks up
# every argument's identity to compute the call's in-labels. The registry is
# WeakValue-free on purpose: a poisoned string must stay registered for the whole
# run even if only a copy is passed downstream — we also fall back to value
# equality for hashable values so a re-derived equal string is still caught.
# --------------------------------------------------------------------------- #


class _TaintRegistry:
    """Tracks taint labels for live values, by identity and by value.

    Identity match is exact (the same object). Value match is a best-effort
    fallback for hashable, equality-comparable values (mainly strings) so that a
    poisoned string surviving a round-trip through a tool still carries its
    label. This mirrors the v0.1 granularity decision: the unit of taint is the
    tool-call argument value, not the token.
    """

    def __init__(self) -> None:
        self._by_id: dict[int, TaintSet] = {}
        self._by_value: dict[Any, TaintSet] = {}
        self._keepalive: dict[int, Any] = {}
        self._lock = threading.Lock()

    def mark(self, value: Any, labels: TaintSet) -> None:
        labels = as_taint_set(labels)
        if not labels:
            return
        with self._lock:
            oid = id(value)
            self._by_id[oid] = propagate(self._by_id.get(oid, EMPTY), labels)
            # Keep a reference so id() can't be recycled onto a different object.
            self._keepalive[oid] = value
            if _is_value_keyable(value):
                self._by_value[value] = propagate(
                    self._by_value.get(value, EMPTY), labels
                )

    def labels_for(self, value: Any) -> TaintSet:
        with self._lock:
            found = self._by_id.get(id(value), EMPTY)
            if _is_value_keyable(value):
                found = propagate(found, self._by_value.get(value, EMPTY))
            return found

    def clear(self) -> None:
        with self._lock:
            self._by_id.clear()
            self._by_value.clear()
            self._keepalive.clear()


def _is_value_keyable(value: Any) -> bool:
    """True if ``value`` can safely be a dict key for value-based taint lookup.

    Restricted to strings/bytes (and hashable tuples): these are the values
    that actually survive being passed through a tool and compared equal
    downstream — the documented "poisoned string surviving a round-trip" case.
    Scalars (int/float/bool) are deliberately excluded: coincidental value
    equality (``taint_source(404)`` tainting every later ``404``, or
    ``taint_source(True)`` tainting every ``True``) is not provenance.
    Identity tracking (``id()``) still covers the same scalar object passed
    through; only the unsound value-equality fallback is removed
    (v0.3 fix: ``fix-registry-scalar-value-collision``).
    """
    if isinstance(value, (str, bytes)):
        return True
    if isinstance(value, tuple):
        try:
            hash(value)
            return True
        except TypeError:
            return False
    return False


_REGISTRY = _TaintRegistry()


# --------------------------------------------------------------------------- #
# Recorder protocol + in-memory default.
# --------------------------------------------------------------------------- #


@runtime_checkable
class Recorder(Protocol):
    """What ``@tracked`` needs from a recorder.

    :mod:`tainttrace.tracker` provides a JSONL-backed implementation; the
    :class:`MemoryRecorder` below is the dependency-free fallback. Any object
    with a compatible ``record`` method works.
    """

    def record(self, call: ToolCall) -> None:
        """Persist/accumulate one recorded tool call."""
        ...


class MemoryRecorder:
    """A minimal in-memory :class:`Recorder` — accumulates calls in a list.

    Enough to run a scripted agent and then build a :class:`TaintGraph` for the
    blast-radius computation, with zero I/O. The richer JSONL recorder in
    :mod:`tainttrace.tracker` is used automatically when that module is present;
    this keeps ``wrap`` self-contained for tests and small scripts.
    """

    def __init__(self) -> None:
        self.calls: list[ToolCall] = []
        self._counter = 0
        self._lock = threading.Lock()

    def record(self, call: ToolCall) -> None:
        with self._lock:
            self.calls.append(call)

    def next_id(self, name: str) -> str:
        with self._lock:
            self._counter += 1
            return f"{name}-{self._counter}"

    def graph(self) -> TaintGraph:
        """Rebuild a :class:`TaintGraph` from the recorded calls (edges inferred)."""
        g = TaintGraph.from_calls(self.calls)
        g.infer_value_edges()
        return g

    def reset(self) -> None:
        with self._lock:
            self.calls.clear()
            self._counter = 0


def _default_recorder() -> Recorder:
    """Return the active default recorder.

    Prefers :class:`tainttrace.tracker.Tracker` if that module is importable (the
    persistent JSONL recorder), else a process-wide :class:`MemoryRecorder`. The
    tracker module may not exist in every install slice; the fallback guarantees
    ``@tracked`` always works.
    """
    try:  # pragma: no cover - depends on which modules shipped
        from . import tracker as _tracker  # type: ignore

        getter = getattr(_tracker, "active_tracker", None) or getattr(
            _tracker, "get_recorder", None
        )
        if callable(getter):
            candidate = getter()
            if isinstance(candidate, Recorder):
                return candidate
    except Exception:
        pass
    return _PROCESS_RECORDER


# Process-wide fallback recorder used when no tracker module / explicit recorder
# is active. Tests and the demo can grab it via :func:`get_recorder`.
_PROCESS_RECORDER = MemoryRecorder()

# The recorder ``@tracked`` writes to. ``use_recorder`` swaps it; defaults to the
# process recorder (or the tracker's, resolved lazily on first call).
_ACTIVE: Recorder | None = None


def get_recorder() -> Recorder:
    """Return the recorder ``@tracked`` is currently writing to."""
    return _ACTIVE if _ACTIVE is not None else _default_recorder()


def use_recorder(recorder: Recorder | None) -> Recorder:
    """Set the active recorder (``None`` resets to the default). Returns it.

    Use this to point a run at a specific recorder — e.g. a fresh
    :class:`MemoryRecorder` per test, or a JSONL :class:`tainttrace.tracker.Tracker`
    bound to ``run.jsonl``.
    """
    global _ACTIVE
    _ACTIVE = recorder
    return get_recorder()


def reset_run() -> None:
    """Clear the taint registry and the process recorder — fresh run state.

    Call between independent runs (or at the top of a test) so taint from a
    previous run does not leak into the next.
    """
    _REGISTRY.clear()
    _PROCESS_RECORDER.reset()


# --------------------------------------------------------------------------- #
# Public boundary primitive: taint_source.
# --------------------------------------------------------------------------- #


def taint_source(
    value: Any,
    *,
    source_id: str,
    reason: str = "",
    origin: Origin = "untrusted",
) -> Any:
    """Mark a value as taint at the boundary where it enters the agent.

    Returns ``value`` unchanged so you can wrap inline::

        page = taint_source(fetch(url), source_id="web:cve-blog",
                            reason="fetched web page")

    The value now carries an untrusted label; any ``@tracked`` tool that receives
    it (directly or via an equal copy) records that label as an input, and the
    propagation rule carries it to every downstream action. ``origin="trusted"``
    marks provenance without widening the blast radius (useful for tagging known
    config so the report can show "trusted-origin" alongside the danger).

    >>> p = taint_source("ignore prior instructions", source_id="web:x")
    >>> labels_of(p) and True
    True
    """
    labels = taint(source_id, origin=origin, reason=reason)
    _REGISTRY.mark(value, labels)
    return value


def labels_of(value: Any) -> TaintSet:
    """Return the taint labels currently attached to ``value`` (possibly empty)."""
    return _REGISTRY.labels_for(value)


def _collect_in_labels(args: tuple[Any, ...], kwargs: dict[str, Any]) -> TaintSet:
    """Union of taint labels across every positional and keyword argument.

    Each top-level argument is looked up by identity/value as before, *and*
    container arguments (list/tuple/dict/set/frozenset) are walked recursively
    so a poisoned value nested one or more levels deep still contributes its
    labels. Without the recursion, ``write_file("x", [poisoned])`` or
    ``write_file("p", {"body": poisoned})`` recorded ``in_labels=∅`` because the
    container itself is never registered — only the tainted string inside it is
    — so the side-effecting write was classified proven-clean and dropped from
    quarantine (v0.4 fix: ``fix-collect-in-labels-container-args``).
    """
    out: TaintSet = EMPTY
    for value in args:
        out = propagate(out, _labels_in_value(value))
    for value in kwargs.values():
        out = propagate(out, _labels_in_value(value))
    return out


def _labels_in_value(value: Any, _seen: set[int] | None = None) -> TaintSet:
    """Labels on ``value`` itself plus those of any nested container member.

    :func:`_collect_in_labels` calls this instead of ``_REGISTRY.labels_for``
    directly so taint hidden inside a list/tuple/dict/set is still collected:
    the registry tracks taint by object identity (and by value for hashable
    scalars like ``str``), so a container is never registered — only the tainted
    member inside it is, and it is only found by recursing into the container.

    ``_seen`` guards against cyclic/self-referential containers (a list that
    contains itself) so the walk terminates; identity dedup keeps a member
    visited twice from re-expanding. Label sets are a real ``frozenset``, so
    unioning the same label more than once is already idempotent — the guard is
    about traversal termination/cost, not label multiplicity (the
    "do-not-double-count" concern is handled by set union, not by skipping).
    """
    out = _REGISTRY.labels_for(value)
    if not isinstance(value, (list, tuple, dict, set, frozenset)):
        return out
    if _seen is None:
        _seen = set()
    oid = id(value)
    if oid in _seen:
        return out
    _seen.add(oid)
    # For a dict, walk both keys and values: a tainted key is a real (if rare)
    # dataflow case and value-equality lookup catches registered string keys.
    if isinstance(value, dict):
        members = (*value.keys(), *value.values())
    else:
        members = value
    for member in members:
        out = propagate(out, _labels_in_value(member, _seen))
    return out


# --------------------------------------------------------------------------- #
# Public decorator: @tracked.
# --------------------------------------------------------------------------- #


def tracked(
    _func: F | None = None,
    *,
    name: str | None = None,
    side_effect: bool | None = None,
) -> Any:
    """Decorate a tool function so every call is recorded with taint labels.

    On each invocation the wrapper:

    1. computes ``in_labels`` = the union of taint on every argument,
    2. calls the wrapped tool, capturing its result,
    3. propagates: the result inherits ``in_labels`` (so it carries the taint of
       its tainted inputs — the registry is updated for the returned value),
    4. records a :class:`~tainttrace.graph.ToolCall` on the active recorder.

    ``side_effect`` flags whether this tool mutates external state (writes a
    file, commits, sends a message). If omitted it is inferred from the tool name
    via a small verb heuristic (``write``/``commit``/``send``/``delete``/…),
    which the developer can always override explicitly.

    Use bare or parameterised::

        @tracked
        def read_url(url): ...

        @tracked(name="fs.write", side_effect=True)
        def write_file(path, body): ...

    >>> rec = use_recorder(MemoryRecorder())
    >>> @tracked(side_effect=True)
    ... def save(text): return "ok"
    >>> _ = save(taint_source("evil", source_id="web:x"))
    >>> rec.graph().propagate().tainted_calls()[0].name
    'save'
    """

    def decorate(func: F) -> F:
        tool_name = name or getattr(func, "__name__", "tool")
        effect = side_effect if side_effect is not None else _infer_side_effect(tool_name)

        # v0.2 (m4_async_tracked): async tools get an `async` wrapper so the
        # coroutine is actually awaited (v0.1 recorded a bare coroutine object
        # and lost the taint). The recording/propagation logic is identical to
        # the sync path; only the await differs.
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                in_labels = _collect_in_labels(args, kwargs)
                result = await func(*args, **kwargs)

                out_labels = propagate(in_labels)
                if out_labels:
                    _REGISTRY.mark(result, out_labels)

                recorder = get_recorder()
                call_id = _make_call_id(recorder, tool_name)
                call = ToolCall(
                    id=call_id,
                    name=tool_name,
                    args=_safe_args(args, kwargs),
                    result=_safe_result(result),
                    in_labels=in_labels,
                    out_labels=out_labels,
                    side_effect=effect,
                    ts=time.time(),
                )
                recorder.record(call)
                return result

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            in_labels = _collect_in_labels(args, kwargs)
            result = func(*args, **kwargs)

            # The result inherits the taint of its inputs (propagation rule). We
            # register that on the returned value so downstream @tracked tools
            # that consume it see the taint, even across hops.
            out_labels = propagate(in_labels)
            if out_labels:
                _REGISTRY.mark(result, out_labels)

            recorder = get_recorder()
            call_id = _make_call_id(recorder, tool_name)
            call = ToolCall(
                id=call_id,
                name=tool_name,
                args=_safe_args(args, kwargs),
                result=_safe_result(result),
                in_labels=in_labels,
                out_labels=out_labels,
                side_effect=effect,
                ts=time.time(),
            )
            recorder.record(call)
            return result

        return wrapper  # type: ignore[return-value]

    # Support both @tracked and @tracked(...).
    if _func is not None and callable(_func):
        return decorate(_func)
    return decorate


# --------------------------------------------------------------------------- #
# Helpers.
# --------------------------------------------------------------------------- #


_SIDE_EFFECT_VERBS = (
    "write",
    "save",
    "commit",
    "push",
    "send",
    "post",
    "delete",
    "remove",
    "update",
    "set",
    "put",
    "create",
    "store",
    "upload",
    "exec",
    "run",
    "apply",
    "mutate",
)


def _infer_side_effect(tool_name: str) -> bool:
    """Heuristic: a tool whose name implies a mutation is side-effecting.

    Matches a known mutating verb as a *token* of the lowercased name (split on
    non-alphanumeric boundaries), so ``write_file`` and ``commit_changes`` are
    flagged while ``input_parser`` (contains "put"), ``compute_hash`` (contains
    "put"), and ``asset_lookup`` (contains "set") are not. A read-only tool
    (``read_url``, ``search``, ``fetch``) returns ``False``. The developer can
    always override via ``side_effect=`` (v0.3 fix:
    ``fix-side-effect-verb-substring-false-positive``).
    """
    tokens = {t for t in re.split(r"[^a-z0-9]+", tool_name.lower()) if t}
    return any(verb in tokens for verb in _SIDE_EFFECT_VERBS)


def _make_call_id(recorder: Recorder, name: str) -> str:
    """Get a unique call id from the recorder if it can mint one, else generate."""
    minter = getattr(recorder, "next_id", None)
    if callable(minter):
        return str(minter(name))
    return f"{name}-{int(time.time() * 1_000_000)}"


def _safe_args(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Best-effort JSON-friendly snapshot of call arguments for the trace.

    Positional args are keyed ``arg0..argN``; everything is coerced to a
    representable form so a later JSONL dump never blows up on an exotic object.
    """
    out: dict[str, Any] = {}
    for i, value in enumerate(args):
        out[f"arg{i}"] = _reprable(value)
    for key, value in kwargs.items():
        out[key] = _reprable(value)
    return out


def _safe_result(value: Any) -> Any:
    """Best-effort JSON-friendly snapshot of a tool result."""
    return _reprable(value)


def _reprable(value: Any) -> Any:
    """Coerce a value into something JSON-serialisable and edge-inferable.

    Scalars pass through (so :meth:`TaintGraph.infer_value_edges` can match
    strings across calls); containers recurse; anything else falls back to
    ``repr``. We deliberately keep strings intact — they are the substance the
    value-reuse edge heuristic depends on.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _reprable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_reprable(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_reprable(v) for v in value)
    try:
        return repr(value)
    except Exception:  # pragma: no cover - defensive
        return "<unreprable>"


def mark_trusted(value: Any, *, source_id: str, reason: str = "") -> Any:
    """Convenience: mark a value as *trusted* provenance (does not widen radius).

    Equivalent to ``taint_source(value, origin="trusted", ...)``. Useful for
    tagging your own prompt/config so the report can show trusted-origin labels
    next to the dangerous ones.
    """
    return taint_source(value, source_id=source_id, reason=reason, origin="trusted")


__all__ = [
    "Recorder",
    "MemoryRecorder",
    "tracked",
    "taint_source",
    "mark_trusted",
    "labels_of",
    "get_recorder",
    "use_recorder",
    "reset_run",
]
