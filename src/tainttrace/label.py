"""Taint labels and the core propagation primitive.

This module defines the smallest unit of provenance TaintTrace tracks: a
:class:`TaintLabel`. A label says "this value was influenced by a particular
source, and that source is either ``untrusted`` (attacker-controllable, e.g. a
fetched web page) or ``trusted`` (your own prompt, a verified config)".

Values carry a :class:`TaintSet` — an immutable set of labels. The propagation
rule is deliberately simple and monotone: a derived value inherits the *union*
of every input's labels, plus any source labels explicitly attached at its
boundary. That union rule is what lets us replay an agent's tool graph after an
incident and mechanically answer "which actions did the poisoned input touch?".

The granularity is the value (a tool-call argument or result), not the token —
see the v0.1 scope. Nothing here knows about tool calls or graphs; those live in
:mod:`tainttrace.graph`. Keeping the label algebra free of graph concerns means
the same primitive can label a raw string, a dict, or a recorded call.
"""

from __future__ import annotations

from typing import Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field

Origin = Literal["untrusted", "trusted"]
"""Trust origin of a label.

``untrusted`` marks data an attacker could control (web fetches, tool output
from external systems, user-supplied content). ``trusted`` marks data you
authored or verified. Quarantine logic keys off ``untrusted`` labels; trusted
labels are carried for provenance/auditing but never widen the blast radius.
"""


class TaintLabel(BaseModel):
    """A single provenance fact attached to a value.

    Labels are *frozen* and *hashable* so a :class:`TaintSet` can be a real
    ``frozenset`` — set algebra (union, membership, dedup) is the whole point.
    Two labels with the same ``source_id`` and ``origin`` are considered the
    same provenance fact regardless of their human-readable ``reason``, so a
    label re-attached at several hops does not multiply.
    """

    model_config = ConfigDict(frozen=True)

    source_id: str = Field(
        ...,
        min_length=1,
        description="Stable id of the taint source, e.g. 'web_fetch:cve-blog'.",
    )
    origin: Origin = Field(
        default="untrusted",
        description="Whether the source is attacker-controllable or trusted.",
    )
    reason: str = Field(
        default="",
        description="Human-readable note for the report, e.g. 'fetched web page'.",
    )

    # Identity is (source_id, origin) only — `reason` is descriptive metadata and
    # must not split one logical source into two set members.
    def __hash__(self) -> int:  # noqa: D105
        return hash((self.source_id, self.origin))

    def __eq__(self, other: object) -> bool:  # noqa: D105
        if not isinstance(other, TaintLabel):
            return NotImplemented
        return (self.source_id, self.origin) == (other.source_id, other.origin)

    @property
    def is_untrusted(self) -> bool:
        """True if this label marks attacker-controllable provenance."""
        return self.origin == "untrusted"

    def __str__(self) -> str:  # noqa: D105
        tag = "untrusted" if self.origin == "untrusted" else "trusted"
        suffix = f" ({self.reason})" if self.reason else ""
        return f"{self.source_id}:{tag}{suffix}"


# A TaintTag is the public alias for a single label — the noun used in the
# wrapper/tracker API (`taint_source(...) -> TaintTag`). It is the same object;
# the alias just reads better at call sites that attach exactly one tag.
TaintTag = TaintLabel


# An immutable set of labels carried by a value. Modelled as a real frozenset so
# union/membership are O(1) and equality is structural.
TaintSet = frozenset[TaintLabel]

# The canonical empty label set — a value with no known taint (proven clean once
# its inputs are all clean).
EMPTY: TaintSet = frozenset()


def make_label(
    source_id: str,
    *,
    origin: Origin = "untrusted",
    reason: str = "",
) -> TaintLabel:
    """Convenience constructor for a single :class:`TaintLabel`.

    >>> make_label("web_fetch", reason="poisoned page").is_untrusted
    True
    """
    return TaintLabel(source_id=source_id, origin=origin, reason=reason)


def taint(
    source_id: str,
    *,
    origin: Origin = "untrusted",
    reason: str = "",
) -> TaintSet:
    """Build a one-element :class:`TaintSet` for an explicit source.

    This is the boundary primitive: call it where untrusted data *enters* the
    agent (a web fetch, an external tool result) to mint the source label that
    everything downstream will inherit.

    >>> s = taint("web_fetch:blog", reason="fetched page")
    >>> any(l.is_untrusted for l in s)
    True
    """
    return frozenset({make_label(source_id, origin=origin, reason=reason)})


def as_taint_set(labels: Iterable[TaintLabel] | None) -> TaintSet:
    """Coerce any iterable of labels into a :class:`TaintSet`.

    Accepts ``None`` (→ empty), a single set, a list, a generator — anything the
    tracker/graph layers hand us. Idempotent on an existing ``frozenset``.
    """
    if labels is None:
        return EMPTY
    if isinstance(labels, frozenset):
        return labels
    return frozenset(labels)


def propagate(*inputs: Iterable[TaintLabel] | None, sources: Iterable[TaintLabel] | None = None) -> TaintSet:
    """The core propagation rule.

    ``out_labels = union(in_labels...) ∪ explicit_source_labels``

    Given the label sets of every input a value derives from (plus any source
    labels minted right at this value's boundary), return the label set the
    derived value carries. This is the single rule the whole graph propagation
    is built from — monotone (labels only ever accumulate along a dataflow path)
    and order-independent.

    Examples
    --------
    >>> a = taint("web", reason="page")
    >>> b = taint("config", origin="trusted")
    >>> out = propagate(a, b)
    >>> sorted(l.source_id for l in out)
    ['config', 'web']

    A value with no tainted inputs and no source labels is proven clean:

    >>> propagate(EMPTY, EMPTY) == EMPTY
    True
    """
    out: set[TaintLabel] = set()
    for inp in inputs:
        out |= as_taint_set(inp)
    out |= as_taint_set(sources)
    return frozenset(out)


def union(*sets: Iterable[TaintLabel] | None) -> TaintSet:
    """Union of several label sets. Thin wrapper over :func:`propagate`."""
    return propagate(*sets)


def is_tainted(labels: Iterable[TaintLabel] | None) -> bool:
    """True if the value carries at least one ``untrusted`` label.

    A value can carry trusted-only provenance and still be considered clean for
    blast-radius purposes — only untrusted origin widens the radius.
    """
    return any(label.is_untrusted for label in as_taint_set(labels))


def untrusted_labels(labels: Iterable[TaintLabel] | None) -> TaintSet:
    """The subset of ``labels`` whose origin is ``untrusted``."""
    return frozenset(label for label in as_taint_set(labels) if label.is_untrusted)


def source_ids(labels: Iterable[TaintLabel] | None) -> set[str]:
    """The set of distinct ``source_id`` values present in ``labels``."""
    return {label.source_id for label in as_taint_set(labels)}


__all__ = [
    "Origin",
    "TaintLabel",
    "TaintTag",
    "TaintSet",
    "EMPTY",
    "make_label",
    "taint",
    "as_taint_set",
    "propagate",
    "union",
    "is_tainted",
    "untrusted_labels",
    "source_ids",
]
