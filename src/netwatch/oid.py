"""Object identifier parsing, formatting and ordering helpers.

SNMP carries object identifiers as ASN.1 OBJECT IDENTIFIER values. Throughout
this package OIDs are stored as canonical dotted strings (for example
``1.3.6.1.2.1.1.5.0``); this module validates and converts them, and provides
the lexicographic helpers required by GETNEXT and walk operations.
"""

from __future__ import annotations

import re
from typing import Iterable, Sequence, Tuple

__all__ = [
    "OidError",
    "parse_oid",
    "format_oid",
    "normalize_oid",
    "oid_key",
    "compare_oids",
    "is_prefix",
    "is_child_of",
    "child_index",
]

_DOTTED_RE = re.compile(r"\A[0-9]+(?:\.[0-9]+)*\Z")
_MAX_SUBIDENTIFIER = 2**32 - 1


class OidError(ValueError):
    """Raised when an object identifier is syntactically invalid."""


def parse_oid(oid: str) -> Tuple[int, ...]:
    """Parse ``oid`` into a tuple of integer arcs, validating ASN.1 rules.

    The first two arcs are constrained by ASN.1: arc 0 must be 0, 1 or 2 and
    arc 1 must be below 40 when arc 0 is 0 or 1. Sub-identifiers are limited to
    32 bits, which is the BER limit for OID components.
    """

    if not isinstance(oid, str):
        raise OidError(f"OID must be a string, got {type(oid).__name__}")
    text = oid[1:] if oid.startswith(".") else oid
    if not text or not _DOTTED_RE.match(text):
        raise OidError(f"invalid OID {oid!r}")
    arcs = tuple(int(part) for part in text.split("."))
    if len(arcs) < 2:
        raise OidError(f"OID {oid!r} needs at least two arcs")
    if arcs[0] > 2:
        raise OidError(f"OID {oid!r} starts with an invalid first arc")
    if arcs[0] < 2 and arcs[1] >= 40:
        raise OidError(f"OID {oid!r} has an invalid second arc")
    for arc in arcs:
        if arc > _MAX_SUBIDENTIFIER:
            raise OidError(f"OID {oid!r} contains a sub-identifier above 2^32 - 1")
    return arcs


def format_oid(arcs: Iterable[int]) -> str:
    """Return the canonical dotted representation of an arc sequence."""

    return ".".join(str(int(arc)) for arc in arcs)


def normalize_oid(oid: str) -> str:
    """Validate ``oid`` and return its canonical dotted form."""

    return format_oid(parse_oid(oid))


def oid_key(oid: str) -> Tuple[int, ...]:
    """Return the tuple used to order OIDs lexicographically."""

    return parse_oid(oid)


def compare_oids(left: str, right: str) -> int:
    """Compare two OIDs, returning -1, 0 or 1."""

    left_arcs = oid_key(left)
    right_arcs = oid_key(right)
    if left_arcs < right_arcs:
        return -1
    if left_arcs > right_arcs:
        return 1
    return 0


def is_prefix(prefix: str, oid: str) -> bool:
    """Return True when ``prefix`` is an OID prefix of ``oid``.

    A prefix always includes an exact match, which lets callers filter
    identifiers by table subtree (for example all ``ifDescr`` instances).
    """

    prefix_arcs = oid_key(prefix)
    oid_arcs = oid_key(oid)
    return len(oid_arcs) >= len(prefix_arcs) and oid_arcs[: len(prefix_arcs)] == prefix_arcs


def is_child_of(prefix: str, oid: str) -> bool:
    """Return True when ``oid`` is a strict child of ``prefix``."""

    return is_prefix(prefix, oid) and len(oid_key(oid)) > len(oid_key(prefix))


def child_index(prefix: str, oid: str) -> int:
    """Return the single sub-identifier that ``oid`` adds to ``prefix``.

    Raises :class:`OidError` when ``oid`` is not a direct child of ``prefix``.
    This is how table rows are matched to their column base OID.
    """

    prefix_arcs = oid_key(prefix)
    oid_arcs = oid_key(oid)
    if len(oid_arcs) != len(prefix_arcs) + 1 or oid_arcs[: len(prefix_arcs)] != prefix_arcs:
        raise OidError(f"{oid!r} is not a direct child of {prefix!r}")
    return int(oid_arcs[-1])


def sort_oids(oids: Iterable[str]) -> Sequence[str]:
    """Return ``oids`` sorted lexicographically by their arc tuples."""

    return sorted(oids, key=oid_key)
