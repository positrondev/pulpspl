"""Stable finding identity (Constitution Art. IX). Line numbers never participate."""

import hashlib
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

_SEP = "\x1f"  # unit separator: cannot appear in paths or identifiers
FINGERPRINT_LEN = 24


def fingerprint(subcheck_id: str, path: str, scope: str, signature: str, ordinal: int) -> str:
    payload = _SEP.join((subcheck_id, path, scope, signature, str(ordinal)))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:FINGERPRINT_LEN]


@dataclass(frozen=True, slots=True)
class FingerprintInput:
    subcheck_id: str
    path: str
    scope: str
    signature: str
    position: tuple[int, int]  # (line, col): source order for ordinals, never hashed


def assign_fingerprints(items: Sequence[FingerprintInput]) -> list[str]:
    """Fingerprint each item; equal (sub-check, path, scope, signature) groups get
    ordinals in source order, so identical constructs in one scope stay distinct.

    Returns fingerprints aligned with ``items``.
    """
    groups: dict[tuple[str, str, str, str], list[int]] = defaultdict(list)
    for idx, it in enumerate(items):
        groups[(it.subcheck_id, it.path, it.scope, it.signature)].append(idx)

    out = [""] * len(items)
    for key, indices in groups.items():
        for ordinal, idx in enumerate(sorted(indices, key=lambda i: items[i].position)):
            out[idx] = fingerprint(*key, ordinal)
    return out
