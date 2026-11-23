"""Canonical JSON — the byte-stable encoding behind Constitution Art. II."""

import json


def canonical_json(value: object) -> str:
    """Sorted keys, fixed indentation, UTF-8 text, trailing newline.

    Python 3 float repr is the shortest round-trip form and platform-independent, so floats
    are safe; NaN/Infinity are not JSON and are rejected.
    """
    return json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
