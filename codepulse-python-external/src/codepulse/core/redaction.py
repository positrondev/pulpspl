"""Redaction applied before any candidate is hashed, cached, or sent (Constitution Art. VII.3)."""

import math
import re
from collections import Counter
from collections.abc import Iterable

_BUILTIN: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("url-credentials", re.compile(r"(?<=://)[^\s/:@'\"]+:[^\s/@'\"]+(?=@)")),
    (
        "token",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{30,}"
            r"|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}"
            r"|AIza[0-9A-Za-z_-]{30,})"
        ),
    ),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)
_QUOTED = re.compile(r"""(["'])([A-Za-z0-9+/=_\-]{24,})\1""")
_ENTROPY_THRESHOLD = 4.5


def _entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def redact(text: str, extra_patterns: Iterable[str] = ()) -> tuple[str, dict[str, int]]:
    """Return (redacted text, count per kind). Deterministic for a given input."""
    counts: Counter[str] = Counter()

    def sub(kind: str, rx: re.Pattern[str], s: str) -> str:
        def repl(m: re.Match[str]) -> str:
            counts[kind] += 1
            return f"<REDACTED:{kind}>"

        return rx.sub(repl, s)

    for kind, rx in _BUILTIN:
        text = sub(kind, rx, text)

    def high_entropy(m: re.Match[str]) -> str:
        if _entropy(m[2]) >= _ENTROPY_THRESHOLD:
            counts["high-entropy"] += 1
            return f"{m[1]}<REDACTED:high-entropy>{m[1]}"
        return m[0]

    text = _QUOTED.sub(high_entropy, text)
    for i, pattern in enumerate(extra_patterns):
        text = sub(f"custom-{i}", re.compile(pattern), text)
    return text, dict(sorted(counts.items()))
