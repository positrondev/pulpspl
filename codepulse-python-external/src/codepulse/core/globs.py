"""Path globs with ``**`` support. ``fnmatch`` lets ``*`` cross ``/``, which is wrong for paths."""

import re
from collections.abc import Callable, Iterable
from functools import lru_cache


@lru_cache(maxsize=4096)
def glob_to_regex(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("/**", i) and i + 3 == n:
            out.append("(?:/.*)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def compile_globs(patterns: Iterable[str]) -> Callable[[str], str | None]:
    """Return a matcher yielding the first pattern that matches a path, or None.

    Memoized on the pattern set: callers pass the same static tuple on every node, so the
    regexes (and the closure) are built once, not recompiled per call."""
    return _compile_globs(tuple(patterns))


@lru_cache(maxsize=1024)
def _compile_globs(patterns: tuple[str, ...]) -> Callable[[str], str | None]:
    compiled = [(p, glob_to_regex(p)) for p in patterns]

    def match(path: str) -> str | None:
        for pattern, rx in compiled:
            if rx.fullmatch(path):
                return pattern
        return None

    return match
