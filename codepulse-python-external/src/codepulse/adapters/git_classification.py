"""Classification from git attributes (spec 009 FR-905, docs/classification.md).

`.gitattributes` lines such as ``secrets/** classification=restricted`` label files the way
the repository already labels line endings and diff drivers: versioned, reviewed in PRs,
and per path. ``git check-attr`` reads only attribute files, never file content, so the
gate still decides before anything is opened (Constitution Art. VII).
"""

import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

from codepulse.core.errors import SourceError
from codepulse.core.ports import ClassificationPort

_UNSET = frozenset({"unspecified", "unset", "set"})  # no level named
TIMEOUT_S = 60


class GitAttributesClassification:
    def __init__(
        self,
        repo: Path,
        attribute: str,
        paths: Sequence[str],
        fallback: ClassificationPort,
        ref: str | None = None,
    ) -> None:
        self._levels = _check_attr(repo, attribute, paths, ref)
        self._fallback = fallback

    def level_of(self, path: str) -> str:
        return self._levels.get(path) or self._fallback.level_of(path)


def _check_attr(
    repo: Path, attribute: str, paths: Sequence[str], ref: str | None
) -> dict[str, str]:
    """One batched `git check-attr` for every path (at ``ref``'s .gitattributes if given)."""
    git = shutil.which("git")
    if git is None:
        raise SourceError("git is not installed; classification.source needs it")
    if not paths:
        return {}
    args = [git, "check-attr", "-z", "--stdin"]
    if ref:
        args += ["--source", ref]
    args.append(attribute)
    try:
        out = subprocess.run(  # noqa: S603 — fixed binary, argv list, no shell
            args,
            cwd=repo,
            input="\0".join(paths) + "\0",
            capture_output=True,
            text=True,
            check=True,
            timeout=TIMEOUT_S,
        ).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        raise SourceError(f"git check-attr failed: {exc}") from exc
    fields = out.split("\0")
    levels: dict[str, str] = {}
    for i in range(0, len(fields) - 2, 3):
        path, _, value = fields[i], fields[i + 1], fields[i + 2]
        if value not in _UNSET:
            levels[path] = value
    return levels
