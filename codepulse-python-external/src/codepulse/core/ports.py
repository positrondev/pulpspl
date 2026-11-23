"""I/O boundaries of the core (Constitution Art. IV). Adapters implement these."""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

LineRange = tuple[int, int]  # inclusive, 1-based


@dataclass(frozen=True, slots=True)
class ChangedFile:
    path: str  # repo-relative POSIX path on the reviewed ref
    ranges: tuple[LineRange, ...]  # lines added or modified; empty for rename-only


class SourcePort(Protocol):
    def changed_files(self, base: str, head: str) -> Sequence[ChangedFile]:
        """Files added/modified/renamed on ``head`` since its merge-base with ``base``."""
        ...

    def tracked_files(self, ref: str | None = None) -> Sequence[str]:
        """All tracked files, sorted: at ``ref`` when given, else in the working tree."""
        ...

    def read_text(self, path: str, ref: str | None) -> str:
        """File content at ``ref``, or the working tree when ``ref`` is None.

        Raises SourceReadError when the file is missing, outside the repo, or not UTF-8.
        """
        ...


class ClassificationPort(Protocol):
    def level_of(self, path: str) -> str:
        """Classification level name for a path. Must not read file content."""
        ...
