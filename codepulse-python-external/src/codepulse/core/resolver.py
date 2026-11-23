"""Target → eligible files. The classification gate runs before any content is read."""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from codepulse.core.config import Config
from codepulse.core.errors import SourceReadError
from codepulse.core.globs import compile_globs
from codepulse.core.model import SkipReason, SkipRecord
from codepulse.core.ports import ClassificationPort, LineRange, SourcePort

GENERATED_MARKER_LINES = 5
# Tool-config files E15 inspects for blanket disables, matched by basename.
TOOL_CONFIG_NAMES = frozenset(
    {
        "pyproject.toml",
        "setup.cfg",
        "tox.ini",
        ".flake8",
        "mypy.ini",
        ".mypy.ini",
        "ruff.toml",
        ".ruff.toml",
        "pylintrc",
        ".pylintrc",
    }
)


class FileKind(StrEnum):
    PYTHON = "python"
    TOOL_CONFIG = "tool_config"
    EXTERNAL = "external"


class TargetKind(StrEnum):
    BRANCH = "branch"
    ALL = "all"
    FILES = "files"


@dataclass(frozen=True, slots=True)
class Target:
    kind: TargetKind
    head: str | None = None
    base: str | None = None  # None → Config.base_ref
    files: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind is TargetKind.BRANCH and not self.head:
            raise ValueError("branch target needs a head ref")
        if self.kind is TargetKind.FILES and not self.files:
            raise ValueError("file-list target needs at least one path")

    @classmethod
    def branch(cls, head: str, base: str | None) -> "Target":
        return cls(TargetKind.BRANCH, head=head, base=base)

    @classmethod
    def all(cls) -> "Target":
        return cls(TargetKind.ALL)

    @classmethod
    def file_list(cls, files: Iterable[str]) -> "Target":
        return cls(TargetKind.FILES, files=tuple(dict.fromkeys(files)))


@dataclass(frozen=True, slots=True)
class ResolvedFile:
    path: str
    text: str
    changed: tuple[LineRange, ...] | None  # None when the run is not diff-scoped
    kind: FileKind = FileKind.PYTHON


@dataclass(frozen=True, slots=True)
class Resolution:
    files: tuple[ResolvedFile, ...]
    skipped: tuple[SkipRecord, ...]


class Resolver:
    def __init__(self, source: SourcePort, classifier: ClassificationPort, config: Config, external_rules=()) -> None:
        self._source = source
        self._classifier = classifier
        self._config = config
        self._excluded = compile_globs(config.exclude)
        self._external_rules = tuple(external_rules)

    def resolve(self, target: Target) -> Resolution:
        ref = target.head  # set only for branch targets (enforced by Target)
        candidates: dict[str, tuple[LineRange, ...] | None]
        if ref is not None:
            base = target.base or self._config.base_ref
            candidates = {c.path: c.ranges for c in self._source.changed_files(base, ref)}
        elif target.kind is TargetKind.ALL:
            candidates = dict.fromkeys(self._source.tracked_files())
        else:
            candidates = dict.fromkeys(target.files)

        files: list[ResolvedFile] = []
        skipped: list[SkipRecord] = []
        for path in sorted(candidates):
            outcome = self._admit(path, ref)
            if isinstance(outcome, SkipRecord):
                skipped.append(outcome)
            else:
                text, kind = outcome
                files.append(ResolvedFile(path, text, candidates[path], kind))
        return Resolution(tuple(files), tuple(skipped))

    def index_files(
        self, target: Target, resolution: Resolution
    ) -> tuple[list[tuple[str, str]], int]:
        """Python files for the project index: every tracked file that passes the same gate
        as review targets, at the reviewed revision (spec 005 FR-501/502). Target files
        reuse the text already read. Returns (files, count not admitted)."""
        ref = target.head
        have = {f.path: f.text for f in resolution.files if f.kind is FileKind.PYTHON}
        out: list[tuple[str, str]] = []
        refused = 0
        for path in self._source.tracked_files(ref):
            if not path.endswith(".py"):
                continue
            if path in have:
                out.append((path, have[path]))
                continue
            outcome = self._admit(path, ref)
            if isinstance(outcome, SkipRecord):
                refused += 1
            else:
                out.append((path, outcome[0]))
        return out, refused

    def _external_eligible(self, path: str) -> bool:
        from codepulse.external_rules.matcher import applies, language_for

        language = language_for(path)
        return language is not None and any(applies(r, path, language) for r in self._external_rules)

    def _admit(self, path: str, ref: str | None) -> tuple[str, FileKind] | SkipRecord:
        """(text, kind) if eligible, else the reason it was skipped. Order matters: every
        check before ``read_text`` uses the path alone."""
        name = path.rsplit("/", 1)[-1]
        script = False  # an extensionless file: Python only if its shebang says so
        if path.endswith(".py"):
            kind = FileKind.PYTHON
        elif self._external_rules and self._external_eligible(path):
            kind = FileKind.EXTERNAL
        elif name in TOOL_CONFIG_NAMES:
            kind = FileKind.TOOL_CONFIG
        elif "." not in name:
            kind, script = FileKind.PYTHON, True
        else:
            return SkipRecord(path, SkipReason.NOT_PYTHON)

        cls = self._config.classification
        level = self._classifier.level_of(path)
        if cls.rank(level) > cls.rank(cls.max_allowed):
            return SkipRecord(
                path,
                SkipReason.CLASSIFICATION_ABOVE_LIMIT,
                f"level {level} > max_allowed {cls.max_allowed}",
            )

        if (pattern := self._excluded(path)) is not None:
            return SkipRecord(path, SkipReason.EXCLUDED_PATTERN, f"pattern {pattern}")

        try:
            text = self._source.read_text(path, ref)
        except SourceReadError as exc:
            if script:
                return SkipRecord(path, SkipReason.NOT_PYTHON, "no extension, not text")
            return SkipRecord(path, SkipReason.UNREADABLE, str(exc))
        if script and not _python_shebang(text):
            return SkipRecord(path, SkipReason.NOT_PYTHON, "no extension, no python shebang")

        if kind is FileKind.PYTHON:
            header = "\n".join(text.splitlines()[:GENERATED_MARKER_LINES])
            for marker in self._config.generated_markers:
                if marker in header:
                    return SkipRecord(
                        path, SkipReason.EXCLUDED_PATTERN, f"generated marker {marker!r}"
                    )
        return text, kind


def _python_shebang(text: str) -> bool:
    """`#!/usr/bin/env python3` and the like: an extensionless script that is Python."""
    first = text.split("\n", 1)[0]
    return first.startswith("#!") and "python" in first
