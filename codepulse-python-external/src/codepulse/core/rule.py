"""The rule plugin API. Built-in and third-party rules use exactly this surface (Art. V).

A sub-check is a pure function ``(node, ctx, options) -> Iterable[RawFinding]``. It never
does I/O and carries no text: severity, message template, and remediation live in the
pack's metadata, keyed by sub-check id.
"""

import ast
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Protocol

from codepulse.core.model import Detection, Severity

if TYPE_CHECKING:
    from codepulse.core.engine.context import ScopeContext
    from codepulse.core.engine.imports import ImportMap
    from codepulse.core.semantic import PromptTemplate

Options = Mapping[str, Any]
SUBCHECK_ID = re.compile(r"^[A-Z][A-Z0-9]*\d{2}\.[a-z0-9][a-z0-9-]*$")
STATIC_DETECTIONS = frozenset({Detection.DETERMINISTIC, Detection.HEURISTIC, Detection.CANDIDATE})
COMMENTS: Literal["comments"] = "comments"
CONFIG_FILES: Literal["config_files"] = "config_files"
Channel = Literal["comments", "config_files"]


@dataclass(frozen=True, slots=True)
class Comment:
    """A ``#`` comment from the token stream; comments never appear in the AST."""

    lineno: int
    col_offset: int
    text: str
    standalone: bool = False  # the only token on its line
    before_code: bool = False  # precedes the file's first code token (file-level directives)


@dataclass(frozen=True, slots=True)
class ConfigFile:
    """A whole tool-config file (pyproject.toml, setup.cfg, ...) for config checks."""

    path: str
    text: str
    lineno: int = 1
    col_offset: int = 0


@dataclass(frozen=True, slots=True)
class ConfigEntry:
    """One setting inside a tool-config file; the anchor for config findings."""

    lineno: int
    col_offset: int
    text: str


Anchor = ast.AST | Comment | ConfigFile | ConfigEntry


@dataclass(frozen=True, slots=True)
class RawFinding:
    node: Anchor
    details: Mapping[str, str] = field(default_factory=dict)  # fills the message template
    severity: Severity | None = None  # override the metadata default for this hit
    signature: str | None = None  # override the fingerprint anchor (default: node signature)


class CheckFn(Protocol):
    def __call__(self, node: Any, ctx: "ScopeContext", opts: Options) -> Iterable[RawFinding]: ...


@dataclass(frozen=True, slots=True)
class SubCheck:
    id: str
    detection: Detection
    subscribes: tuple[type[ast.AST], ...] | Channel
    fn: CheckFn
    needs_index: bool = False  # skipped (and reported) when the project index is off

    def __post_init__(self) -> None:
        if not SUBCHECK_ID.match(self.id):
            raise ValueError(f"invalid sub-check id {self.id!r} (expected e.g. E04.no-timeout)")
        if self.detection not in STATIC_DETECTIONS:
            raise ValueError(f"{self.id}: detection {self.detection} is not a static class")

    @property
    def rule_id(self) -> str:
        return self.id.split(".", 1)[0]


def subcheck(
    id: str,
    *,
    detection: Detection,
    subscribes: tuple[type[ast.AST], ...] | Channel,
    needs_index: bool = False,
) -> Callable[[CheckFn], SubCheck]:
    def wrap(fn: CheckFn) -> SubCheck:
        return SubCheck(id, detection, subscribes, fn, needs_index)

    return wrap


@dataclass(frozen=True, slots=True)
class Catalog:
    """Shared knowledge (provider SDKs, SQL sinks, ...) that projects can extend from config.

    ``parse`` validates the merged entry list once at registry build and returns the typed
    object rules read via ``ctx.catalog(name)``. It raises ValueError/TypeError/KeyError on
    bad input.
    """

    name: str
    defaults: tuple[Any, ...]
    parse: Callable[[list[Any]], Any]


@dataclass(frozen=True, slots=True)
class Indexer:
    """Extracts cross-file facts from one module for the project index (spec 005).

    ``extract(tree, imports, path)`` must be pure and return immutable data; rules read it
    back with ``ctx.index.facts(name)``.
    """

    name: str
    extract: Callable[[ast.Module, "ImportMap", str], Any]


@dataclass(frozen=True, slots=True)
class RulePack:
    """What a ``codepulse.rules`` entry point provides."""

    name: str
    subchecks: tuple[SubCheck, ...]
    metadata: Mapping[str, Any]  # {"version": str, "rules": {rule_id: {...}}}
    catalogs: tuple[Catalog, ...] = ()
    prompts: tuple["PromptTemplate", ...] = ()  # semantic templates for candidate sub-checks
    indexers: tuple[Indexer, ...] = ()  # cross-file fact extractors (project index)
    # Globs over callee source text (`llm.invoke`): an unresolved call matching one is a
    # call the pack's rules could not analyze, so the report lists it (spec 006 FR-603).
    unresolved_watch: tuple[str, ...] = ()
