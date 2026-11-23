"""Cross-file facts for rules that need to see beyond one module (spec 005 FR-501..505).

The index holds facts, never source: module names, imported names, referenced
identifiers, and whatever each rule pack's indexers extract. It lives in memory for one
run, is never persisted or sent to a backend, and is built only from files that passed the
classification gate (Art. VII). Built in sorted path order so it is a pure function of its
inputs (Art. II).
"""

import ast
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any

from codepulse.core.engine.imports import Factory, ImportMap
from codepulse.core.model import SkipReason, SkipRecord
from codepulse.core.rule import Indexer

SOURCE_ROOTS = ("src/", "lib/")


@dataclass(frozen=True, slots=True)
class ModuleFacts:
    path: str
    module: str  # dotted import name derived from the path
    imported: frozenset[str]  # absolute qualified names this module imports
    names: frozenset[str]  # identifiers and attribute names it references
    extra: Mapping[str, Any] = field(default_factory=dict)  # indexer name -> facts
    factories: Mapping[str, Factory] = field(default_factory=dict)  # absolute name -> factory

    def references(self, qualname: str) -> bool:
        """Does this module import ``qualname``, or import its module and name its leaf?"""
        module, _, leaf = qualname.rpartition(".")
        if any(i == qualname or i.startswith(qualname + ".") for i in self.imported):
            return True
        return bool(module) and leaf in self.names and module in self.imported


@dataclass(frozen=True, eq=False)
class ProjectIndex:
    # Immutable for one run, but every node in every file queries it, so the per-indexer
    # fact lists, the path lookup and the factory map are each built once and cached here
    # (not slots: cached_property needs an instance __dict__). This keeps lookups O(1)
    # instead of O(modules) per call -- the latter is O(modules x nodes) over a run.
    # eq=False gives it identity hashing (O(1)), so rules can memoize project-wide derived
    # models on the index without paying an O(modules) value-hash on every lookup.
    modules: tuple[ModuleFacts, ...]
    skipped: tuple[SkipRecord, ...] = ()

    @cached_property
    def _by_path(self) -> dict[str, ModuleFacts]:
        return {m.path: m for m in self.modules}

    @cached_property
    def _facts(self) -> dict[str, tuple[tuple[ModuleFacts, Any], ...]]:
        out: dict[str, list[tuple[ModuleFacts, Any]]] = {}
        for m in self.modules:
            for name, value in m.extra.items():
                out.setdefault(name, []).append((m, value))
        return {name: tuple(pairs) for name, pairs in out.items()}

    @cached_property
    def _factories(self) -> dict[str, Factory]:
        return {k: v for m in self.modules for k, v in m.factories.items()}

    def get(self, path: str) -> ModuleFacts | None:
        return self._by_path.get(path)

    def factories(self) -> dict[str, Factory]:
        """Every module-level client factory in the project, by absolute name."""
        return self._factories

    def facts(self, indexer: str) -> Iterator[tuple[ModuleFacts, Any]]:
        return iter(self._facts.get(indexer, ()))


def module_name(path: str) -> str:
    """``src/pkg/agent.py`` -> ``pkg.agent``; ``pkg/__init__.py`` -> ``pkg``."""
    for root in SOURCE_ROOTS:
        if path.startswith(root):
            path = path[len(root) :]
            break
    parts = path.removesuffix(".py").split("/")
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def absolute_imports(tree: ast.Module, module: str, is_package: bool) -> frozenset[str]:
    package = module if is_package else module.rpartition(".")[0]
    out: set[str] = set()
    for node in ast.walk(tree):
        match node:
            case ast.Import(names=names):
                out.update(a.name for a in names)
            case ast.ImportFrom(module=mod, level=level, names=names):
                base = mod or ""
                if level:
                    anchor = package.split(".") if package else []
                    anchor = anchor[: len(anchor) - (level - 1)] if level > 1 else anchor
                    base = ".".join(p for p in (*anchor, base) if p)
                if base:
                    out.add(base)
                out.update(f"{base}.{a.name}" if base else a.name for a in names if a.name != "*")
    return frozenset(out)


def referenced_names(tree: ast.Module) -> frozenset[str]:
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            out.add(node.id)
        elif isinstance(node, ast.Attribute):
            out.add(node.attr)
    return frozenset(out)


def build_index(files: Iterable[tuple[str, str]], indexers: Sequence[Indexer]) -> ProjectIndex:
    """Index ``(path, text)`` pairs. Unparseable files and crashing indexers are recorded."""
    modules: list[ModuleFacts] = []
    skipped: list[SkipRecord] = []
    for path, text in sorted(files):
        try:
            tree = ast.parse(text, filename=path)
        except (SyntaxError, ValueError) as exc:
            skipped.append(SkipRecord(path, SkipReason.PARSE_ERROR, str(exc)))
            continue
        imports = ImportMap.build(tree)
        extra: dict[str, Any] = {}
        for ix in indexers:
            # codepulse: ignore[E12.handler-substance] reason="indexer crash recorded as skip"
            try:
                extra[ix.name] = ix.extract(tree, imports, path)
            except Exception as exc:  # noqa: BLE001 — a pack bug must not abort the run; recorded (Art. VIII)
                detail = f"indexer {ix.name}: {type(exc).__name__}: {exc}"
                skipped.append(SkipRecord(path, SkipReason.INDEXER_ERROR, detail))
        name = module_name(path)
        modules.append(
            ModuleFacts(
                path,
                name,
                absolute_imports(tree, name, path.endswith("__init__.py")),
                referenced_names(tree),
                extra,
                imports.factories(name),
            )
        )
    return ProjectIndex(tuple(modules), tuple(skipped))
