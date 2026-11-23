"""Scope state the visitor maintains, so rules ask questions instead of re-walking the tree.

Try/handler/with/loop state is per frame: a nested ``def`` body does not execute inside the
enclosing function's ``try`` or loop, so it starts clean.
"""

import ast
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from codepulse.core.engine.flow import FlowFacts
from codepulse.core.engine.imports import ImportMap

if TYPE_CHECKING:
    from codepulse.core.engine.index import ProjectIndex

MODULE_SCOPE = "<module>"
FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda


class FrameKind(StrEnum):
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"


@dataclass(slots=True)
class Frame:
    kind: FrameKind
    name: str
    qualname: str
    node: ast.AST | None = None
    is_async: bool = False
    decorators: tuple[str, ...] = ()  # qualified where resolvable, else source text
    try_bodies: list[ast.Try | ast.TryStar] = field(default_factory=list)
    handlers: list[ast.ExceptHandler] = field(default_factory=list)
    with_items: list[ast.withitem] = field(default_factory=list)
    loop_depth: int = 0
    flow: FlowFacts | None = None  # built on first query (spec 005 FR-507)


class ScopeContext:
    def __init__(
        self,
        path: str,
        imports: ImportMap,
        catalogs: Mapping[str, Any] | None = None,
        index: "ProjectIndex | None" = None,
    ) -> None:
        self.path = path
        self._module_imports = imports
        self._scoped: dict[int, tuple[ast.AST, ImportMap]] = {}
        self.index = index  # None when the project index is disabled
        self._catalogs = dict(catalogs or {})
        self._frames = [Frame(FrameKind.MODULE, MODULE_SCOPE, MODULE_SCOPE)]
        self._nodes: list[ast.AST] = []
        self._flow_cache: dict[int, tuple[ast.AST, FlowFacts]] = {}

    # -- queries for rules -------------------------------------------------------------

    @property
    def module_imports(self) -> ImportMap:
        """The module-level import map: one stable object per module, independent of the
        current function frame. Use this (not ``imports``) as a cache key for module-wide
        facts, so a per-function scoped map does not defeat memoization."""
        return self._module_imports

    @property
    def imports(self) -> ImportMap:
        """Name resolution at this point: the executing function's own bindings first,
        then the module's (spec 008)."""
        fn = self.function
        node = fn.node if fn else None
        if node is None:
            return self._module_imports
        cached = self._scoped.get(id(node))
        if cached is None or cached[0] is not node:
            cached = (node, self._module_imports.scoped(node))
            self._scoped[id(node)] = cached
        return cached[1]

    def imports_of(self, fn: ast.AST) -> ImportMap:
        """Resolution inside ``fn`` for a rule subscribed to the def (not yet entered)."""
        cached = self._scoped.get(id(fn))
        if cached is None or cached[0] is not fn:
            cached = (fn, self._module_imports.scoped(fn))
            self._scoped[id(fn)] = cached
        return cached[1]

    def catalog(self, name: str) -> Any:
        """Parsed catalog contents; KeyError if no pack declares it (a rule bug)."""
        return self._catalogs[name]

    @property
    def scope(self) -> str:
        return self._frames[-1].qualname

    @property
    def frames(self) -> tuple[Frame, ...]:
        return tuple(self._frames)

    @property
    def function(self) -> Frame | None:
        """The function whose body is executing here; None at module or class-body level."""
        top = self._frames[-1]
        return top if top.kind is FrameKind.FUNCTION else None

    @property
    def flow(self) -> FlowFacts | None:
        """Local flow facts of the executing function; None at module or class level."""
        fn = self.function
        if fn is None or fn.node is None:
            return None
        if fn.flow is None:
            fn.flow = FlowFacts.of(fn.node)
        return fn.flow

    def flow_of(self, fn: ast.AST) -> FlowFacts:
        """Flow facts of a function node a rule is subscribed to (it isn't on the stack yet)."""
        cached = self._flow_cache.get(id(fn))
        if cached is None or cached[0] is not fn:
            cached = (fn, FlowFacts.of(fn))
            self._flow_cache[id(fn)] = cached
        return cached[1]

    @property
    def is_async(self) -> bool:
        fn = self.function
        return fn is not None and fn.is_async

    @property
    def try_bodies(self) -> tuple[ast.Try | ast.TryStar, ...]:
        """``try`` statements whose body encloses this point, innermost first."""
        return tuple(reversed(self._frames[-1].try_bodies))

    @property
    def enclosing_handlers(self) -> tuple[ast.ExceptHandler, ...]:
        """Handlers that would catch an exception raised here, innermost first."""
        return tuple(h for t in self.try_bodies for h in t.handlers)

    @property
    def handler(self) -> ast.ExceptHandler | None:
        """Innermost ``except`` clause whose body we are in."""
        handlers = self._frames[-1].handlers
        return handlers[-1] if handlers else None

    @property
    def with_items(self) -> tuple[ast.withitem, ...]:
        return tuple(reversed(self._frames[-1].with_items))

    @property
    def loop_depth(self) -> int:
        return self._frames[-1].loop_depth

    @property
    def parent(self) -> ast.AST | None:
        return self._nodes[-1] if self._nodes else None

    def ancestors(self) -> Iterator[ast.AST]:
        """Enclosing nodes, nearest first."""
        return reversed(self._nodes)

    # -- mutation, used only by the visitor ---------------------------------------------

    def push_node(self, node: ast.AST) -> None:
        self._nodes.append(node)

    def pop_node(self) -> None:
        self._nodes.pop()

    def child_qualname(self, name: str) -> str:
        """Qualified name a definition called ``name`` would get at this point."""
        return self._child_qualname(name)

    def _child_qualname(self, name: str) -> str:
        parent = self._frames[-1]
        match parent.kind:
            case FrameKind.MODULE:
                return name
            case FrameKind.CLASS:
                return f"{parent.qualname}.{name}"
            case FrameKind.FUNCTION:
                return f"{parent.qualname}.<locals>.{name}"

    def _decorator_name(self, dec: ast.expr) -> str:
        target = dec.func if isinstance(dec, ast.Call) else dec
        return self.imports.qualified_name(target) or ast.unparse(target)

    def enter_function(self, node: FunctionNode) -> None:
        decorators: tuple[str, ...]
        if isinstance(node, ast.Lambda):
            name, decorators = "<lambda>", ()
        else:
            name = node.name
            decorators = tuple(self._decorator_name(d) for d in node.decorator_list)
        self._frames.append(
            Frame(
                FrameKind.FUNCTION,
                name,
                self._child_qualname(name),
                node,
                is_async=isinstance(node, ast.AsyncFunctionDef),
                decorators=decorators,
            )
        )

    def enter_class(self, node: ast.ClassDef) -> None:
        self._frames.append(
            Frame(FrameKind.CLASS, node.name, self._child_qualname(node.name), node)
        )

    def exit_frame(self) -> None:
        self._frames.pop()

    def enter_try(self, node: ast.Try | ast.TryStar) -> None:
        self._frames[-1].try_bodies.append(node)

    def exit_try(self) -> None:
        self._frames[-1].try_bodies.pop()

    def enter_handler(self, node: ast.ExceptHandler) -> None:
        self._frames[-1].handlers.append(node)

    def exit_handler(self) -> None:
        self._frames[-1].handlers.pop()

    def enter_with(self, items: list[ast.withitem]) -> None:
        self._frames[-1].with_items.extend(items)

    def exit_with(self, count: int) -> None:
        del self._frames[-1].with_items[-count:]

    def enter_loop(self) -> None:
        self._frames[-1].loop_depth += 1

    def exit_loop(self) -> None:
        self._frames[-1].loop_depth -= 1
