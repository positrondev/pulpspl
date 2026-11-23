"""Local flow facts for one function: where a name is bound, where it is used, and which
uses are guards (spec 005 FR-506).

Intra-procedural and flow-insensitive apart from source order: a rule asks "is ``x``
checked between line A and line B?", not "on every path". Nested functions are their own
scope and are not descended into. Built once per function on first query (FR-507).
"""

import ast
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field

_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_GUARD_CALLS = frozenset({"isinstance", "issubclass", "len", "bool", "callable", "hasattr"})


@dataclass(frozen=True, slots=True)
class Binding:
    name: str
    line: int
    col: int
    value: ast.expr | None  # the bound expression; None for `for`/`with`/`except` targets
    stmt: ast.AST


@dataclass(frozen=True, slots=True)
class Use:
    name: str
    line: int
    col: int
    node: ast.Name
    guard: bool  # read as a condition, assertion, comparison, or type/shape check
    attrs: tuple[str, ...]  # attribute chain read off the name: `r.usage.total` -> (usage, total)


@dataclass(slots=True)
class FlowFacts:
    bindings: dict[str, list[Binding]] = field(default_factory=dict)
    uses: dict[str, list[Use]] = field(default_factory=dict)

    @classmethod
    def of(cls, fn: ast.AST, guard_calls: Iterable[str] = ()) -> "FlowFacts":
        facts = cls()
        _Collector(facts, _GUARD_CALLS | frozenset(guard_calls)).run(fn)
        for bseq in facts.bindings.values():
            bseq.sort(key=lambda b: (b.line, b.col))
        for useq in facts.uses.values():
            useq.sort(key=lambda u: (u.line, u.col))
        return facts

    def bindings_of(self, name: str) -> list[Binding]:
        return self.bindings.get(name, [])

    def uses_of(self, name: str, after: int = 0, before: int | None = None) -> list[Use]:
        return [
            u
            for u in self.uses.get(name, [])
            if u.line > after and (before is None or u.line < before)
        ]

    def guarded(self, name: str, after: int, before: int | None = None) -> bool:
        return any(u.guard for u in self.uses_of(name, after, before))

    def names_bound_from(self, pred: Callable[[Binding], bool]) -> set[str]:
        return {b.name for seq in self.bindings.values() for b in seq if pred(b)}

    def derived(self, roots: set[str]) -> set[str]:
        """Names bound (directly or transitively) from expressions that read ``roots``."""
        out = set(roots)
        changed = True
        while changed:
            changed = False
            for name, seq in self.bindings.items():
                if name in out:
                    continue
                if any(b.value is not None and _reads(b.value) & out for b in seq):
                    out.add(name)
                    changed = True
        return out


def _reads(expr: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(expr) if isinstance(n, ast.Name)}


def target_names(target: ast.AST) -> Iterator[ast.Name]:
    match target:
        case ast.Name():
            yield target
        case ast.Tuple(elts=elts) | ast.List(elts=elts):
            for e in elts:
                yield from target_names(e)
        case ast.Starred(value=value):
            yield from target_names(value)


@dataclass(slots=True)
class _Collector:
    facts: FlowFacts
    guard_calls: frozenset[str]

    def run(self, fn: ast.AST) -> None:
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            for a in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs):
                self._bind(a.arg, a.lineno, a.col_offset, None, a)
            for star in (fn.args.vararg, fn.args.kwarg):
                if star is not None:
                    self._bind(star.arg, star.lineno, star.col_offset, None, star)
        body = getattr(fn, "body", [])
        for stmt in body if isinstance(body, list) else [body]:
            self._walk(stmt, guard=False)

    def _bind(self, name: str, line: int, col: int, value: ast.expr | None, stmt: ast.AST) -> None:
        self.facts.bindings.setdefault(name, []).append(Binding(name, line, col, value, stmt))

    def _bind_target(self, target: ast.AST, value: ast.expr | None, stmt: ast.AST) -> None:
        for n in target_names(target):
            self._bind(n.id, n.lineno, n.col_offset, value, stmt)

    def _walk(self, node: ast.AST, guard: bool, attrs: tuple[str, ...] = ()) -> None:
        match node:
            case ast.FunctionDef() | ast.AsyncFunctionDef() | ast.ClassDef():
                self._bind(node.name, node.lineno, node.col_offset, None, node)
                return  # a nested definition is its own scope
            case ast.Lambda():
                return
            case ast.Name(ctx=ast.Load()):
                use = Use(node.id, node.lineno, node.col_offset, node, guard, attrs)
                self.facts.uses.setdefault(node.id, []).append(use)
                return
            case ast.Attribute(ctx=ast.Load()):
                self._walk(node.value, guard, (node.attr, *attrs))
                return
            case ast.Assign(targets=targets, value=value):
                self._walk(value, guard=False)
                for t in targets:
                    self._bind_target(t, value, node)
                    self._walk_store(t)
                return
            case (
                ast.AnnAssign(target=target, value=value)
                | ast.AugAssign(target=target, value=value)
            ):
                if value is not None:
                    self._walk(value, guard=False)
                if isinstance(node, ast.AugAssign) and isinstance(target, ast.Name):
                    # `x += y` reads `x` before rebinding it.
                    read = Use(target.id, target.lineno, target.col_offset, target, False, ())
                    self.facts.uses.setdefault(target.id, []).append(read)
                if value is not None or isinstance(node, ast.AugAssign):
                    self._bind_target(target, value, node)
                self._walk_store(target)
                return
            case ast.NamedExpr(target=target, value=value):
                self._walk(value, guard)
                self._bind_target(target, value, node)
                return
            case ast.For() | ast.AsyncFor():
                self._walk(node.iter, guard=False)
                self._bind_target(node.target, None, node)
                self._each(node.body)
                self._each(node.orelse)
                return
            case ast.With() | ast.AsyncWith():
                for item in node.items:
                    self._walk(item.context_expr, guard=False)
                    if item.optional_vars is not None:
                        self._bind_target(item.optional_vars, item.context_expr, node)
                self._each(node.body)
                return
            case ast.ExceptHandler(name=str(name)):
                if node.type is not None:
                    self._walk(node.type, guard=False)
                self._bind(name, node.lineno, node.col_offset, None, node)
                self._each(node.body)
                return
            case ast.If(test=test) | ast.While(test=test):
                self._walk(test, guard=True)
                self._each(node.body)
                self._each(node.orelse)
                return
            case ast.IfExp(test=test, body=body, orelse=orelse):
                self._walk(test, guard=True)
                self._walk(body, guard)
                self._walk(orelse, guard)
                return
            case ast.Assert(test=test, msg=msg):
                self._walk(test, guard=True)
                if msg is not None:
                    self._walk(msg, guard=False)
                return
            case ast.Compare() | ast.BoolOp(op=ast.And() | ast.Or()) if not guard:
                # `ok = r is not None`, `return a and b`: a comparison is a check wherever it is.
                for child in ast.iter_child_nodes(node):
                    self._walk(child, guard=True)
                return
            case ast.Call(func=func) if _call_name(func) in self.guard_calls:
                self._walk(func, guard=False)
                for arg in (*node.args, *(k.value for k in node.keywords)):
                    self._walk(arg, guard=True)
                return
            case ast.comprehension():
                self._walk(node.iter, guard=False)
                self._bind_target(node.target, None, node)
                for cond in node.ifs:
                    self._walk(cond, guard=True)
                return
            case ast.Match(subject=subject, cases=cases):
                self._walk(subject, guard=True)
                for c in cases:
                    if c.guard is not None:
                        self._walk(c.guard, guard=True)
                    self._each(c.body)
                return
        for child in ast.iter_child_nodes(node):
            self._walk(child, guard)

    def _walk_store(self, target: ast.AST) -> None:
        """Subscript/attribute targets read their base: `state["k"] = v` uses `state`."""
        match target:
            case ast.Subscript(value=value, slice=slc):
                self._walk(value, guard=False)
                self._walk(slc, guard=False)
            case ast.Attribute(value=value):
                self._walk(value, guard=False)
            case ast.Tuple(elts=elts) | ast.List(elts=elts):
                for e in elts:
                    self._walk_store(e)

    def _each(self, stmts: list[ast.stmt]) -> None:
        for s in stmts:
            self._walk(s, guard=False)


def _call_name(func: ast.expr) -> str:
    match func:
        case ast.Name(id=name):
            return name
        case ast.Attribute(attr=attr):
            return attr
    return ""


__all__ = ["Binding", "FlowFacts", "Use", "target_names"]
