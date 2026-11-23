"""Static call-target resolution: ``llm.invoke`` → ``langchain_openai.ChatOpenAI.invoke``.

Rules match qualified names against catalogs instead of raw identifiers (APDD fix R4), so
aliased imports and instance variables resolve correctly. Resolution is module-wide and
flow-insensitive by design: a name bound to two different types is ambiguous and resolves
to None rather than to a guess.
"""

import ast
import builtins
from collections.abc import Mapping

_BUILTINS = frozenset(dir(builtins))
_OPTIONAL = frozenset({"typing.Optional", "typing_extensions.Optional"})


Factory = tuple[str, tuple[ast.Call, ...]]  # (produced type, constructor calls returned)


def absolutize(name: str | None, module: str, is_package: bool = False) -> str | None:
    """``.provider.make`` imported in ``pkg.ai.graph`` -> ``pkg.ai.provider.make``."""
    if name is None or not name.startswith(".") or not module:
        return name
    level = len(name) - len(name.lstrip("."))
    parts = module.split(".") if is_package else module.split(".")[:-1]
    parts = parts[: len(parts) - (level - 1)] if level > 1 else parts
    return ".".join([*parts, name.lstrip(".")])


class ImportMap:
    def __init__(self) -> None:
        self._aliases: dict[str, str] = {}
        self._bindings: dict[str, str | None] = {}  # None marks an ambiguous binding
        self._binding_calls: dict[str, list[ast.Call]] = {}  # every constructor call per name
        self._local_defs: set[str] = set()
        # Module-level factories: `def _client(): return anthropic.Anthropic(...)`.
        # Calling one yields that type, and its constructor calls carry the config.
        self._factories: dict[str, Factory] = {}
        # Factories defined in other modules, by absolute qualified name (project index).
        self._foreign: Mapping[str, Factory] = {}
        self._module = ""
        self._is_package = False
        # `f = mock if test else litellm.acompletion`: every callable a name may hold.
        self._alternatives: dict[str, tuple[str, ...]] = {}

    @classmethod
    def build(
        cls,
        tree: ast.AST,
        foreign: Mapping[str, Factory] | None = None,
        module: str = "",
        is_package: bool = False,
    ) -> "ImportMap":
        m = cls()
        m._foreign = foreign or {}
        m._module, m._is_package = module, is_package
        nodes = list(ast.walk(tree))
        for node in nodes:
            m._collect_import(node)
        if isinstance(tree, ast.Module):
            for stmt in tree.body:
                if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                    m._collect_factory(stmt)
        # Source order, not walk order: `x = f` nested in an `if` must precede `self.y = x`.
        for node in sorted(
            nodes, key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0))
        ):
            m._collect_binding(node)
        return m

    def qualified_names(self, expr: ast.expr) -> tuple[str, ...]:
        """Every target an expression may name: a single resolution, or the alternatives a
        name was assigned at run time (conditional injection of a client or callable)."""
        match expr:
            case ast.IfExp(body=a, orelse=b):
                return tuple(sorted({*self.qualified_names(a), *self.qualified_names(b)}))
            case ast.BoolOp(values=values):
                return tuple(sorted({q for v in values for q in self.qualified_names(v)}))
            case ast.Name() | ast.Attribute() if (key := _key(expr)) in self._alternatives:
                return self._alternatives[key]
        q = self.qualified_name(expr)
        return (q,) if q else ()

    def factories(self, module: str) -> dict[str, Factory]:
        """This module's factories by absolute name, for the project index."""
        return {f"{module}.{name}": f for name, f in sorted(self._factories.items())}

    def _factory(self, func: ast.expr) -> Factory | None:
        if isinstance(func, ast.Name) and func.id in self._factories:
            return self._factories[func.id]
        if not self._foreign:
            return None
        name = absolutize(self.qualified_name(func), self._module, self._is_package)
        return self._foreign.get(name or "")

    def scoped(self, fn: ast.AST) -> "ImportMap":
        """This map as seen inside ``fn``: names the function binds resolve to its own
        bindings, everything else to the module's. A name assigned different chains in
        different functions (`model = llm.with_structured_output(A)` here,
        `model = llm.bind_tools(t)` there) is ambiguous module-wide but not per function."""
        own = list(_own_nodes(fn))
        local_keys = {k for n in own for k in _target_keys(n)}
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            local_keys |= {a.arg for a in ast.walk(fn.args) if isinstance(a, ast.arg)}
        m = ImportMap()
        m._aliases = self._aliases
        m._local_defs = self._local_defs
        m._factories = self._factories
        m._foreign, m._module, m._is_package = self._foreign, self._module, self._is_package
        m._alternatives = {k: v for k, v in self._alternatives.items() if k not in local_keys}
        m._bindings = {k: v for k, v in self._bindings.items() if k not in local_keys}
        m._binding_calls = {k: v for k, v in self._binding_calls.items() if k not in local_keys}
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            for a in ast.walk(fn.args):
                m._collect_binding(a)
        for n in sorted(own, key=lambda x: (getattr(x, "lineno", 0), getattr(x, "col_offset", 0))):
            m._collect_binding(n)
        return m

    def _collect_factory(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        returns: list[ast.expr] = []
        stack: list[ast.AST] = list(fn.body)
        while stack:
            n = stack.pop()
            if isinstance(n, ast.Return) and n.value is not None:
                returns.append(n.value)
            if not isinstance(
                n, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef
            ):
                stack.extend(ast.iter_child_nodes(n))
        calls = tuple(r for r in returns if isinstance(r, ast.Call))
        produced = {self.qualified_name(c.func) for c in calls}
        if fn.returns is not None and (typed := self._annotation_type(fn.returns)):
            self._factories[fn.name] = (typed, calls)
        elif calls and len(calls) == len(returns) and len(produced) == 1:
            (only,) = produced
            if only is not None and only.rsplit(".", 1)[-1][:1].isupper():
                self._factories[fn.name] = (only, calls)  # a constructor, not any helper

    def _collect_import(self, node: ast.AST) -> None:
        match node:
            case ast.Import(names=names):
                for a in names:
                    if a.asname:
                        self._aliases[a.asname] = a.name
                    else:  # `import a.b` binds `a`
                        head = a.name.split(".", 1)[0]
                        self._aliases[head] = head
            case ast.ImportFrom(module=module, level=level, names=names):
                prefix = "." * level + (module or "")
                for a in names:
                    if a.name == "*":  # star imports are unknowable statically
                        continue
                    sep = "." if module else ""
                    self._aliases[a.asname or a.name] = f"{prefix}{sep}{a.name}"
            case (
                ast.FunctionDef(name=name)
                | ast.AsyncFunctionDef(name=name)
                | ast.ClassDef(name=name)
            ):
                self._local_defs.add(name)

    def _collect_binding(self, node: ast.AST) -> None:
        match node:
            case ast.AnnAssign(target=target, annotation=ann):
                self._bind(target, self._annotation_type(ann))
            case ast.Assign(targets=targets, value=value) if isinstance(
                value, ast.IfExp | ast.BoolOp | ast.Name | ast.Attribute
            ):
                # A function reference (or a runtime choice between several) bound to a name;
                # calls through the name may reach any of them.
                options = self.qualified_names(value)
                for t in targets:
                    key = _key(t)
                    if key is not None and options:
                        self._alternatives[key] = tuple(
                            sorted({*self._alternatives.get(key, ()), *options})
                        )
            case ast.Assign(targets=targets, value=value):
                if isinstance(value, ast.Constant) and value.value is None:
                    return  # `self.x = None` placeholders don't make a binding ambiguous
                call = value if isinstance(value, ast.Call) else None
                bound = self.qualified_name(call) if call else None
                for t in targets:
                    self._bind(t, bound, call)
                    factory = self._factory(call.func) if call is not None else None
                    for inner in factory[1] if factory else ():
                        self._bind(t, bound, inner)
            case ast.withitem(context_expr=ast.Call(func=func) as call, optional_vars=target) if (
                target is not None
            ):
                self._bind(target, self.qualified_name(func), call)
            case ast.arg(arg=name, annotation=ann) if ann is not None:
                self._bind(ast.Name(id=name), self._annotation_type(ann))

    def _bind(self, target: ast.expr, qualified: str | None, call: ast.Call | None = None) -> None:
        if isinstance(target, ast.Name):
            key = target.id
        elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            key = f"{target.value.id}.{target.attr}"
        else:
            return
        if key in self._bindings and self._bindings[key] != qualified:
            self._bindings[key] = None
        else:
            self._bindings[key] = qualified
        if call is not None:
            self._binding_calls.setdefault(key, []).append(call)

    def is_bound(self, key: str) -> bool:
        """True if ``key`` was assigned from a call (an instance), not just imported."""
        return key in self._binding_calls

    def binding_calls(self, key: str) -> tuple[ast.Call, ...]:
        """Every call assigned to ``key`` (``name`` or ``self.attr``), in walk order.

        Lets rules see constructor configuration such as ``OpenAI(timeout=30)`` behind a
        variable. Callers needing a guarantee must check all of them.
        """
        return tuple(self._binding_calls.get(key, ()))

    def _annotation_type(self, ann: ast.expr) -> str | None:
        match ann:
            case ast.Constant(value=str(text)):
                try:
                    return self._annotation_type(ast.parse(text, mode="eval").body)
                except SyntaxError:
                    return None
            case ast.BinOp(op=ast.BitOr(), left=left, right=ast.Constant(value=None)):
                return self._annotation_type(left)
            case ast.BinOp(op=ast.BitOr(), left=ast.Constant(value=None), right=right):
                return self._annotation_type(right)
            case ast.Subscript(value=base, slice=inner) if self.qualified_name(base) in _OPTIONAL:
                return self._annotation_type(inner)
            case _:
                return self.qualified_name(ann)

    def qualified_name(self, expr: ast.expr) -> str | None:
        """Dotted origin of an expression, or None when it cannot be known statically."""
        match expr:
            case ast.Name(id=name):
                if name in self._bindings:
                    return self._bindings[name]
                if name in self._aliases:
                    return self._aliases[name]
                if name in _BUILTINS and name not in self._local_defs:
                    return f"builtins.{name}"
                return None
            case ast.Attribute(value=value, attr=attr):
                if isinstance(value, ast.Name):
                    key = f"{value.id}.{attr}"
                    if key in self._bindings:
                        return self._bindings[key]
                base = self.qualified_name(value)
                return None if base is None else f"{base}.{attr}"
            case ast.Call(func=func):
                factory = self._factory(func)
                return factory[0] if factory else self.qualified_name(func)
            case _:
                return None


def _own_nodes(fn: ast.AST) -> list[ast.AST]:
    """Nodes of a function body, not descending into nested functions or classes."""
    out: list[ast.AST] = []
    body = getattr(fn, "body", [])
    stack: list[ast.AST] = list(body) if isinstance(body, list) else [body]
    while stack:
        n = stack.pop()
        out.append(n)
        if not isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
            stack.extend(ast.iter_child_nodes(n))
    return out


def _target_keys(node: ast.AST) -> list[str]:
    targets: list[ast.expr] = []
    match node:
        case ast.Assign(targets=ts):
            targets = list(ts)
        case ast.AnnAssign(target=t) | ast.AugAssign(target=t):
            targets = [t]
        case ast.withitem(optional_vars=t) if t is not None:
            targets = [t]
    keys = []
    for t in targets:
        if isinstance(t, ast.Name):
            keys.append(t.id)
        elif isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name):
            keys.append(f"{t.value.id}.{t.attr}")
    return keys


def _key(target: ast.expr) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
        return f"{target.value.id}.{target.attr}"
    return None
