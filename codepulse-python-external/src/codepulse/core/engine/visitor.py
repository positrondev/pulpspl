"""Single-pass analysis of one file: one parse, one traversal, one token scan (APDD §6.3)."""

import ast
import io
import tokenize
from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from codepulse.core.candidate import Candidate
from codepulse.core.engine.context import ScopeContext
from codepulse.core.engine.imports import ImportMap
from codepulse.core.engine.index import ProjectIndex, module_name
from codepulse.core.engine.shape import node_signature
from codepulse.core.fingerprint import FingerprintInput, assign_fingerprints
from codepulse.core.model import (
    Detection,
    Finding,
    Location,
    Origin,
    SkipReason,
    SkipRecord,
    sort_findings,
)
from codepulse.core.registry import RuleRegistry
from codepulse.core.rule import Anchor, Comment, ConfigEntry, ConfigFile, RawFinding, SubCheck
from codepulse.core.suppression import Suppression, parse_suppression

__all__ = [
    "Comment",
    "FileAnalysis",
    "RuleError",
    "UnresolvedCall",
    "analyze_config_file",
    "analyze_source",
]

_NON_CODE_TOKENS = frozenset(
    {
        tokenize.COMMENT,
        tokenize.NL,
        tokenize.NEWLINE,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.ENCODING,
        tokenize.ENDMARKER,
    }
)


@dataclass(frozen=True, slots=True)
class RuleError:
    """A sub-check that crashed or produced an unusable hit. Reported, never swallowed."""

    subcheck_id: str
    path: str
    line: int
    error: str

    def to_dict(self) -> dict[str, object]:
        return {
            "subcheck_id": self.subcheck_id,
            "path": self.path,
            "line": self.line,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class UnresolvedCall:
    """A call that looks like one the rules analyze, but whose target is unknown."""

    path: str
    line: int
    callee: str

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "line": self.line, "callee": self.callee}


@dataclass(frozen=True, slots=True)
class FileAnalysis:
    path: str
    findings: tuple[Finding, ...] = ()
    skip: SkipRecord | None = None
    rule_errors: tuple[RuleError, ...] = ()
    suppressions: tuple[Suppression, ...] = ()
    candidates: tuple[Candidate, ...] = ()
    unresolved: tuple[UnresolvedCall, ...] = ()


@dataclass(frozen=True, slots=True)
class _Hit:
    check: SubCheck
    raw: RawFinding
    scope: str
    start: int
    end: int
    col: int
    message: str
    snippet: str


@dataclass(slots=True)
class _Walker:
    path: str
    registry: RuleRegistry
    ctx: ScopeContext
    text: str = ""
    hits: list[_Hit] = field(default_factory=list)
    errors: list[RuleError] = field(default_factory=list)
    scopes: list[tuple[int, int, str]] = field(default_factory=list)  # for comment lookup
    suppressions: list[Suppression] = field(default_factory=list)
    unresolved: list[UnresolvedCall] = field(default_factory=list)

    # -- dispatch -------------------------------------------------------------------

    def visit(self, node: ast.AST) -> None:
        if isinstance(node, ast.Call) and self.registry.unresolved_watch:
            self._watch(node)
        for check in self.registry.node_checks(type(node)):
            self.run(check, node, self.ctx.scope)
        self.ctx.push_node(node)
        self._children(node)
        self.ctx.pop_node()

    def _watch(self, node: ast.Call) -> None:
        if self.ctx.imports.qualified_names(node.func):
            return  # resolved, possibly to one of several injected alternatives
        callee = ast.unparse(node.func)
        watch = self.registry.unresolved_watch
        if any(fnmatchcase(callee, g) for g in watch if not g.startswith("!")) and not any(
            fnmatchcase(callee, g[1:]) for g in watch if g.startswith("!")
        ):
            self.unresolved.append(UnresolvedCall(self.path, node.lineno, callee))

    def run(self, check: SubCheck, node: Anchor, scope: str) -> None:
        if check.needs_index and self.ctx.index is None:
            return  # reported once per run as index_disabled (spec 005 FR-505)
        # codepulse: ignore[E12.handler-substance] reason="crash recorded as RuleError"
        try:
            raws = list(check.fn(node, self.ctx, self.registry.options(check.id)))
        except Exception as exc:  # noqa: BLE001 — a rule bug must not abort the run; recorded (Art. VIII)
            self.errors.append(
                RuleError(
                    check.id, self.path, self._position(node)[0], f"{type(exc).__name__}: {exc}"
                )
            )
            return
        template = self.registry.meta(check.id).message
        for raw in raws:
            start, end, col = self._position(raw.node, fallback=node)
            try:
                message = template.format_map(raw.details)
            except (KeyError, IndexError, ValueError) as exc:
                self.errors.append(
                    RuleError(check.id, self.path, start, f"message template: missing {exc}")
                )
                continue
            # A finding anchored on a def/class belongs to that definition's own scope.
            if isinstance(raw.node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                hit_scope = self.ctx.child_qualname(raw.node.name)
            else:
                hit_scope = scope
            snippet = ""
            if check.detection is Detection.CANDIDATE and isinstance(raw.node, ast.AST):
                snippet = ast.get_source_segment(self.text, raw.node) or ""
            self.hits.append(_Hit(check, raw, hit_scope, start, end, col, message, snippet))

    def _position(self, node: Anchor, fallback: Anchor | None = None) -> tuple[int, int, int]:
        # Some nodes (arguments, withitem, comprehension) carry no position.
        for candidate in (node, fallback, *self.ctx.ancestors()):
            line = getattr(candidate, "lineno", None)
            if isinstance(line, int):
                end = getattr(candidate, "end_lineno", None)
                col = getattr(candidate, "col_offset", 0)
                return line, end if isinstance(end, int) else line, col
        return 1, 1, 0

    # -- traversal ------------------------------------------------------------------

    def _each(self, nodes: list[ast.stmt] | list[ast.expr]) -> None:
        for n in nodes:
            self.visit(n)

    def _record_scope(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
        self.scopes.append((start, node.end_lineno or node.lineno, self.ctx.scope))

    def _children(self, node: ast.AST) -> None:
        ctx = self.ctx
        match node:
            case ast.FunctionDef() | ast.AsyncFunctionDef():
                self._each(node.decorator_list)
                self.visit(node.args)
                if node.returns is not None:
                    self.visit(node.returns)
                for tp in node.type_params:
                    self.visit(tp)
                ctx.enter_function(node)
                self._record_scope(node)
                self._each(node.body)
                ctx.exit_frame()
            case ast.Lambda():
                self.visit(node.args)
                ctx.enter_function(node)
                self.visit(node.body)
                ctx.exit_frame()
            case ast.ClassDef():
                self._each(node.decorator_list)
                self._each(node.bases)
                for kw in node.keywords:
                    self.visit(kw)
                for tp in node.type_params:
                    self.visit(tp)
                ctx.enter_class(node)
                self._record_scope(node)
                self._each(node.body)
                ctx.exit_frame()
            case ast.Try() | ast.TryStar():
                ctx.enter_try(node)
                self._each(node.body)
                ctx.exit_try()
                for handler in node.handlers:  # handlers are not protected by their own try
                    self.visit(handler)
                self._each(node.orelse)
                self._each(node.finalbody)
            case ast.ExceptHandler():
                if node.type is not None:
                    self.visit(node.type)
                ctx.enter_handler(node)
                self._each(node.body)
                ctx.exit_handler()
            case ast.With() | ast.AsyncWith():
                for item in node.items:
                    self.visit(item)
                ctx.enter_with(node.items)
                self._each(node.body)
                ctx.exit_with(len(node.items))
            case ast.For() | ast.AsyncFor():
                self.visit(node.target)
                self.visit(node.iter)
                ctx.enter_loop()
                self._each(node.body)
                ctx.exit_loop()
                self._each(node.orelse)
            case ast.While():
                self.visit(node.test)
                ctx.enter_loop()
                self._each(node.body)
                ctx.exit_loop()
                self._each(node.orelse)
            case ast.ListComp() | ast.SetComp() | ast.GeneratorExp() | ast.DictComp():
                ctx.enter_loop()
                for child in ast.iter_child_nodes(node):
                    self.visit(child)
                ctx.exit_loop()
            case _:
                for child in ast.iter_child_nodes(node):
                    self.visit(child)

    # -- comment channel --------------------------------------------------------------

    def scope_at(self, line: int) -> str:
        best: tuple[int, str] | None = None
        for start, end, qualname in self.scopes:
            if start <= line <= end and (best is None or start >= best[0]):
                best = (start, qualname)
        return best[1] if best else "<module>"

    def _suppress(self, comment: Comment, target_line: int) -> None:
        if (s := parse_suppression(comment.text, comment.lineno, target_line)) is not None:
            self.suppressions.append(s)

    def scan_tokens(self, text: str) -> None:
        """Comment checks plus ``codepulse: ignore`` directives, in one token pass.

        A standalone directive applies to the next code line; a trailing one to its own.
        """
        checks = self.registry.comment_checks
        first_code_line: int | None = None
        pending: list[Comment] = []
        try:
            for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                if tok.type == tokenize.COMMENT:
                    comment = Comment(
                        tok.start[0],
                        tok.start[1],
                        tok.string,
                        standalone=not tok.line[: tok.start[1]].strip(),
                        before_code=first_code_line is None,
                    )
                    for check in checks:
                        self.run(check, comment, self.scope_at(comment.lineno))
                    if comment.standalone:
                        pending.append(comment)
                    else:
                        self._suppress(comment, comment.lineno)
                elif tok.type not in _NON_CODE_TOKENS:
                    first_code_line = first_code_line or tok.start[0]
                    for c in pending:
                        self._suppress(c, tok.start[0])
                    pending.clear()
        except (tokenize.TokenError, SyntaxError) as exc:
            # The AST parsed, so this is a tokenizer edge case: comment checks are incomplete.
            self.errors.append(RuleError("<comments>", self.path, 1, f"tokenize: {exc}"))
        for c in pending:  # trailing standalone directives with no code after them
            self._suppress(c, c.lineno)

    # -- output -----------------------------------------------------------------------

    def results(self) -> tuple[tuple[Finding, ...], tuple[Candidate, ...]]:
        """Findings and candidates; one fingerprint pass so both share Art. IX identity."""
        inputs = [
            FingerprintInput(
                h.check.id,
                self.path,
                h.scope,
                h.raw.signature or _signature(h.raw.node),
                (h.start, h.col),
            )
            for h in self.hits
        ]
        out = []
        candidates = []
        for h, fp in zip(self.hits, assign_fingerprints(inputs), strict=True):
            meta = self.registry.meta(h.check.id)
            location = Location(self.path, h.start, h.end, h.scope)
            if meta.detection is Detection.CANDIDATE:
                candidates.append(
                    Candidate(
                        fp,
                        meta.rule_id,
                        meta.id,
                        location,
                        h.message,
                        h.snippet,
                        dict(h.raw.details),
                        h.raw.severity or meta.severity,
                        meta.component,
                    )
                )
                continue
            out.append(
                Finding(
                    fingerprint=fp,
                    rule_id=meta.rule_id,
                    subcheck_id=meta.id,
                    severity=h.raw.severity or meta.severity,
                    detection=meta.detection,
                    origin=Origin.NOT_APPLICABLE,  # attributed later by the normalizer
                    location=location,
                    component=meta.component,
                    message=h.message,
                    remediation=meta.remediation,
                )
            )
        ordered = sorted(candidates, key=lambda c: (c.location.start_line, c.fingerprint))
        return sort_findings(out), tuple(ordered)


def _signature(node: Anchor) -> str:
    match node:
        case Comment(text=text):
            return f"Comment:{text.strip()}"
        case ConfigEntry(text=text):
            return f"Config:{text.strip()}"
        case ConfigFile():
            return "ConfigFile"
        case _:
            return node_signature(node)


def _skip(path: str, detail: str) -> FileAnalysis:
    return FileAnalysis(path, skip=SkipRecord(path, SkipReason.PARSE_ERROR, detail))


def analyze_source(
    path: str, text: str, registry: RuleRegistry, index: "ProjectIndex | None" = None
) -> FileAnalysis:
    """Run every active sub-check over one file. Never raises for bad input."""
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as exc:
        return _skip(path, f"line {exc.lineno or '?'}: {exc.msg}")
    except ValueError as exc:  # e.g. null bytes on some Python versions
        return _skip(path, str(exc))

    walker = _Walker(
        path,
        registry,
        ScopeContext(
            path,
            ImportMap.build(
                tree,
                index.factories() if index is not None else None,
                module_name(path),
                path.endswith("__init__.py"),
            ),
            registry.catalogs,
            index,
        ),
        text,
    )
    try:
        walker.visit(tree)
    except RecursionError:
        return _skip(path, "nesting too deep to analyze")
    walker.scan_tokens(text)
    findings, candidates = walker.results()
    return FileAnalysis(
        path,
        findings,
        None,
        tuple(walker.errors),
        tuple(walker.suppressions),
        candidates,
        tuple(walker.unresolved),
    )


CONFIG_SCOPE = "<config>"


def analyze_config_file(path: str, text: str, registry: RuleRegistry) -> FileAnalysis:
    """Run config-file checks (E15 blanket disables) over one tool-config file."""
    walker = _Walker(path, registry, ScopeContext(path, ImportMap(), registry.catalogs))
    for check in registry.config_checks:
        walker.run(check, ConfigFile(path, text), CONFIG_SCOPE)
    findings, _ = walker.results()
    return FileAnalysis(path, findings, None, tuple(walker.errors))
