"""Reusable, declarative, limited-scope Python data-flow matching.

Supported: local function parameters, imported-call sources, assignments, call sinks,
call sanitizers, and intra-procedural propagation through expressions. This is a
conservative static heuristic, NOT whole-program taint analysis or a security proof.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from codepulse.core.errors import ConfigError
from codepulse.external_rules.ast_matcher import QueryContext

FIELDS = frozenset({'type','source_calls','source_parameters','sink_calls','sanitizer_calls'})


def validate_flow(match: dict, where: str) -> dict:
    unknown = set(match) - FIELDS
    if unknown:
        raise ConfigError(f'{where}: unknown flow fields {sorted(unknown)}')
    if 'sink_calls' not in match or not match['sink_calls']:
        raise ConfigError(f'{where}: sink_calls must contain at least one regex')
    if not match.get('source_calls') and not match.get('source_parameters'):
        raise ConfigError(f'{where}: source_calls or source_parameters must be configured')
    fields={}
    for name in ('source_calls','source_parameters','sink_calls','sanitizer_calls'):
        raw = match.get(name, [])
        if not isinstance(raw,list) or len(raw)>100 or any(not isinstance(v,str) or not v or len(v)>256 for v in raw):
            raise ConfigError(f'{where}.{name}: expected list of 1-256 character regex strings (max 100)')
        for value in raw:
            try: re.compile(value)
            except re.error as exc: raise ConfigError(f'{where}.{name}: invalid regex: {exc}') from exc
        fields[name]=tuple(raw)
    return fields


@dataclass(frozen=True)
class FlowMatcher:
    source_calls: tuple[re.Pattern,...]
    source_parameters: tuple[re.Pattern,...]
    sink_calls: tuple[re.Pattern,...]
    sanitizer_calls: tuple[re.Pattern,...]

    @classmethod
    def create(cls, query: dict):
        return cls(*(tuple(re.compile(p) for p in query[k])
                     for k in ('source_calls','source_parameters','sink_calls','sanitizer_calls')))

    @staticmethod
    def matches(patterns, value: str) -> bool:
        return any(pattern.search(value) for pattern in patterns)


def flow_matches(text: str, rule, path: str, tree: ast.Module | None = None):
    """Return sink locations where untrusted values may reach a configured call.

    This implementation intentionally stays intra-procedural and merges branches
    conservatively. No claim is made for indirect flow across function boundaries.
    """
    if tree is None:
        try: tree=ast.parse(text,filename=path)
        except (SyntaxError,ValueError): return []
    query=FlowMatcher.create(rule.ast_predicate)
    context=QueryContext.build(tree)
    found: list[tuple[int,int,str,str]]=[]

    def tainted(expr: ast.AST | None, env: set[str]) -> bool:
        if expr is None: return False
        if isinstance(expr,ast.Name): return expr.id in env
        if isinstance(expr,ast.Call):
            name=context.qualified_call(expr)
            if query.matches(query.sanitizer_calls,name): return False
            if query.matches(query.source_calls,name): return True
        return any(tainted(n,env) for n in ast.iter_child_nodes(expr))

    scope_name = '<module>'

    def calls(expr: ast.AST):
        for sub in ast.walk(expr):
            if isinstance(sub,ast.Call):
                name=context.qualified_call(sub)
                if query.matches(query.sink_calls,name) and any(tainted(v,active)
                       for v in (*sub.args,*(kw.value for kw in sub.keywords))):
                    found.append((sub.lineno,sub.col_offset,ast.unparse(sub)[:160],scope_name))

    def assigned_names(target):
        if isinstance(target,ast.Name): return [target.id]
        if isinstance(target,(ast.Tuple,ast.List)):
            return [name for member in target.elts for name in assigned_names(member)]
        return []

    def statements(body, env):
        nonlocal active
        for stmt in body:
            active=env
            if isinstance(stmt,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                continue
            if isinstance(stmt,ast.Assign):
                calls(stmt.value)
                is_tainted=tainted(stmt.value,env)
                for target in stmt.targets:
                    for name in assigned_names(target):
                        if is_tainted: env.add(name)
                        else: env.discard(name)
            elif isinstance(stmt,ast.AnnAssign):
                if stmt.value is not None:
                    calls(stmt.value)
                    for name in assigned_names(stmt.target):
                        if tainted(stmt.value,env): env.add(name)
                        else: env.discard(name)
            elif isinstance(stmt,ast.AugAssign):
                calls(stmt.value)
                if tainted(stmt.value,env): env.update(assigned_names(stmt.target))
            elif isinstance(stmt,ast.If):
                calls(stmt.test)
                lhs,rhs=set(env),set(env)
                statements(stmt.body,lhs)
                statements(stmt.orelse,rhs)
                env.update(lhs|rhs)
            elif isinstance(stmt,(ast.For,ast.AsyncFor,ast.While)):
                calls(stmt.iter if hasattr(stmt,'iter') else stmt.test)
                branch=set(env)
                statements(stmt.body,branch)
                env.update(branch)
                statements(stmt.orelse,env)
            elif isinstance(stmt,(ast.With,ast.AsyncWith)):
                for item in stmt.items: calls(item.context_expr)
                statements(stmt.body,env)
            elif isinstance(stmt,(ast.Try,ast.TryStar)):
                branches=[]
                for group in (stmt.body,stmt.orelse,stmt.finalbody,*(h.body for h in stmt.handlers)):
                    local=set(env)
                    statements(group,local)
                    branches.append(local)
                for local in branches: env.update(local)
            else: calls(stmt)

    active: set[str]=set()
    for node in ast.walk(tree):
        if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)): continue
        scope_name=node.name  # local flow is per function; nested class names not yet resolved
        params=[*node.args.posonlyargs,*node.args.args,*node.args.kwonlyargs]
        active={arg.arg for arg in params if query.matches(query.source_parameters,arg.arg)}
        statements(node.body,active)
    return found[:5000]
