"""Safe, declarative Python AST query interpreter. No eval(), imports or rule callbacks.

This is a syntactic query engine, NOT type-flow or symbol-resolution parity with legacy.
"""
from __future__ import annotations

import ast
import fnmatch
import re
from collections import Counter
from dataclasses import dataclass
from math import log2

from codepulse.core.errors import ConfigError

NODES = frozenset({
    'Call','Assign','AnnAssign','AugAssign','FunctionDef','AsyncFunctionDef','ClassDef',
    'ExceptHandler','Raise','Return','With','AsyncWith','While','For','AsyncFor',
    'Constant','JoinedStr','BinOp','Expr','Assert','Attribute','Import','ImportFrom',
    'Try','Name','Dict','keyword','Pass','If','Lambda','Subscript','Compare'
})
PREDICATES = frozenset({
    'callee', 'callee_regex', 'callee_glob', 'keyword_absent', 'keyword_present',
    'name_regex', 'literal_regex', 'decorator_regex', 'test_name', 'no_assert',
    'no_auth', 'bare_except', 'swallow', 'except_return_constant', 'under_with',
    'under_loop', 'under_async', 'filename_regex', 'ancestor', 'not_ancestor',
    'has_call', 'not_has_call', 'attr', 'value_equals', 'all', 'any', 'not',
    'call_arg_regex', 'source_regex', 'kwargs_any', 'has_assert', 'node_contains',
    'raise_literal', 'except_log_only', 'hardcoded_secret', 'string_length_gte',
    'function_lines_gt', 'call_inside_handler', 'assignment_name_regex', 'fstring',
    'literal_string', 'node_count_gt', 'has_keyword_value_regex', 'raise_bad_value',
    'ancestor_decorator_regex', 'keyword_value_regex', 'keyword_nonliteral',
    'positional_nonliteral', 'keyword_absent_regex', 'function_has_call_regex',
    'literal_external_url', 'callee_any_regex', 'bound_tool_regex',
    'resolved_callee_regex', 'resolved_callee_glob', 'scope_call_regex',
    'module_call_regex', 'dict_path_literal', 'module_has_call_regex',
    'function_branch_count_gt', 'string_entropy_gte', 'call_keyword_literal_regex', 'call_has_fstring_arg', 'ancestor_class_decorator_regex'
})


def validate_query(match: dict, path: str) -> dict:
    node = match.get('node')
    nodes = (node,) if isinstance(node, str) else node
    if not isinstance(nodes, (tuple, list)) or not nodes or any(not isinstance(n,str) or n not in NODES for n in nodes):
        raise ConfigError(f'{path}.node: expected supported Python AST node or nonempty node list, got {node!r}')
    query = match.get('where')
    if not isinstance(query, dict) or not query:
        raise ConfigError(f'{path}.where: expected nonempty predicate mapping')
    def walk(item, depth=0):
        if depth > 10 or not isinstance(item, dict) or len(item) != 1:
            raise ConfigError(f'{path}.where: predicate must be a one-key mapping (max depth 10)')
        key, val = next(iter(item.items()))
        if key not in PREDICATES:
            raise ConfigError(f'{path}.where: unknown predicate {key!r}')
        if key in ('all', 'any'):
            if not isinstance(val, list) or not val or len(val) > 20:
                raise ConfigError(f'{path}.where.{key}: nonempty list up to 20')
            for child in val: walk(child, depth + 1)
        elif key == 'not': walk(val, depth + 1)
        elif key in ('keyword_absent', 'keyword_present', 'callee', 'callee_regex',
                     'callee_glob', 'name_regex', 'literal_regex','decorator_regex',
                     'filename_regex', 'ancestor', 'not_ancestor', 'has_call',
                     'not_has_call','attr','value_equals','call_arg_regex',
                     'source_regex','node_contains','ancestor_decorator_regex',
                     'keyword_value_regex','keyword_nonliteral','keyword_absent_regex',
                     'function_has_call_regex','callee_any_regex','bound_tool_regex',
                     'resolved_callee_regex','resolved_callee_glob', 'scope_call_regex',
                     'module_call_regex', 'dict_path_literal', 'module_has_call_regex',
                     'call_keyword_literal_regex','ancestor_class_decorator_regex'):
            if not isinstance(val, str) or not val or len(val) > 256:
                raise ConfigError(f'{path}.where.{key}: expected string 1-256 chars')
            if key.endswith('_regex'):
                try: re.compile(val)
                except re.error as e: raise ConfigError(f'{path}.where.{key}: {e}') from e
            if key in ('ancestor','not_ancestor') and val not in NODES:
                raise ConfigError(f'{path}.where.{key}: unknown node class')
        elif key == 'string_entropy_gte':
            if not isinstance(val, (int,float)) or isinstance(val,bool) or not (0 <= val <= 8):
                raise ConfigError(f'{path}.where.{key}: expected number 0-8')
        elif key in ('string_length_gte', 'function_lines_gt', 'node_count_gt', 'function_branch_count_gt'):
            if type(val) is not int or not (0 <= val <= 100000):
                raise ConfigError(f'{path}.where.{key}: expected integer 0-100000')
        elif key in ('assignment_name_regex', 'has_keyword_value_regex'):
            if not isinstance(val, str) or not (1 <= len(val) <= 256):
                raise ConfigError(f'{path}.where.{key}: expected regex string')
            try: re.compile(val)
            except re.error as e: raise ConfigError(f'{path}.where.{key}: {e}') from e
        elif not isinstance(val, bool):
            raise ConfigError(f'{path}.where.{key}: expected boolean')
    walk(query)
    return {'node': tuple(nodes), 'where': query}


def _callee(node):
    if not isinstance(node, ast.Call): return ''
    try: return ast.unparse(node.func)
    except (ValueError, TypeError): return ''


def _desc(node):
    return (n for n in ast.walk(node) if n is not node)


def _calls(node):
    return (_callee(n) for n in ast.walk(node) if isinstance(n, ast.Call))


def _assigned_pairs(node: ast.AST):
    """Generic AST named binding extraction, shared by multiple external predicates."""
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, (ast.Name, ast.Attribute)):
                yield getattr(target, 'id', getattr(target, 'attr', '')), node.value
    elif isinstance(node, ast.AnnAssign) and node.value is not None:
        target = node.target
        if isinstance(target, (ast.Name, ast.Attribute)):
            yield getattr(target, 'id', getattr(target, 'attr', '')), node.value
    elif isinstance(node, ast.keyword) and node.arg is not None:
        yield node.arg, node.value
    elif isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                yield key.value, value


def _literal_text(node: ast.AST):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _log_only(node: ast.AST) -> bool:
    if not isinstance(node, ast.ExceptHandler) or not node.body:
        return False
    saw_log = False
    for stmt in node.body:
        if isinstance(stmt, (ast.Pass, ast.Continue)):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            callee = _callee(stmt.value)
            if callee.split('.')[-1] in {'debug','info','warning','warn','error','exception','critical','log','print'}:
                saw_log = True
                continue
        return False
    return saw_log


def _secret_binding(node: ast.AST) -> bool:
    secret_name = re.compile(r'(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)')
    dummy = re.compile(r'(?i)^(test|dummy|example|changeme|placeholder|your[_ -]?|<|\$\{|x{4,}|[*]{3,})')
    for name, value in _assigned_pairs(node):
        literal = _literal_text(value)
        if not secret_name.search(name) or literal is None:
            continue
        if len(literal) < 8 or dummy.search(literal) or literal.isupper() or '://' in literal:
            continue
        if re.fullmatch(r'[a-z_]+',literal):
            continue
        return True
    return False


@dataclass(frozen=True)
class QueryContext:
    """Read-only analysis facts shared by declarative predicates in a source file.

    These facts are generic Python semantics, not custom per-rule detectors.
    """
    module: ast.Module
    imports: dict[str, str]

    @classmethod
    def build(cls, module: ast.Module):
        imports: dict[str, str] = {}
        for stmt in module.body:
            if isinstance(stmt, ast.Import):
                for item in stmt.names:
                    imports[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
            elif isinstance(stmt, ast.ImportFrom) and stmt.level == 0 and stmt.module:
                for item in stmt.names:
                    if item.name != '*':
                        imports[item.asname or item.name] = f'{stmt.module}.{item.name}'
        return cls(module, imports)

    def qualified_call(self, node: ast.AST) -> str:
        callee = _callee(node)
        prefix, dot, suffix = callee.partition('.')
        if prefix in self.imports:
            return self.imports[prefix] + (dot + suffix if dot else '')
        return callee


def _dict_path_literal(node: ast.AST, dotted_path: str) -> bool:
    """Find a literal at a nested dictionary key path in a node subtree.

    e.g. config.configurable.thread_id -> 'fixed' in an ast.Call keyword value.
    """
    parts = dotted_path.split('.')
    def follow(value, depth):
        if depth == len(parts):
            return isinstance(value, ast.Constant) and isinstance(value.value, (str,int,float))
        if isinstance(value, ast.Dict):
            return any(isinstance(k, ast.Constant) and k.value == parts[depth] and follow(v,depth+1)
                       for k,v in zip(value.keys,value.values))
        return False
    if isinstance(node,ast.Call):
        for keyword in node.keywords:
            if keyword.arg == parts[0] and follow(keyword.value,1): return True
    return any(follow(n,0) for n in ast.walk(node) if isinstance(n,ast.Dict))


def _branch_count(node: ast.AST) -> int:
    if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)): return 0
    branching=(ast.If,ast.For,ast.AsyncFor,ast.While,ast.Try,ast.IfExp,ast.Match)
    n=0
    def visit(current):
        nonlocal n
        for child in ast.iter_child_nodes(current):
            if isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)): continue
            n += isinstance(child,branching)
            visit(child)
    for statement in node.body: visit(statement)
    return n


def _entropy(s: str) -> float:
    if not s: return 0.0
    return -sum((count/len(s))*log2(count/len(s)) for count in Counter(s).values())


def _scope_calls(ancestors: tuple[ast.AST,...], node: ast.AST, context: QueryContext):
    scope=next((a for a in reversed(ancestors) if isinstance(a,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))),context.module)
    return [context.qualified_call(n) for n in ast.walk(scope) if isinstance(n,ast.Call)]



def evaluate(expr: dict, node: ast.AST, ancestors: tuple[ast.AST, ...], path: str, source: str, context: QueryContext | None = None) -> bool:
    key, val = next(iter(expr.items()))
    if key == 'all': return all(evaluate(v,node,ancestors,path,source,context) for v in val)
    if key == 'any': return any(evaluate(v,node,ancestors,path,source,context) for v in val)
    if key == 'not': return not evaluate(val,node,ancestors,path,source,context)
    if key == 'call_has_fstring_arg':
        return isinstance(node,ast.Call) and any(isinstance(a,ast.JoinedStr) for a in [*node.args, *(k.value for k in node.keywords)]) == val
    if key == 'ancestor_class_decorator_regex':
        return any(re.search(val,ast.unparse(decorator)) for anc in ancestors
                   if isinstance(anc,ast.ClassDef) for decorator in anc.decorator_list)
    if key == 'resolved_callee_regex': return bool(re.search(val,context.qualified_call(node) if context else _callee(node)))
    if key == 'resolved_callee_glob': return fnmatch.fnmatchcase(context.qualified_call(node) if context else _callee(node),val)
    if key == 'scope_call_regex': return bool(context and any(re.search(val,c) for c in _scope_calls(ancestors,node,context)))
    if key == 'module_call_regex' or key == 'module_has_call_regex':
        return bool(context and any(re.search(val,context.qualified_call(c)) for c in ast.walk(context.module) if isinstance(c,ast.Call)))
    if key == 'dict_path_literal': return _dict_path_literal(node,val)
    if key == 'function_branch_count_gt': return _branch_count(node) > val
    if key == 'string_entropy_gte': return isinstance(node,ast.Constant) and isinstance(node.value,str) and _entropy(node.value) >= val
    if key == 'call_has_fstring_arg':
        return isinstance(node, ast.Call) and any(isinstance(a, ast.JoinedStr) for a in [*node.args, *(k.value for k in node.keywords)]) == val
    if key == 'call_keyword_literal_regex':
        return isinstance(node,ast.Call) and any(k.arg and isinstance(k.value,ast.Constant) and
            re.search(val,k.arg+'='+str(k.value.value)) for k in node.keywords)
    if key == 'callee': return _callee(node) == val
    if key == 'callee_regex': return bool(re.search(val, _callee(node)))
    if key == 'callee_glob': return fnmatch.fnmatchcase(_callee(node),val)
    if key == 'keyword_absent': return isinstance(node,ast.Call) and not any(k.arg == val for k in node.keywords)
    if key == 'keyword_present': return isinstance(node,ast.Call) and any(k.arg == val for k in node.keywords)
    if key == 'name_regex': return bool(re.search(val,getattr(node,'name','')))
    if key == 'literal_regex': return isinstance(node,ast.Constant) and isinstance(node.value,str) and bool(re.search(val,node.value))
    if key == 'decorator_regex': return bool(re.search(val,' '.join(ast.unparse(d) for d in getattr(node,'decorator_list',()))))
    if key == 'test_name': return getattr(node,'name','').startswith('test') == val
    if key == 'no_assert':
        has = any(isinstance(n,ast.Assert) or isinstance(n,ast.Call) and (
            _callee(n).startswith(('pytest.raises','pytest.fail','pytest.warns')) or
            _callee(n).split('.')[-1].lstrip('_').startswith(('assert','check','expect','verify')))
            for n in _desc(node))
        return (not has) == val
    if key == 'has_assert': return any(isinstance(n,ast.Assert) for n in _desc(node)) == val
    if key == 'no_auth':
        decorators = ' '.join(ast.unparse(d) for d in getattr(node,'decorator_list',()))
        is_route = bool(re.search(r'\b(get|post|put|patch|delete)\s*\(',decorators))
        protected = bool(re.search(r'\b(Depends|Security|get_current_user|auth)\b',decorators, re.I)) or bool(re.search(r'\b(Depends|Security)\s*\(', ast.unparse(getattr(node,'args',ast.arguments(posonlyargs=[],args=[],vararg=None,kwonlyargs=[],kw_defaults=[],kwarg=None,defaults=[]))), re.I))
        return (is_route and not protected) == val
    if key == 'bare_except': return (isinstance(node,ast.ExceptHandler) and node.type is None) == val
    if key == 'swallow': return (isinstance(node,ast.ExceptHandler) and bool(node.body) and all(isinstance(n,(ast.Pass,ast.Continue)) or isinstance(n,ast.Expr) and isinstance(n.value,ast.Constant) for n in node.body)) == val
    if key == 'except_return_constant': return (isinstance(node,ast.ExceptHandler) and any(isinstance(s,ast.Return) and (s.value is None or isinstance(s.value,ast.Constant)) for s in node.body)) == val
    if key == 'under_with': return any(isinstance(a,(ast.With,ast.AsyncWith)) for a in ancestors) == val
    if key == 'under_loop': return any(isinstance(a,(ast.For,ast.AsyncFor,ast.While)) for a in ancestors) == val
    if key == 'under_async': return any(isinstance(a,ast.AsyncFunctionDef) for a in ancestors) == val
    if key == 'filename_regex': return bool(re.search(val,path))
    if key == 'ancestor': return any(type(a).__name__ == val for a in ancestors)
    if key == 'not_ancestor': return not any(type(a).__name__ == val for a in ancestors)
    if key == 'has_call': return any(fnmatch.fnmatchcase(n,val) for n in _calls(node))
    if key == 'not_has_call': return not any(fnmatch.fnmatchcase(n,val) for n in _calls(node))
    if key == 'attr': return getattr(node,'attr',None) == val
    if key == 'value_equals': return isinstance(node,ast.Constant) and str(node.value) == val
    if key == 'call_arg_regex': return isinstance(node,ast.Call) and bool(re.search(val,' '.join(ast.unparse(a) for a in node.args)))
    if key == 'source_regex': return bool(re.search(val,ast.get_source_segment(source,node) or ''))
    if key == 'node_contains': return val in ast.unparse(node)
    if key == 'raise_bad_value':
        return (isinstance(node, ast.Raise) and (isinstance(node.exc, ast.Tuple) or
                isinstance(node.exc,ast.Constant) and node.exc.value is not None)) == val
    if key == 'raise_literal':
        return (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Constant)
                and node.exc.value is not None) == val
    if key == 'except_log_only': return _log_only(node) == val
    if key == 'hardcoded_secret': return _secret_binding(node) == val
    if key == 'string_length_gte':
        return isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) >= val
    if key == 'function_lines_gt':
        return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (getattr(node,'end_lineno',node.lineno)-node.lineno+1) > val
    if key == 'call_inside_handler': return any(isinstance(a,ast.ExceptHandler) for a in ancestors) == val
    if key == 'assignment_name_regex': return any(re.search(val,name) for name,_ in _assigned_pairs(node))
    if key == 'fstring': return isinstance(node,ast.JoinedStr) == val
    if key == 'literal_string': return isinstance(node,ast.Constant) and isinstance(node.value,str) == val
    if key == 'node_count_gt': return sum(1 for _ in ast.walk(node)) > val
    if key == 'has_keyword_value_regex':
        return isinstance(node,ast.Call) and any(k.arg is not None and
            re.search(val, k.arg+'='+ast.unparse(k.value)) for k in node.keywords)
    if key == 'ancestor_decorator_regex':
        return any(re.search(val, ast.unparse(d)) for a in ancestors
                   if isinstance(a,(ast.FunctionDef,ast.AsyncFunctionDef))
                   for d in a.decorator_list)
    if key == 'keyword_value_regex':
        return isinstance(node,ast.Call) and any(k.arg and
            re.search(val, k.arg+'='+ast.unparse(k.value)) for k in node.keywords)
    if key == 'keyword_nonliteral':
        return isinstance(node,ast.Call) and any(k.arg==val and
            not isinstance(k.value,ast.Constant) for k in node.keywords)
    if key == 'keyword_absent_regex':
        return isinstance(node,ast.Call) and not any(k.arg and re.search(val,k.arg)
                                                    for k in node.keywords)
    if key == 'positional_nonliteral':
        return isinstance(node,ast.Call) and bool(node.args) and (not isinstance(node.args[0],ast.Constant)) == val
    if key == 'function_has_call_regex':
        return any(re.search(val,call) for call in _calls(node))
    if key == 'callee_any_regex':
        return bool(re.search(val,_callee(node)))
    if key == 'bound_tool_regex':
        if not isinstance(node,ast.Call): return False
        callee=_callee(node)
        binder=callee.rsplit('.',1)[-1] in ('bind_tools','ToolNode','create_react_agent','create_tool_calling_agent')
        collections=[k.value for k in node.keywords if k.arg=='tools']
        if binder:
            collections.extend(node.args)
        for collection in collections:
            if isinstance(collection,(ast.List,ast.Tuple,ast.Set)):
                for elt in collection.elts:
                    name=ast.unparse(elt.func if isinstance(elt,ast.Call) else elt)
                    if re.search(val,name):
                        return True
        return False
    if key == 'literal_external_url':
        from urllib.parse import urlsplit
        if not isinstance(node,ast.Call): return False
        possible=[*node.args,*(k.value for k in node.keywords if k.arg in ('url','base_url','endpoint'))]
        for arg in possible:
            if not isinstance(arg,ast.Constant) or not isinstance(arg.value,str): continue
            parsed=urlsplit(arg.value)
            host=(parsed.hostname or '').lower()
            if parsed.scheme not in ('http','https') or not host: continue
            reserved=('localhost','127.0.0.1','0.0.0.0','::1','example.com','example.net','example.org')
            if host in reserved or host.endswith(('.example','.test','.invalid','.localhost')): continue
            return val
        return not val
    if key == 'kwargs_any': return isinstance(node,ast.Call) and any(k.arg is None for k in node.keywords) == val
    raise AssertionError(f'unvalidated predicate {key}')


def query_matches(text: str, rule, path: str, tree: ast.Module | None = None):
    """Return locations for one syntactic rule; a syntax error gives no AST matches."""
    if tree is None:
        try: tree=ast.parse(text,filename=path)
        except (SyntaxError,ValueError): return []
    out=[]
    context=QueryContext.build(tree)
    def visit(node, ancestors):
        if type(node).__name__ in rule.ast_predicate['node']:
            if evaluate(rule.ast_predicate['where'],node,ancestors,path,text,context):
                lexical = '.'.join(a.name for a in ancestors
                                   if isinstance(a, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))) or '<module>'
                out.append((node.lineno if hasattr(node,'lineno') else 1,
                            getattr(node,'col_offset',0),
                            ast.unparse(node)[:160], lexical))
        for child in ast.iter_child_nodes(node): visit(child,(*ancestors,node))
    visit(tree,())
    return out[:5000]
