"""Node signatures: the construct part of a fingerprint.

Deliberately coarse. A call is identified by its callee, not its arguments, so that
fixing one sub-check (adding ``max_tokens=``) does not change the identity of a
sibling finding on the same call (``E04.no-timeout``). Positions never participate.
"""

import ast


def _expr(node: ast.expr | None) -> str:
    return "bare" if node is None else ast.unparse(node)


def node_signature(node: ast.AST) -> str:
    match node:
        case ast.Call(func=func):
            return f"Call:{ast.unparse(func)}"
        case ast.FunctionDef(name=name) | ast.AsyncFunctionDef(name=name) | ast.ClassDef(name=name):
            return f"{type(node).__name__}:{name}"
        case ast.ExceptHandler(type=exc_type):
            return f"ExceptHandler:{_expr(exc_type)}"
        case ast.Assign(targets=targets):
            return "Assign:" + ",".join(ast.unparse(t) for t in targets)
        case ast.AnnAssign(target=target) | ast.AugAssign(target=target):
            return f"{type(node).__name__}:{ast.unparse(target)}"
        case ast.keyword(arg=arg):
            return f"keyword:{arg or '**'}"
        case _:
            return type(node).__name__
