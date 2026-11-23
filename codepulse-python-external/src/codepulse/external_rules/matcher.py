"""Line-scoped deterministic text/regex matching, producing standard findings."""
from __future__ import annotations

import ast
import re
from dataclasses import replace

from codepulse.core.engine.visitor import FileAnalysis, RuleError
from codepulse.core.fingerprint import FingerprintInput, assign_fingerprints
from codepulse.core.globs import compile_globs
from codepulse.core.model import Detection, Finding, Location, Origin
from codepulse.external_rules.loader import LANGUAGES
from codepulse.core.resolver import TOOL_CONFIG_NAMES

MAX_LINE_CHARS = 4096
MAX_HITS_PER_FILE = 5000


def language_for(path: str) -> str | None:
    if path.rsplit("/", 1)[-1] in TOOL_CONFIG_NAMES:
        return "config"
    return next((lang for lang, ext in LANGUAGES.items() if ext is not None and path.endswith(ext)), None)


def applies(rule, path: str, language: str) -> bool:
    return (language in rule.languages and compile_globs(rule.includes)(path) is not None
            and compile_globs(rule.excludes)(path) is None)


def match_file(analysis: FileAnalysis, text: str, registry) -> FileAnalysis:
    language = language_for(analysis.path)
    if language is None or analysis.skip is not None or not registry.external_rules:
        return analysis
    matches = []
    ast_tree = None
    ast_failure = None
    if language == 'python' and any(r.match_type in ('python_ast', 'python_flow') and applies(r, analysis.path, language)
                                    for r in registry.external_rules):
        try:
            ast_tree = ast.parse(text, filename=analysis.path)
        except (SyntaxError, ValueError) as exc:
            ast_failure = RuleError('external.python_ast', analysis.path,
                                    max(1, getattr(exc, 'lineno', 1) or 1),
                                    f'Python AST unavailable: {exc}')
    for rule in registry.external_rules:
        if not applies(rule, analysis.path, language):
            continue
        if rule.match_type in ("python_ast", "python_flow"):
            if rule.match_type == "python_ast":
                from codepulse.external_rules.ast_matcher import query_matches
            else:
                from codepulse.external_rules.flow_matcher import flow_matches as query_matches
            if ast_failure is not None:
                continue
            meta = registry.meta(rule.id)
            for line_num, column, signature, scope in query_matches(text, rule, analysis.path, ast_tree):
                matches.append((rule, meta, line_num, column, signature, scope))
                if len(matches) >= MAX_HITS_PER_FILE:
                    break
            if len(matches) >= MAX_HITS_PER_FILE:
                break
            continue
        expression = rule.pattern_for(language)
        if expression is None:
            continue
        kind = rule.match_type
        regex = re.compile(expression) if kind == "regex" else None
        meta = registry.meta(rule.id)
        for line_num, line in enumerate(text.splitlines(), 1):
            if len(line) > MAX_LINE_CHARS:
                continue
            # One finding per rule per matching line; avoids excessive duplicate reports.
            found = regex.search(line) if regex else (expression if expression in line else None)
            if found is None:
                continue
            # Matched text, rather than line number, gives stable identity for moved lines.
            signature = found.group(0) if regex else expression
            column = found.start() if regex else line.index(expression)
            matches.append((rule, meta, line_num, column, signature, "<module>"))
            if len(matches) >= MAX_HITS_PER_FILE:
                break
        if len(matches) >= MAX_HITS_PER_FILE:
            break
    keys = [FingerprintInput(rule.id, analysis.path, scope, signature, (line, col))
            for rule, _, line, col, signature, scope in matches]
    fps = assign_fingerprints(keys)
    findings = [Finding(fp, rule.rule_id, rule.id, meta.severity, rule.detection,
        Origin.NOT_APPLICABLE, Location(analysis.path, line, line, scope),
        meta.component, meta.message, meta.remediation)
        for (rule, meta, line, _, _, scope), fp in zip(matches, fps)]
    return replace(analysis, findings=(*analysis.findings, *findings),
                   rule_errors=(*analysis.rule_errors, *((ast_failure,) if ast_failure else ())))
