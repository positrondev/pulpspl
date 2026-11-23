"""Strict loading and validation of non-executable YAML rule packs."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from codepulse.core.errors import ConfigError
from codepulse.core.model import Component, Severity, Detection

RULE_ID = re.compile(r"^[A-Z][A-Z0-9]*\d{2,5}\.[a-z0-9][a-z0-9-]*$")
LANGUAGES = {"python": ".py", "java": ".java", "javascript": ".js", "typescript": ".ts", "config": None}


@dataclass(frozen=True, slots=True)
class ExternalRule:
    id: str
    match_type: str
    name: str
    languages: tuple[str, ...]
    patterns: tuple[tuple[str, str], ...]
    includes: tuple[str, ...]
    excludes: tuple[str, ...]
    severity: Severity
    component: Component
    message: str
    remediation: str
    enabled: bool
    pack_id: str
    pack_version: str
    ast_predicate: dict | None = None
    detection: Detection = Detection.DETERMINISTIC

    @property
    def rule_id(self) -> str:
        return self.id.split(".", 1)[0]

    def pattern_for(self, language: str) -> str | None:
        return dict(self.patterns).get(language)


def _keys(obj: object, required: set[str], allowed: set[str], where: str) -> dict:
    if not isinstance(obj, dict):
        raise ConfigError(f"{where}: expected mapping")
    unknown = set(obj) - allowed
    missing = required - set(obj)
    if unknown or missing:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)}, missing keys {sorted(missing)}")
    return obj


def _str(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}: expected non-empty string")
    return value


def _strings(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
        raise ConfigError(f"{where}: expected list of non-empty strings")
    return tuple(value)


def load_rules(repo: Path, directories: tuple[str, ...], *, allow_external_paths: bool = False) -> tuple[ExternalRule, ...]:
    """Strictly parse declarative rules. Absolute rule paths allowed only in isolated mode."""
    result: list[ExternalRule] = []
    seen: set[str] = set()
    root = repo.resolve()
    for directory in directories:
        folder = (root / directory).resolve()
        if not allow_external_paths and not folder.is_relative_to(root):
            raise ConfigError(f"external_rules.directories: outside repository: {directory}")
        if not folder.is_dir():
            raise ConfigError(f"external_rules.directories: directory does not exist: {folder}")
        for file in sorted((*folder.rglob("*.yaml"), *folder.rglob("*.yml"))):
            if not file.resolve().is_relative_to(folder):
                raise ConfigError(f"external rule file outside configured directory: {file}")
            where = str(file)
            try:
                raw = yaml.safe_load(file.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, yaml.YAMLError) as exc:
                raise ConfigError(f"{where}: unable to read rule pack: {exc}") from exc
            doc = _keys(raw, {"schema_version", "pack", "rules"}, {"schema_version", "pack", "rules"}, where)
            if type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
                raise ConfigError(f"{where}.schema_version: only version 1 is supported")
            pack = _keys(doc["pack"], {"id", "version"}, {"id", "version"}, where + ".pack")
            pack_id = _str(pack["id"], where + ".pack.id")
            pack_version = _str(pack["version"], where + ".pack.version")
            if not isinstance(doc["rules"], list):
                raise ConfigError(f"{where}.rules: expected list")
            for i, item in enumerate(doc["rules"]):
                p = f"{where}.rules[{i}]"
                data = _keys(item, {"id", "name", "languages", "match", "severity", "message", "remediation"},
                    {"id", "name", "description", "languages", "files", "match", "severity", "message", "remediation", "enabled", "component", "detection"}, p)
                sid = _str(data["id"], p + ".id")
                if not RULE_ID.fullmatch(sid):
                    raise ConfigError(f"{p}.id: expected E04.no-timeout or CP100.no-debug")
                if sid in seen:
                    raise ConfigError(f"{p}.id: duplicate external rule {sid}")
                seen.add(sid)
                languages = _strings(data["languages"], p + ".languages")
                if not languages or len(set(languages)) != len(languages) or set(languages) - LANGUAGES.keys():
                    raise ConfigError(f"{p}.languages: choose unique languages from {sorted(LANGUAGES)}")
                if "description" in data:
                    _str(data["description"], p + ".description")
                detection = data.get("detection", "deterministic")
                if detection not in ("deterministic", "heuristic"):
                    raise ConfigError(f"{p}.detection: supported: deterministic, heuristic")
                enabled = data.get("enabled", True)
                if not isinstance(enabled, bool):
                    raise ConfigError(f"{p}.enabled: expected boolean")
                files = _keys(data.get("files", {}), set(), {"include", "exclude"}, p + ".files")
                inc = _strings(files.get("include", ["**/*"]), p + ".files.include")
                exc = _strings(files.get("exclude", []), p + ".files.exclude")
                match = _keys(data["match"], {"type"}, {"type", "patterns", "node", "where", "source_calls", "source_parameters", "sink_calls", "sanitizer_calls"}, p + ".match")
                if match["type"] not in ("regex", "text", "python_ast", "python_flow"):
                    raise ConfigError(f"{p}.match.type: supported: regex, text, python_ast, python_flow")
                predicate = None
                if match["type"] in ("python_ast", "python_flow"):
                    if languages != ("python",):
                        raise ConfigError(f"{p}: {match["type"]} requires languages: [python]")
                    if "patterns" in match:
                        raise ConfigError(f"{p}.match: python_ast does not accept patterns")
                    if match["type"] == "python_ast":
                        from codepulse.external_rules.ast_matcher import validate_query
                        predicate = validate_query(match, p + ".match")
                    else:
                        from codepulse.external_rules.flow_matcher import validate_flow
                        predicate = validate_flow(match, p + ".match")
                    patterns = {}
                else:
                    patterns = _keys(match.get("patterns"), set(languages), set(languages), p + ".match.patterns")
                parsed = []
                for lang in (languages if match["type"] not in ("python_ast", "python_flow") else ()):
                    expression = _str(patterns[lang], p + f".match.patterns.{lang}")
                    if len(expression) > 512:
                        raise ConfigError(f"{p}.match.patterns.{lang}: maximum 512 characters")
                    if match["type"] == "regex":
                        try:
                            re.compile(expression)
                        except re.error as exc:
                            raise ConfigError(f"{p}.match.patterns.{lang}: invalid regex: {exc}") from exc
                    parsed.append((lang, expression))
                try:
                    severity = Severity(_str(data["severity"], p + ".severity"))
                    component = Component(data.get("component", "other"))
                except ValueError as exc:
                    raise ConfigError(f"{p}: invalid severity or component: {exc}") from exc
                # Runtime matcher is retained in a side mapping, so rule metadata remains portable.
                result.append(ExternalRule(sid, match["type"], _str(data["name"], p + ".name"),
                    languages, tuple(parsed), inc, exc, severity, component,
                    _str(data["message"], p + ".message"),
                    _str(data["remediation"], p + ".remediation"),
                    enabled, pack_id, pack_version, predicate, Detection(detection)))
    return tuple(result)

