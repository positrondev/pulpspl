"""Typed configuration with path-qualified validation errors. Stdlib only."""

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from codepulse.core.errors import ConfigError
from codepulse.core.model import Severity
from codepulse.core.serialization import canonical_json
from codepulse.core.validation import mapping as _mapping
from codepulse.core.validation import require as _require
from codepulse.core.validation import str_list as _str_list

DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".venv/**",
    "venv/**",
    "**/vendor/**",
    "**/migrations/**",
    "**/node_modules/**",
    "build/**",
    "dist/**",
)
DEFAULT_LEVELS: tuple[str, ...] = ("public", "internal", "confidential", "restricted")
DEFAULT_GENERATED_MARKERS: tuple[str, ...] = ("@generated", "DO NOT EDIT")
# Code that never runs in production: findings there keep their sub-check but are capped at
# low severity (classification check, 2026-11-01: 51 of 91 sampled were rated too high).
DEFAULT_NONPRODUCTION_PATHS: tuple[str, ...] = (
    "tests/**",
    "**/tests/**",
    "**/test_*.py",
    "**/*_test.py",
    "**/tests.py",
    "**/conftest.py",
    "**/*_testing/**",
    "**/testing/**",
    "**/fixtures/**",
    "examples/**",
    "**/examples/**",
    "cookbook/**",
    "**/cookbook/**",
    "**/cookbooks/**",
    "docs/**",
    "**/docs/**",
    "**/demo/**",
    "**/demos/**",
    "**/samples/**",
    "notebooks/**",
    "scripts/**",
    "benchmarks/**",
    "**/benchmarks/**",
)
# Syntax only: whether an id exists is decided by the registry, which also knows plugins.
_RULE_KEY = re.compile(r"^[A-Z][A-Z0-9]*\d{2}(\.[a-z0-9][a-z0-9-]*)?$")


@dataclass(frozen=True, slots=True)
class ClassificationRule:
    pattern: str
    level: str


CLASSIFICATION_SOURCES = ("static", "gitattributes", "chain")


@dataclass(frozen=True, slots=True)
class ClassificationConfig:
    levels: tuple[str, ...] = DEFAULT_LEVELS
    default: str = "internal"
    max_allowed: str = "internal"
    rules: tuple[ClassificationRule, ...] = ()
    source: str = "static"  # static | gitattributes | chain (spec 009 FR-905)
    attribute: str = "classification"  # the git attribute holding a file's level

    def rank(self, level: str) -> int:
        """Unknown labels (a typo in .gitattributes) rank above every level: fail closed."""
        return self.levels.index(level) if level in self.levels else len(self.levels)

    @classmethod
    def from_mapping(cls, value: object, path: str = "classification") -> "ClassificationConfig":
        data = _mapping(
            value, path, {"levels", "default", "max_allowed", "rules", "source", "attribute"}
        )
        source = _require(data.get("source", "static"), str, f"{path}.source", "string")
        if source not in CLASSIFICATION_SOURCES:
            raise ConfigError(f"{path}.source: {source!r} is not one of {CLASSIFICATION_SOURCES}")
        levels = _str_list(data.get("levels", list(DEFAULT_LEVELS)), f"{path}.levels")
        if not levels:
            raise ConfigError(f"{path}.levels: must not be empty")
        if len(set(levels)) != len(levels):
            raise ConfigError(f"{path}.levels: duplicate level names")

        def level(v: object, p: str) -> str:
            name: str = _require(v, str, p, "string")
            if name not in levels:
                raise ConfigError(f"{p}: {name!r} is not one of {list(levels)}")
            return name

        fallback = "internal" if "internal" in levels else levels[0]
        rules_raw = _require(data.get("rules") or [], list, f"{path}.rules", "list")
        rules = []
        for i, r in enumerate(rules_raw):
            rp = f"{path}.rules[{i}]"
            rd = _mapping(r, rp, {"pattern", "level"})
            rules.append(
                ClassificationRule(
                    pattern=_require(rd.get("pattern"), str, f"{rp}.pattern", "string"),
                    level=level(rd.get("level"), f"{rp}.level"),
                )
            )
        return cls(
            levels=levels,
            default=level(data.get("default", fallback), f"{path}.default"),
            max_allowed=level(data.get("max_allowed", fallback), f"{path}.max_allowed"),
            rules=tuple(rules),
            source=source,
            attribute=_require(
                data.get("attribute", "classification"), str, f"{path}.attribute", "string"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "levels": list(self.levels),
            "default": self.default,
            "max_allowed": self.max_allowed,
            "rules": [{"pattern": r.pattern, "level": r.level} for r in self.rules],
            "source": self.source,
            "attribute": self.attribute,
        }


@dataclass(frozen=True, slots=True)
class RuleOverride:
    enabled: bool | None = None
    severity: Severity | None = None
    options: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: object, path: str) -> "RuleOverride":
        data = _mapping(value, path, {"enabled", "severity", "options"})
        enabled = data.get("enabled")
        if enabled is not None:
            _require(enabled, bool, f"{path}.enabled", "bool")
        severity = None
        if "severity" in data:
            raw = _require(data["severity"], str, f"{path}.severity", "string")
            try:
                severity = Severity(raw)
            except ValueError:
                raise ConfigError(
                    f"{path}.severity: {raw!r} is not one of {[str(s) for s in Severity]}"
                ) from None
        options = _require(data.get("options", {}), dict, f"{path}.options", "mapping")
        return cls(enabled=enabled, severity=severity, options=dict(options))

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "severity": None if self.severity is None else str(self.severity),
            "options": dict(self.options),
        }


SEMANTIC_BACKENDS = ("null", "openai_compatible")
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True, slots=True)
class SemanticConfig:
    """Constitution Art. VII lives here: a backend that may send data must be allow-listed
    and must declare no retention and no training, or loading the config fails."""

    backend: str = "null"
    base_url: str | None = None  # e.g. https://llm-gateway.internal/v1
    model: str | None = None
    api_key_env: str | None = None  # name of the env var holding the key; never the key
    retention: str | None = None  # must be "none"
    training: str | None = None  # must be "prohibited"
    allowed_hosts: tuple[str, ...] = ()
    timeout_s: int = 30
    max_tokens: int = 400
    token_budget: int = 50_000
    min_confidence: float = 0.75
    json_mode: bool = True
    cache_dir: str = ".codepulse/cache"
    egress_log: str = ".codepulse/egress.jsonl"
    redact_patterns: tuple[str, ...] = ()
    validation_record: str | None = None  # eval.json from `codepulse eval` (spec 006 FR-607)

    @classmethod
    def from_mapping(cls, value: object, path: str = "semantic") -> "SemanticConfig":
        data = _mapping(value, path, set(cls.__dataclass_fields__))
        d = cls()

        def opt_str(key: str) -> str | None:
            v = data.get(key)
            return None if v is None else _require(v, str, f"{path}.{key}", "string")

        def num(key: str, kind: type, default: object) -> Any:
            v = data.get(key, default)
            if kind is float and isinstance(v, int) and not isinstance(v, bool):
                return float(v)
            return _require(v, kind, f"{path}.{key}", kind.__name__)

        cfg = cls(
            backend=_require(data.get("backend", d.backend), str, f"{path}.backend", "string"),
            base_url=opt_str("base_url"),
            model=opt_str("model"),
            api_key_env=opt_str("api_key_env"),
            retention=opt_str("retention"),
            training=opt_str("training"),
            allowed_hosts=_str_list(data.get("allowed_hosts", []), f"{path}.allowed_hosts"),
            timeout_s=num("timeout_s", int, d.timeout_s),
            max_tokens=num("max_tokens", int, d.max_tokens),
            token_budget=num("token_budget", int, d.token_budget),
            min_confidence=num("min_confidence", float, d.min_confidence),
            json_mode=num("json_mode", bool, d.json_mode),
            cache_dir=_require(
                data.get("cache_dir", d.cache_dir), str, f"{path}.cache_dir", "string"
            ),
            egress_log=_require(
                data.get("egress_log", d.egress_log), str, f"{path}.egress_log", "string"
            ),
            redact_patterns=_str_list(data.get("redact_patterns", []), f"{path}.redact_patterns"),
            validation_record=opt_str("validation_record"),
        )
        cfg._validate(path)
        return cfg

    def _validate(self, path: str) -> None:
        if self.backend not in SEMANTIC_BACKENDS:
            raise ConfigError(
                f"{path}.backend: {self.backend!r} is not one of {list(SEMANTIC_BACKENDS)}"
            )
        if not 0.0 <= self.min_confidence <= 1.0:
            raise ConfigError(f"{path}.min_confidence: must be between 0 and 1")
        for key in ("timeout_s", "max_tokens", "token_budget"):
            if getattr(self, key) <= 0:
                raise ConfigError(f"{path}.{key}: must be positive")
        for i, pattern in enumerate(self.redact_patterns):
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(f"{path}.redact_patterns[{i}]: {exc}") from None
        if self.backend == "null":
            return
        if not self.base_url or not self.model:
            raise ConfigError(f"{path}: base_url and model are required for {self.backend}")
        if self.retention != "none" or self.training != "prohibited":
            raise ConfigError(
                f"{path}: a backend that receives code must declare retention: none and "
                "training: prohibited (Constitution Art. VII)"
            )
        parts = urlsplit(self.base_url)
        host = parts.hostname or ""
        if host not in self.allowed_hosts:
            raise ConfigError(f"{path}.base_url: host {host!r} is not in allowed_hosts")
        if parts.scheme != "https" and not (parts.scheme == "http" and host in _LOCAL_HOSTS):
            raise ConfigError(f"{path}.base_url: https is required except for localhost")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name in self.__dataclass_fields__:
            v = getattr(self, name)
            out[name] = list(v) if isinstance(v, tuple) else v
        return out


@dataclass(frozen=True, slots=True)
class SonarQubeConfig:
    base_url: str
    project_key: str
    token_env: str = "SONARQUBE_TOKEN"  # noqa: S105 — the env var's name, not a secret
    edition: str = "community"  # community: no branch analysis | developer | enterprise

    @classmethod
    def from_mapping(cls, value: object, path: str = "sonarqube") -> "SonarQubeConfig":
        data = _mapping(
            value,
            path,
            {"base_url", "project_key", "token_env", "edition"},
            required={"base_url", "project_key"},
        )
        base = _require(data["base_url"], str, f"{path}.base_url", "string")
        if urlsplit(base).scheme not in ("https", "http"):
            raise ConfigError(f"{path}.base_url: expected an http(s) URL")
        return cls(
            base,
            _require(data["project_key"], str, f"{path}.project_key", "string"),
            _require(data.get("token_env", "SONARQUBE_TOKEN"), str, f"{path}.token_env", "string"),
            _require(data.get("edition", "community"), str, f"{path}.edition", "string"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "project_key": self.project_key,
            "token_env": self.token_env,
            "edition": self.edition,
        }


DEFAULT_STORE_URL = "sqlite:///.codepulse/codepulse.db"


@dataclass(frozen=True, slots=True)
class StoreConfig:
    url: str = DEFAULT_STORE_URL
    url_env: str | None = None  # env var holding a server URL; credentials never live in the file
    enabled: bool = True  # every review records by default (spec 009 FR-907); --no-store opts out

    @property
    def auto_migrate(self) -> bool:
        """Only CodePulse's own local SQLite file is migrated implicitly; a shared server
        database gets DDL only from an explicit `codepulse db upgrade`."""
        return self.url_env is None and self.url.startswith("sqlite")

    @classmethod
    def from_mapping(cls, value: object, path: str = "store") -> "StoreConfig":
        data = _mapping(value, path, {"url", "url_env", "enabled"})
        url = _require(data.get("url", DEFAULT_STORE_URL), str, f"{path}.url", "string")
        url_env = data.get("url_env")
        if url_env is not None:
            _require(url_env, str, f"{path}.url_env", "string")
        if "@" in url.split("://", 1)[-1].split("/", 1)[0]:
            raise ConfigError(
                f"{path}.url: credentials in the file; put the URL in an env var and set url_env"
            )
        enabled = _require(data.get("enabled", True), bool, f"{path}.enabled", "bool")
        return cls(url, url_env, enabled)

    def resolve_url(self, environ: Mapping[str, str]) -> str:
        if self.url_env is None:
            return self.url
        value = environ.get(self.url_env)
        if not value:
            raise ConfigError(f"store.url_env: environment variable {self.url_env} is not set")
        return value

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "url_env": self.url_env, "enabled": self.enabled}


@dataclass(frozen=True, slots=True)
class ExternalRulesConfig:
    enabled: bool = False
    directories: tuple[str, ...] = ()
    strict_validation: bool = True
    builtin_metadata: str | None = None
    mode: str = "legacy"  # legacy | external_only

    @classmethod
    def from_mapping(cls, value: object) -> "ExternalRulesConfig":
        data = _mapping(value, "external_rules", {"enabled", "directories", "strict_validation", "builtin_metadata", "mode"})
        enabled = _require(data.get("enabled", False), bool, "external_rules.enabled", "bool")
        dirs = _str_list(data.get("directories", []), "external_rules.directories")
        strict = _require(data.get("strict_validation", True), bool, "external_rules.strict_validation", "bool")
        if enabled and not dirs:
            raise ConfigError("external_rules.directories: at least one directory required when enabled")
        if not strict:
            raise ConfigError("external_rules.strict_validation: phase 1 requires strict validation")
        metadata = data.get("builtin_metadata")
        if metadata is not None:
            metadata = _require(metadata, str, "external_rules.builtin_metadata", "string")
            if not metadata.strip():
                raise ConfigError("external_rules.builtin_metadata: expected a non-empty path")
        mode = data.get("mode", "legacy")
        if mode not in ("legacy", "external_only"):
            raise ConfigError("external_rules.mode: expected legacy or external_only")
        if mode == "external_only" and not enabled:
            raise ConfigError("external_rules.mode external_only requires enabled: true")
        return cls(enabled, dirs, strict, metadata, mode)

    def to_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "directories": list(self.directories),
                "strict_validation": self.strict_validation, "mode": self.mode,
                **({"builtin_metadata": self.builtin_metadata} if self.builtin_metadata else {})}


@dataclass(frozen=True, slots=True)
class Config:
    base_ref: str = "origin/main"
    output_dir: str = ".codepulse/out"
    dashboard_dir: str = ".codepulse/dashboard"  # refreshed after every stored review
    exclude: tuple[str, ...] = DEFAULT_EXCLUDES
    generated_markers: tuple[str, ...] = DEFAULT_GENERATED_MARKERS
    classification: ClassificationConfig = field(default_factory=ClassificationConfig)
    rules: Mapping[str, RuleOverride] = field(default_factory=dict)
    catalogs: Mapping[str, tuple[Any, ...]] = field(default_factory=dict)  # extends defaults
    semantic: SemanticConfig = field(default_factory=SemanticConfig)
    sonarqube: SonarQubeConfig | None = None
    store: StoreConfig = field(default_factory=StoreConfig)
    include_experimental: bool = False
    nonproduction_paths: tuple[str, ...] = DEFAULT_NONPRODUCTION_PATHS
    nonproduction_max_severity: Severity | None = Severity.LOW
    external_rules: ExternalRulesConfig = field(default_factory=ExternalRulesConfig)
    index_enabled: bool = True  # project index for cross-file sub-checks (spec 005)

    @classmethod
    def from_mapping(cls, value: object) -> "Config":
        data = _mapping(
            value,
            "config",
            {
                "base_ref",
                "output_dir",
                "dashboard_dir",
                "exclude",
                "generated_markers",
                "classification",
                "rules",
                "catalogs",
                "semantic",
                "sonarqube",
                "store",
                "include_experimental",
                "index",
                "nonproduction",
                "external_rules",
            },
        )
        index = _mapping(data.get("index") or {}, "index", {"enabled"})
        nonprod = _mapping(
            data.get("nonproduction") or {}, "nonproduction", {"paths", "max_severity"}
        )
        cap = nonprod.get("max_severity", Severity.LOW.value)
        if cap is not None and cap not in {s.value for s in Severity}:
            raise ConfigError(f"nonproduction.max_severity: unknown severity {cap!r}")
        # A YAML section whose entries are all commented out parses as null: treat as empty.
        rules_raw = _require(data.get("rules") or {}, dict, "rules", "mapping")
        rules: dict[str, RuleOverride] = {}
        for key, override in rules_raw.items():
            if not isinstance(key, str) or not _RULE_KEY.match(key):
                raise ConfigError(
                    f"rules: invalid rule id {key!r} (expected e.g. E04 or E04.no-timeout)"
                )
            rules[key] = RuleOverride.from_mapping(override or {}, f"rules.{key}")
        return cls(
            base_ref=_require(data.get("base_ref", "origin/main"), str, "base_ref", "string"),
            dashboard_dir=_require(
                data.get("dashboard_dir", ".codepulse/dashboard"),
                str,
                "dashboard_dir",
                "string",
            ),
            output_dir=_require(
                data.get("output_dir", ".codepulse/out"), str, "output_dir", "string"
            ),
            exclude=_str_list(data.get("exclude", list(DEFAULT_EXCLUDES)), "exclude"),
            generated_markers=_str_list(
                data.get("generated_markers", list(DEFAULT_GENERATED_MARKERS)), "generated_markers"
            ),
            classification=ClassificationConfig.from_mapping(data.get("classification") or {}),
            rules=rules,
            semantic=SemanticConfig.from_mapping(data.get("semantic") or {}),
            store=StoreConfig.from_mapping(data.get("store") or {}),
            include_experimental=_require(
                data.get("include_experimental", False), bool, "include_experimental", "bool"
            ),
            external_rules=ExternalRulesConfig.from_mapping(data.get("external_rules") or {}),
            index_enabled=_require(index.get("enabled", True), bool, "index.enabled", "bool"),
            nonproduction_paths=_str_list(
                nonprod.get("paths", list(DEFAULT_NONPRODUCTION_PATHS)), "nonproduction.paths"
            ),
            nonproduction_max_severity=Severity(cap) if cap is not None else None,
            sonarqube=(
                SonarQubeConfig.from_mapping(data["sonarqube"]) if data.get("sonarqube") else None
            ),
            catalogs={
                name: tuple(_require(entries, list, f"catalogs.{name}", "list"))
                for name, entries in _require(
                    data.get("catalogs") or {}, dict, "catalogs", "mapping"
                ).items()
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_ref": self.base_ref,
            "output_dir": self.output_dir,
            "dashboard_dir": self.dashboard_dir,
            "exclude": list(self.exclude),
            "generated_markers": list(self.generated_markers),
            "classification": self.classification.to_dict(),
            "rules": {k: v.to_dict() for k, v in self.rules.items()},
            "catalogs": {k: list(v) for k, v in self.catalogs.items()},
            "semantic": self.semantic.to_dict(),
            "sonarqube": self.sonarqube.to_dict() if self.sonarqube else None,
            "store": self.store.to_dict(),
            "include_experimental": self.include_experimental,
            "index": {"enabled": self.index_enabled},
            "nonproduction": {
                "paths": list(self.nonproduction_paths),
                "max_severity": (
                    self.nonproduction_max_severity.value
                    if self.nonproduction_max_severity
                    else None
                ),
            },
        }

    def config_hash(self) -> str:
        """No external packs: preserve historical configuration hashes."""
        data = self.to_dict()
        if self.external_rules.enabled or self.external_rules.builtin_metadata:
            data["external_rules"] = self.external_rules.to_dict()
        return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()
