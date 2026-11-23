"""Merge rule packs and config overrides into one validated, versioned registry."""

import ast
import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from codepulse.core.config import Config, RuleOverride
from codepulse.core.errors import RegistryError
from codepulse.core.model import Component, Detection, Severity
from codepulse.core.rule import (
    COMMENTS,
    CONFIG_FILES,
    STATIC_DETECTIONS,
    Catalog,
    Indexer,
    RulePack,
    SubCheck,
)
from codepulse.core.validation import mapping, require

_RULE_ID = re.compile(r"^[A-Z][A-Z0-9]*\d{2}$")
_SUB_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")


@dataclass(frozen=True, slots=True)
class SubCheckMeta:
    id: str
    rule_id: str
    rule_name: str
    component: Component
    detection: Detection
    severity: Severity
    message: str  # str.format template filled from RawFinding.details
    remediation: str
    enabled: bool
    options: Mapping[str, Any]
    experimental: bool = False


def _enum[E: (Severity, Detection, Component)](cls: type[E], value: object, path: str) -> E:
    raw = require(value, str, path, "string", RegistryError)
    try:
        return cls(raw)
    except ValueError:
        raise RegistryError(f"{path}: {raw!r} is not one of {[str(m) for m in cls]}") from None


def _parse_rule(rule_id: str, rule: object, path: str) -> list[SubCheckMeta]:
    data = mapping(
        rule,
        path,
        {"name", "component", "options", "subchecks"},
        RegistryError,
        required={"name", "component", "subchecks"},
    )
    name = require(data["name"], str, f"{path}.name", "string", RegistryError)
    component = _enum(Component, data["component"], f"{path}.component")
    rule_opts = require(
        data.get("options") or {}, dict, f"{path}.options", "mapping", RegistryError
    )
    subs = require(data["subchecks"], dict, f"{path}.subchecks", "mapping", RegistryError)
    out = []
    for sub_name, sub in subs.items():
        sp = f"{path}.subchecks.{sub_name}"
        if not isinstance(sub_name, str) or not _SUB_NAME.match(sub_name):
            raise RegistryError(f"{path}.subchecks: invalid sub-check name {sub_name!r}")
        sd = mapping(
            sub,
            sp,
            {
                "detection",
                "severity",
                "message",
                "remediation",
                "enabled",
                "experimental",
                "options",
            },
            RegistryError,
            required={"detection", "severity", "message", "remediation"},
        )
        detection = _enum(Detection, sd["detection"], f"{sp}.detection")
        if detection not in STATIC_DETECTIONS:
            raise RegistryError(
                f"{sp}.detection: {detection} is assigned at run time, not declared"
            )
        sub_opts = require(sd.get("options") or {}, dict, f"{sp}.options", "mapping", RegistryError)
        out.append(
            SubCheckMeta(
                id=f"{rule_id}.{sub_name}",
                rule_id=rule_id,
                rule_name=name,
                component=component,
                detection=detection,
                severity=_enum(Severity, sd["severity"], f"{sp}.severity"),
                message=require(sd["message"], str, f"{sp}.message", "string", RegistryError),
                remediation=require(
                    sd["remediation"], str, f"{sp}.remediation", "string", RegistryError
                ),
                enabled=require(
                    sd.get("enabled", True), bool, f"{sp}.enabled", "bool", RegistryError
                ),
                options={**rule_opts, **sub_opts},
                experimental=require(
                    sd.get("experimental", False), bool, f"{sp}.experimental", "bool", RegistryError
                ),
            )
        )
    return out


def _check_option_type(default: object, value: object, path: str) -> None:
    if default is None:
        return
    if isinstance(default, bool) or isinstance(value, bool):
        ok = isinstance(default, bool) and isinstance(value, bool)
    elif isinstance(default, float):
        ok = isinstance(value, int | float)  # 5 is a fine value for a 4.5 default
    else:
        ok = isinstance(value, type(default))
    if not ok:
        raise RegistryError(
            f"{path}: expected {type(default).__name__}, got {type(value).__name__}"
        )


def _apply(meta: SubCheckMeta, override: RuleOverride | None) -> SubCheckMeta:
    if override is None:
        return meta
    options = dict(meta.options)
    options.update({k: v for k, v in override.options.items() if k in options})
    return replace(
        meta,
        enabled=meta.enabled if override.enabled is None else override.enabled,
        severity=override.severity or meta.severity,
        options=options,
    )


def _validate_override(key: str, override: RuleOverride, metas: Sequence[SubCheckMeta]) -> None:
    known: dict[str, object] = {}
    for m in metas:
        known.update(m.options)
    unknown = sorted(set(override.options) - set(known))
    if unknown:
        raise RegistryError(f"rules.{key}.options: unknown option(s): {', '.join(unknown)}")
    for name, value in override.options.items():
        _check_option_type(known[name], value, f"rules.{key}.options.{name}")


def _parse_catalogs(catalogs: Mapping[str, Catalog], config: Config) -> dict[str, Any]:
    for name in config.catalogs:
        if name not in catalogs:
            raise RegistryError(f"catalogs: unknown catalog {name!r}")
    parsed = {}
    for name, cat in sorted(catalogs.items()):
        entries = [*cat.defaults, *config.catalogs.get(name, ())]
        try:
            parsed[name] = cat.parse(entries)
        except (ValueError, TypeError, KeyError) as exc:
            raise RegistryError(f"catalogs.{name}: {exc}") from exc
    return parsed


class RuleRegistry:
    def __init__(
        self,
        version: str,
        metas: Mapping[str, SubCheckMeta],
        active: tuple[SubCheck, ...],
        unimplemented: tuple[str, ...],
        catalogs: Mapping[str, Any] | None = None,
        prompts: Mapping[str, Any] | None = None,
    ) -> None:
        self.version = version
        self.experimental_skipped: tuple[str, ...] = ()
        self.indexers: tuple[Indexer, ...] = ()
        self.unresolved_watch: tuple[str, ...] = ()
        self.catalogs = dict(catalogs or {})
        self.prompts = dict(prompts or {})  # sub-check id -> PromptTemplate
        self._metas = dict(metas)
        self.active = active
        self.external_rules = ()
        self.unimplemented = unimplemented
        table: dict[type[ast.AST], list[SubCheck]] = defaultdict(list)
        comments: list[SubCheck] = []
        configs: list[SubCheck] = []
        for sc in active:
            if sc.subscribes == COMMENTS:
                comments.append(sc)
            elif sc.subscribes == CONFIG_FILES:
                configs.append(sc)
            else:
                for node_type in sc.subscribes:
                    table[node_type].append(sc)
        self._table = {t: tuple(v) for t, v in table.items()}
        self.comment_checks = tuple(comments)
        self.config_checks = tuple(configs)

    @property
    def rule_names(self) -> dict[str, str]:
        return {m.rule_id: m.rule_name for m in self._metas.values()}

    @property
    def index_checks(self) -> tuple[str, ...]:
        """Active sub-checks that need the project index (spec 005 FR-505)."""
        return tuple(sc.id for sc in self.active if sc.needs_index)

    def node_checks(self, node_type: type[ast.AST]) -> tuple[SubCheck, ...]:
        return self._table.get(node_type, ())

    def meta(self, subcheck_id: str) -> SubCheckMeta:
        return self._metas[subcheck_id]

    def options(self, subcheck_id: str) -> Mapping[str, Any]:
        return self._metas[subcheck_id].options

    @classmethod
    def build(cls, packs: Iterable[RulePack], config: Config, external_rules=()) -> "RuleRegistry":
        packs = sorted(packs, key=lambda p: p.name)
        metas: dict[str, SubCheckMeta] = {}
        owner: dict[str, str] = {}
        impls: dict[str, SubCheck] = {}
        catalogs: dict[str, tuple[str, Catalog]] = {}
        indexers: dict[str, Indexer] = {}
        labels = []
        for pack in packs:
            data = mapping(
                pack.metadata, pack.name, {"version", "rules"}, RegistryError, {"version"}
            )
            version = require(data["version"], str, f"{pack.name}.version", "string", RegistryError)
            labels.append(f"{pack.name}@{version}")
            rules = require(
                data.get("rules") or {}, dict, f"{pack.name}.rules", "mapping", RegistryError
            )
            for rule_id, rule in rules.items():
                if not isinstance(rule_id, str) or not _RULE_ID.match(rule_id):
                    raise RegistryError(f"{pack.name}: invalid rule id {rule_id!r}")
                if rule_id in owner:
                    raise RegistryError(
                        f"rule {rule_id} is defined by both {owner[rule_id]} and {pack.name}"
                    )
                owner[rule_id] = pack.name
                for m in _parse_rule(rule_id, rule, f"{pack.name}:rules.{rule_id}"):
                    metas[m.id] = m
            for cat in pack.catalogs:
                if cat.name in catalogs:
                    raise RegistryError(
                        f"catalog {cat.name!r} is defined by both {catalogs[cat.name][0]} "
                        f"and {pack.name}"
                    )
                catalogs[cat.name] = (pack.name, cat)
            for ix in pack.indexers:
                if ix.name in indexers:
                    raise RegistryError(f"indexer {ix.name!r} is defined twice")
                indexers[ix.name] = ix
            for sc in pack.subchecks:
                if sc.id in impls:
                    raise RegistryError(f"sub-check {sc.id} is implemented twice")
                impls[sc.id] = sc

        # External declarative rules contribute metadata but never AST visitor callbacks.
        for rule in external_rules:
            if rule.id in metas:
                raise RegistryError(f"external rule {rule.id} collides with a built-in rule")
            if rule.rule_id in owner:
                raise RegistryError(f"external rule prefix {rule.rule_id} collides with pack {owner[rule.rule_id]}")
            metas[rule.id] = SubCheckMeta(
                rule.id, rule.rule_id, rule.name, rule.component,
                rule.detection, rule.severity, rule.message,
                rule.remediation, rule.enabled, {}, False,
            )

        for sid, sc in impls.items():
            if sid not in metas:
                raise RegistryError(f"sub-check {sid} has no metadata")
            if metas[sid].detection is not sc.detection:
                raise RegistryError(
                    f"sub-check {sid}: detection {sc.detection} in code "
                    f"but {metas[sid].detection} in metadata"
                )

        by_rule: dict[str, list[SubCheckMeta]] = defaultdict(list)
        for m in metas.values():
            by_rule[m.rule_id].append(m)
        for key, override in config.rules.items():
            targets = by_rule.get(key) or ([metas[key]] if key in metas else None)
            if targets is None:
                raise RegistryError(f"rules: unknown rule or sub-check {key!r}")
            _validate_override(key, override, targets)

        parsed = _parse_catalogs({name: cat for name, (_, cat) in catalogs.items()}, config)
        prompts = {t.subcheck_id: t for p in packs for t in p.prompts}
        for sid in prompts:
            if sid not in metas or metas[sid].detection is not Detection.CANDIDATE:
                raise RegistryError(f"prompt template for {sid}: not a candidate sub-check")

        # Precedence (spec 004 FR-404): sub-check override > rule override >
        # experimental default > metadata `enabled`.
        def baseline(m: SubCheckMeta) -> SubCheckMeta:
            if m.experimental and not config.include_experimental:
                return replace(m, enabled=False)
            return m

        resolved = {
            sid: _apply(_apply(baseline(m), config.rules.get(m.rule_id)), config.rules.get(sid))
            for sid, m in metas.items()
        }
        active = tuple(impls[s] for s in sorted(impls) if resolved[s].enabled)
        external_ids = {r.id for r in external_rules}
        unimplemented = tuple(sorted(set(metas) - set(impls) - external_ids))
        experimental_skipped = tuple(
            sorted(
                s for s, m in resolved.items() if m.experimental and not m.enabled and s in impls
            )
        )
        if external_rules:
            labels.append("external@1")
        digest = hashlib.sha256(
            json.dumps(
                [
                    [
                        p.name,
                        p.metadata,
                        [[c.name, c.defaults] for c in p.catalogs],
                        [[t.subcheck_id, t.version, t.text] for t in p.prompts],
                        list(p.unresolved_watch),
                    ]
                    for p in packs
                ] + [["external", r.__dict__ if hasattr(r, "__dict__") else {f: getattr(r, f) for f in r.__dataclass_fields__}] for r in external_rules],
                sort_keys=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest()[:8]
        registry = cls(
            f"{'+'.join(labels)}#{digest}", resolved, active, unimplemented, parsed, prompts
        )
        registry.external_rules = tuple(r for r in external_rules if resolved[r.id].enabled)
        registry.experimental_skipped = experimental_skipped
        registry.indexers = tuple(indexers[k] for k in sorted(indexers))
        registry.unresolved_watch = tuple(sorted({g for p in packs for g in p.unresolved_watch}))
        return registry

    def all_metas(self) -> list[SubCheckMeta]:
        """Every known sub-check with its effective configuration, for operator views."""
        return [self._metas[k] for k in sorted(self._metas)]

    def is_implemented(self, subcheck_id: str) -> bool:
        return subcheck_id not in self.unimplemented
