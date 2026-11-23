"""External tool findings: mapping into the E-series taxonomy and cross-stream merge
(APDD §6.3.3, spec 002 FR-209/210). Pure; adapters do the reading."""

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
from typing import Any

from codepulse.core.fingerprint import FingerprintInput, assign_fingerprints
from codepulse.core.model import Component, Detection, Finding, Location, Origin, Severity

DEFAULT_ELEMENT = "E15"  # static-analysis gate compliance owns anything unmapped
EXTERNAL_SCOPE = "<external>"


@dataclass(frozen=True, slots=True)
class ExternalIssue:
    tool: str  # ruff | mypy | bandit | sarif:<driver> | sonarqube
    code: str
    path: str  # repo-relative POSIX
    line: int
    end_line: int
    message: str
    severity_raw: str = ""


@dataclass(frozen=True, slots=True)
class IngestNote:
    """What happened with one external source: never silently absent (Art. VIII)."""

    tool: str
    status: str  # ok | pending | error
    issues: int
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status,
            "issues": self.issues,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ExternalRule:
    tool: str  # glob over the tool name
    code: str  # glob over the tool's rule code
    element: str
    severity: Severity | None = None


@dataclass(frozen=True, slots=True)
class ExternalMap:
    rules: tuple[ExternalRule, ...]
    severities: Mapping[tuple[str, str], Severity]  # (tool glob, raw severity upper) -> severity
    defaults: Mapping[str, Severity]  # tool glob -> severity when nothing else applies

    def element(self, issue: ExternalIssue) -> tuple[str, Severity | None]:
        for r in self.rules:
            if fnmatchcase(issue.tool, r.tool) and fnmatchcase(issue.code, r.code):
                return r.element, r.severity
        return DEFAULT_ELEMENT, None

    def severity(self, issue: ExternalIssue, override: Severity | None) -> Severity:
        if override is not None:
            return override
        raw = issue.severity_raw.upper()
        for (tool, value), sev in self.severities.items():
            if fnmatchcase(issue.tool, tool) and value == raw:
                return sev
        for tool, sev in self.defaults.items():
            if fnmatchcase(issue.tool, tool):
                return sev
        return Severity.LOW


_ELEMENT = re.compile(r"^E\d{2}$")


def parse_external_map(entries: list[Any]) -> ExternalMap:
    rules: list[ExternalRule] = []
    severities: dict[tuple[str, str], Severity] = {}
    defaults: dict[str, Severity] = {}
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise TypeError(f"[{i}]: expected mapping")
        kind = entry.get("kind")
        try:
            if kind == "rule":
                if not _ELEMENT.match(str(entry["element"])):
                    raise ValueError(f"[{i}].element: expected E01..E15")
                sev = Severity(entry["severity"]) if "severity" in entry else None
                rules.append(
                    ExternalRule(str(entry["tool"]), str(entry["code"]), entry["element"], sev)
                )
            elif kind == "severity":
                severities[(str(entry["tool"]), str(entry["raw"]).upper())] = Severity(
                    entry["severity"]
                )
            elif kind == "default":
                defaults[str(entry["tool"])] = Severity(entry["severity"])
            else:
                raise ValueError(f"[{i}].kind: expected rule, severity, or default")
        except KeyError as exc:
            raise ValueError(f"[{i}]: missing {exc}") from None
    return ExternalMap(tuple(rules), severities, defaults)


def _slug(code: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", code.lower()).strip("-")[:60] or "issue"


def to_findings(
    issues: Iterable[ExternalIssue],
    mapping: ExternalMap,
    component_of: Callable[[str], Component],
    remediation_of: Callable[[str], str | None],
) -> list[Finding]:
    items = sorted(issues, key=lambda i: (i.path, i.line, i.tool, i.code, i.message))
    mapped = []
    for issue in items:
        element, override = mapping.element(issue)
        sub = f"{element}.{_slug(issue.tool)}-{_slug(issue.code)}"
        mapped.append((issue, element, sub, mapping.severity(issue, override)))
    fps = assign_fingerprints(
        [
            FingerprintInput(sub, i.path, EXTERNAL_SCOPE, f"{i.code}:{i.message}", (i.line, 0))
            for i, _, sub, _ in mapped
        ]
    )
    return [
        Finding(
            fingerprint=fp,
            rule_id=element,
            subcheck_id=sub,
            severity=sev,
            detection=Detection.EXTERNAL,
            origin=Origin.NOT_APPLICABLE,
            location=Location(i.path, max(i.line, 1), max(i.end_line, i.line, 1), EXTERNAL_SCOPE),
            component=component_of(element),
            message=f"{i.message} [{i.tool} {i.code}]",
            remediation=remediation_of(element),
            source_tool=f"{i.tool}:{i.code}",
        )
        for (i, element, sub, sev), fp in zip(mapped, fps, strict=True)
    ]


def merge(
    internal: Sequence[Finding], external: Sequence[Finding]
) -> tuple[list[Finding], list[Finding]]:
    """Fold an external finding into an internal one for the same element, file, and span.

    Returns (internal with corroboration, external findings that stayed independent).
    """
    merged = list(internal)
    remaining = []
    for ext in external:
        idx = next(
            (
                k
                for k, f in enumerate(merged)
                if f.rule_id == ext.rule_id
                and f.location.path == ext.location.path
                and f.location.start_line <= ext.location.start_line <= f.location.end_line
            ),
            None,
        )
        if idx is None:
            remaining.append(ext)
        else:
            f = merged[idx]
            sources = tuple(sorted({*f.corroborated_by, ext.source_tool or ""} - {""}))
            merged[idx] = replace(f, corroborated_by=sources)
    return merged, remaining
