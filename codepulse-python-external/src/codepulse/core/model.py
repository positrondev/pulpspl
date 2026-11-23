"""Domain types shared by every pipeline stage. Frozen, enum-typed, JSON-serializable."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """0 = most severe; used as the primary sort key."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {s: i for i, s in enumerate(Severity)}


class Detection(StrEnum):
    DETERMINISTIC = "deterministic"
    HEURISTIC = "heuristic"
    CANDIDATE = "candidate"  # sub-check class only; resolved to SEMANTIC once judged
    SEMANTIC = "semantic"
    EXTERNAL = "external"


class Origin(StrEnum):
    INTRODUCED = "introduced"
    PRE_EXISTING = "pre_existing"
    NOT_APPLICABLE = "n/a"  # full-repo runs have no diff to attribute against


class Component(StrEnum):
    GRAPH_NODE = "graph_node"
    LLM_CALL = "llm_call"
    DATABASE = "database"
    REST_API = "rest_api"
    OTHER = "other"


class SkipReason(StrEnum):
    NOT_PYTHON = "not_python"
    EXCLUDED_PATTERN = "excluded_pattern"
    CLASSIFICATION_ABOVE_LIMIT = "classification_above_limit"
    PARSE_ERROR = "parse_error"
    UNREADABLE = "unreadable"
    INDEXER_ERROR = "indexer_error"  # project index only: a pack's indexer crashed on the file


@dataclass(frozen=True, slots=True)
class Location:
    path: str  # repo-relative, POSIX separators
    start_line: int
    end_line: int
    scope: str  # qualified scope, e.g. "Agent.run.<locals>.step"; "<module>" at top level

    def __post_init__(self) -> None:
        if self.path.startswith("/") or "\\" in self.path:
            raise ValueError(f"Location.path must be relative POSIX, got {self.path!r}")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError(
                f"invalid line range: start_line={self.start_line} end_line={self.end_line}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "scope": self.scope,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Location":
        return cls(d["path"], d["start_line"], d["end_line"], d["scope"])


@dataclass(frozen=True, slots=True)
class Finding:
    fingerprint: str
    rule_id: str  # "E04"
    subcheck_id: str  # "E04.no-timeout"
    severity: Severity
    detection: Detection
    origin: Origin
    location: Location
    component: Component
    message: str
    remediation: str | None
    source_tool: str | None = None
    corroborated_by: tuple[str, ...] = ()  # other tools that flagged the same construct

    def __post_init__(self) -> None:
        if not self.subcheck_id.startswith(self.rule_id + "."):
            raise ValueError(
                f"subcheck_id {self.subcheck_id!r} must start with rule_id {self.rule_id!r}"
            )

    @property
    def sort_key(self) -> tuple[int, str, int, str, str]:
        return (
            self.severity.rank,
            self.location.path,
            self.location.start_line,
            self.rule_id,
            self.fingerprint,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "subcheck_id": self.subcheck_id,
            "severity": str(self.severity),
            "detection": str(self.detection),
            "origin": str(self.origin),
            "location": self.location.to_dict(),
            "component": str(self.component),
            "message": self.message,
            "remediation": self.remediation,
            "source_tool": self.source_tool,
            "corroborated_by": list(self.corroborated_by),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Finding":
        return cls(
            fingerprint=d["fingerprint"],
            rule_id=d["rule_id"],
            subcheck_id=d["subcheck_id"],
            severity=Severity(d["severity"]),
            detection=Detection(d["detection"]),
            origin=Origin(d["origin"]),
            location=Location.from_dict(d["location"]),
            component=Component(d["component"]),
            message=d["message"],
            remediation=d["remediation"],
            source_tool=d.get("source_tool"),
            corroborated_by=tuple(d.get("corroborated_by", ())),
        )


@dataclass(frozen=True, slots=True)
class SkipRecord:
    path: str
    reason: SkipReason
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "reason": str(self.reason), "detail": self.detail}


def sort_findings(findings: Iterable[Finding]) -> tuple[Finding, ...]:
    """Contract order: severity desc, path, line, rule_id, fingerprint."""
    return tuple(sorted(findings, key=lambda f: f.sort_key))
