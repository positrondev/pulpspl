"""Candidates: constructs the deterministic layer cannot judge (APDD §6.3.4)."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from codepulse.core.model import Component, Location, Severity


@dataclass(frozen=True, slots=True)
class Candidate:
    fingerprint: str
    rule_id: str
    subcheck_id: str
    location: Location
    question: str  # the sub-check's message template, rendered: what a judge must decide
    snippet: str  # the construct's source segment: one function or handler, never a file
    facts: Mapping[str, str] = field(default_factory=dict)
    severity: Severity = Severity.MEDIUM
    component: Component = Component.OTHER

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "subcheck_id": self.subcheck_id,
            "location": self.location.to_dict(),
            "question": self.question,
            "facts": dict(sorted(self.facts.items())),
            "severity": str(self.severity),
            "component": str(self.component),
        }


class UnevaluatedReason(StrEnum):
    BACKEND_DISABLED = "backend_disabled"  # semantic backend is `null`: needs human review
    INSUFFICIENT_CONTEXT = "insufficient_context"
    TIMEOUT = "timeout"
    BACKEND_ERROR = "backend_error"
    PARSE_ERROR = "parse_error"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TEMPLATE_MISSING = "template_missing"


@dataclass(frozen=True, slots=True)
class Unevaluated:
    candidate: Candidate
    reason: UnevaluatedReason
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {**self.candidate.to_dict(), "reason": str(self.reason), "detail": self.detail}
