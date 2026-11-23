"""Findings → one ordered, attributed, deduplicated collection (APDD §6.3.5)."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import date
from enum import StrEnum

from codepulse.core.candidate import Candidate
from codepulse.core.engine.visitor import FileAnalysis
from codepulse.core.model import Finding, Origin, sort_findings
from codepulse.core.ports import LineRange
from codepulse.core.suppression import Suppression


@dataclass(frozen=True, slots=True)
class SuppressedFinding:
    finding: Finding
    suppression: Suppression

    def to_dict(self) -> dict[str, object]:
        return {"finding": self.finding.to_dict(), "suppression": self.suppression.to_dict()}


@dataclass(frozen=True, slots=True)
class SuppressedCandidate:
    """A judgment question a reviewer already answered with a justified suppression."""

    candidate: Candidate
    suppression: Suppression

    def to_dict(self) -> dict[str, object]:
        return {"candidate": self.candidate.to_dict(), "suppression": self.suppression.to_dict()}


class SuppressionProblem(StrEnum):
    EXPIRED = "expired"
    INVALID_UNTIL = "invalid_until"


@dataclass(frozen=True, slots=True)
class SuppressionIssue:
    path: str
    line: int
    problem: SuppressionProblem
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "problem": str(self.problem),
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class Normalized:
    findings: tuple[Finding, ...]
    suppressed: tuple[SuppressedFinding, ...]
    suppression_issues: tuple[SuppressionIssue, ...]


def attribute_origin(finding: Finding, changed: tuple[LineRange, ...] | None) -> Origin:
    """Introduced if the finding's span overlaps a changed hunk; n/a outside diff runs."""
    if changed is None:
        return Origin.NOT_APPLICABLE
    loc = finding.location
    if any(start <= loc.end_line and loc.start_line <= end for start, end in changed):
        return Origin.INTRODUCED
    return Origin.PRE_EXISTING


def _active_suppressions(
    analysis: FileAnalysis, today: date, issues: list[SuppressionIssue]
) -> list[Suppression]:
    active = []
    for s in analysis.suppressions:
        if s.invalid_until:
            issues.append(
                SuppressionIssue(
                    analysis.path, s.line, SuppressionProblem.INVALID_UNTIL, f"until={s.until_raw}"
                )
            )
        elif s.reason is None:
            continue  # ignored; E15.unjustified-suppression reports it
        elif s.until is not None and s.until < today:
            issues.append(
                SuppressionIssue(
                    analysis.path, s.line, SuppressionProblem.EXPIRED, f"until={s.until_raw}"
                )
            )
        else:
            active.append(s)
    return active


def split_candidates(
    analysis: FileAnalysis, today: date
) -> tuple[list[Candidate], list[SuppressedCandidate]]:
    """Candidates the file's active suppressions answer vs. those still open.
    Problems with the suppressions themselves are reported once, by ``normalize``."""
    active = _active_suppressions(analysis, today, [])
    kept, answered = [], []
    for c in analysis.candidates:
        match = next(
            (
                s
                for s in active
                if s.target_line == c.location.start_line
                and (c.rule_id in s.ids or c.subcheck_id in s.ids)
            ),
            None,
        )
        if match is None:
            kept.append(c)
        else:
            answered.append(SuppressedCandidate(c, match))
    return kept, answered


def normalize(
    analyses: Iterable[FileAnalysis],
    changed: Mapping[str, tuple[LineRange, ...] | None],
    today: date,
) -> Normalized:
    """``today`` is the run date, passed in so the core never reads the clock."""
    kept: list[Finding] = []
    suppressed: list[SuppressedFinding] = []
    issues: list[SuppressionIssue] = []
    for analysis in analyses:
        active = _active_suppressions(analysis, today, issues)
        ranges = changed.get(analysis.path)
        for raw in analysis.findings:
            finding = replace(raw, origin=attribute_origin(raw, ranges))
            match = next(
                (
                    s
                    for s in active
                    if s.target_line == finding.location.start_line and s.covers(finding)
                ),
                None,
            )
            if match is None:
                kept.append(finding)
            else:
                suppressed.append(SuppressedFinding(finding, match))

    unique: dict[str, Finding] = {}
    for f in sort_findings(kept):
        unique.setdefault(f.fingerprint, f)
    return Normalized(
        findings=tuple(unique.values()),
        suppressed=tuple(sorted(suppressed, key=lambda s: s.finding.sort_key)),
        suppression_issues=tuple(sorted(issues, key=lambda i: (i.path, i.line, i.problem))),
    )
