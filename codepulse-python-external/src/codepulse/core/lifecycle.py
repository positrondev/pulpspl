"""Issue lifecycle (APDD v4.1 §10.1-10.2). Pure: statuses, transitions, reconciliation, calibration.

An *issue* is the identity behind a fingerprint; it outlives any single run. The store adapter
applies the changes planned here, so every lifecycle rule is testable without a database.
"""

import statistics
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum

from codepulse.core.errors import CodePulseError
from codepulse.core.model import Detection, Finding


class IssueStatus(StrEnum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    WAIVED = "waived"


class RejectReason(StrEnum):
    FALSE_POSITIVE = "false_positive"
    NOT_APPLICABLE = "not_applicable"
    ACCEPTED_RISK = "accepted_risk"


S = IssueStatus
# Manual (reviewer) transitions, FR-305. The reconciler's automatic moves are separate.
TRANSITIONS: Mapping[IssueStatus, frozenset[IssueStatus]] = {
    S.OPEN: frozenset({S.CONFIRMED, S.REJECTED, S.IN_PROGRESS, S.RESOLVED, S.WAIVED}),
    S.CONFIRMED: frozenset({S.IN_PROGRESS, S.RESOLVED, S.WAIVED, S.REJECTED}),
    S.IN_PROGRESS: frozenset({S.RESOLVED, S.OPEN}),
    S.REJECTED: frozenset({S.OPEN}),
    S.RESOLVED: frozenset({S.OPEN}),
    S.WAIVED: frozenset({S.OPEN}),
}
# Statuses the reconciler may auto-resolve when the code is gone. Rejected and waived issues
# keep the reviewer's decision; if they recur, they are still rejected or waived.
AUTO_RESOLVABLE = frozenset({S.OPEN, S.CONFIRMED, S.IN_PROGRESS})


class TransitionError(CodePulseError):
    """A triage request the lifecycle does not allow. Maps to exit code 2."""


@dataclass(frozen=True, slots=True)
class IssueState:
    fingerprint: str
    subcheck_id: str
    path: str
    status: IssueStatus
    waiver_expires_at: date | None = None


@dataclass(frozen=True, slots=True)
class Triage:
    fingerprint: str
    status: IssueStatus
    by: str
    reason: RejectReason | None = None
    justification: str | None = None
    until: date | None = None
    evidence: str | None = None


def initial_status(finding: Finding) -> IssueStatus:
    """Deterministic findings are machine-verifiable and confirmed on raise (APDD Q4)."""
    return S.CONFIRMED if finding.detection is Detection.DETERMINISTIC else S.OPEN


def validate_triage(current: IssueStatus, t: Triage, today: date) -> None:
    if not t.by.strip():
        raise TransitionError("triage needs --by (who is making this decision)")
    if t.status is current:
        raise TransitionError(f"issue is already {current}")
    if t.status not in TRANSITIONS[current]:
        allowed = ", ".join(sorted(TRANSITIONS[current])) or "none"
        raise TransitionError(f"cannot move {current} -> {t.status} (allowed: {allowed})")
    if t.status is S.REJECTED and t.reason is None:
        raise TransitionError(f"rejecting needs --reason ({', '.join(RejectReason)})")
    if t.status is S.WAIVED:
        if not (t.justification and t.justification.strip()):
            raise TransitionError("waiving needs --justification")
        if t.until is None or t.until <= today:
            raise TransitionError("waiving needs --until with a future date")


class ChangeKind(StrEnum):
    CREATE = "create"
    SEEN = "seen"
    RESOLVE = "resolve"
    REOPEN = "reopen"
    EXPIRE_WAIVER = "expire_waiver"


@dataclass(frozen=True, slots=True)
class PlannedChange:
    kind: ChangeKind
    fingerprint: str
    previous: IssueStatus | None
    new: IssueStatus | None  # None for SEEN: occurrence recorded, status unchanged
    finding: Finding | None = None
    note: str = ""


def plan_reconciliation(
    existing: Mapping[str, IssueState],
    present: Sequence[Finding],
    analyzed_paths: Iterable[str],
    today: date,
) -> list[PlannedChange]:
    """What this run means for every known issue.

    ``present`` must include suppressed findings: suppression hides a finding from the
    report, but the code it describes still exists, so its issue must not resolve.
    """
    analyzed = set(analyzed_paths)
    by_fp: dict[str, Finding] = {}
    for f in present:
        by_fp.setdefault(f.fingerprint, f)
    changes: list[PlannedChange] = []
    for fp in sorted(by_fp):
        f = by_fp[fp]
        state = existing.get(fp)
        if state is None:
            changes.append(
                PlannedChange(ChangeKind.CREATE, fp, None, initial_status(f), f, "first seen")
            )
        elif state.status is S.RESOLVED:
            changes.append(
                PlannedChange(
                    ChangeKind.REOPEN, fp, S.RESOLVED, S.OPEN, f, "recurrence after resolution"
                )
            )
        else:
            changes.append(PlannedChange(ChangeKind.SEEN, fp, state.status, None, f))
    for fp in sorted(set(existing) - set(by_fp)):
        state = existing[fp]
        if state.path in analyzed and state.status in AUTO_RESOLVABLE:
            changes.append(
                PlannedChange(
                    ChangeKind.RESOLVE,
                    fp,
                    state.status,
                    S.RESOLVED,
                    None,
                    "no longer present in an analyzed file",
                )
            )
    for fp in sorted(existing):
        state = existing[fp]
        if (
            state.status is S.WAIVED
            and state.waiver_expires_at is not None
            and state.waiver_expires_at < today
        ):
            changes.append(
                PlannedChange(
                    ChangeKind.EXPIRE_WAIVER,
                    fp,
                    S.WAIVED,
                    S.OPEN,
                    by_fp.get(fp),
                    f"waiver expired {state.waiver_expires_at.isoformat()}",
                )
            )
    return changes


# -- calibration and trends (APDD §10.2, §9.4) ----------------------------------------------

ACTED_ON = frozenset({S.CONFIRMED, S.IN_PROGRESS, S.RESOLVED})


@dataclass(frozen=True, slots=True)
class RuleCalibration:
    subcheck_id: str
    confirmed: int
    rejected: int
    waived: int
    open: int

    @property
    def confirmation_rate(self) -> float | None:
        d = self.confirmed + self.rejected + self.waived
        return self.confirmed / d if d else None

    @property
    def rejection_rate(self) -> float | None:
        d = self.confirmed + self.rejected + self.waived
        return self.rejected / d if d else None

    @property
    def actionable_precision(self) -> float | None:
        d = self.confirmed + self.rejected
        return self.confirmed / d if d else None


def calibrate(issues: Iterable[tuple[str, IssueStatus]]) -> list[RuleCalibration]:
    """Per sub-check: acted-on (confirmed, in progress, or resolved) vs rejected vs waived."""
    counts: dict[str, list[int]] = {}
    for sub, status in issues:
        c = counts.setdefault(sub, [0, 0, 0, 0])
        if status in ACTED_ON:
            c[0] += 1
        elif status is S.REJECTED:
            c[1] += 1
        elif status is S.WAIVED:
            c[2] += 1
        else:
            c[3] += 1
    return [RuleCalibration(sub, *c) for sub, c in sorted(counts.items())]


def median_days_to_resolve(spans: Iterable[tuple[datetime, datetime]]) -> float | None:
    """Median days from confirmation to resolution over (confirmed_at, resolved_at) pairs."""
    days = [(end - start).total_seconds() / 86400 for start, end in spans if end >= start]
    return round(statistics.median(days), 2) if days else None
