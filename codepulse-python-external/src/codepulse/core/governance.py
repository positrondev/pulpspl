"""Rule governance (APDD §10.3, §12.3; spec 004 FR-403). Pure window math over decisions.

A sub-check whose confirmation rate stays under the threshold for N consecutive windows,
each with enough reviewer decisions to mean something, is flagged for revision. CodePulse
suggests the override; a human applies it (Constitution Art. I).
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta

from codepulse.core.lifecycle import ACTED_ON, IssueStatus


@dataclass(frozen=True, slots=True)
class Decision:
    subcheck_id: str
    status: IssueStatus  # the status a reviewer moved the issue to
    at: datetime


@dataclass(frozen=True, slots=True)
class WindowStats:
    start: date  # inclusive
    end: date  # exclusive
    acted: int = 0
    rejected: int = 0
    waived: int = 0

    @property
    def decisions(self) -> int:
        return self.acted + self.rejected + self.waived

    @property
    def confirmation_rate(self) -> float | None:
        return self.acted / self.decisions if self.decisions else None


@dataclass(frozen=True, slots=True)
class Flag:
    subcheck_id: str
    windows: tuple[WindowStats, ...]


def windows(today: date, days: int, count: int) -> list[tuple[date, date]]:
    """``count`` consecutive windows of ``days`` ending today (inclusive), oldest first."""
    end = today + timedelta(days=1)
    spans = []
    for k in range(count):
        e = end - timedelta(days=days * k)
        spans.append((e - timedelta(days=days), e))
    return list(reversed(spans))


def per_window(
    decisions: Iterable[Decision], spans: Sequence[tuple[date, date]]
) -> dict[str, list[WindowStats]]:
    counts: dict[str, list[list[int]]] = {}
    for d in decisions:
        day = d.at.date()
        for i, (start, end) in enumerate(spans):
            if start <= day < end:
                c = counts.setdefault(d.subcheck_id, [[0, 0, 0] for _ in spans])[i]
                if d.status in ACTED_ON:
                    c[0] += 1
                elif d.status is IssueStatus.REJECTED:
                    c[1] += 1
                elif d.status is IssueStatus.WAIVED:
                    c[2] += 1
                break
    return {
        sub: [WindowStats(s, e, *c) for (s, e), c in zip(spans, cs, strict=True)]
        for sub, cs in sorted(counts.items())
    }


def flag_noisy(
    stats: dict[str, list[WindowStats]], threshold: float, min_decisions: int
) -> list[Flag]:
    flags = []
    for sub, ws in sorted(stats.items()):
        if ws and all(
            w.decisions >= min_decisions and (w.confirmation_rate or 0.0) < threshold for w in ws
        ):
            flags.append(Flag(sub, tuple(ws)))
    return flags


def override_yaml(flags: Sequence[Flag]) -> str:
    """The exact codepulse.yaml snippet a rule owner would apply after review."""
    if not flags:
        return ""
    lines = ["rules:"]
    for f in flags:
        rates = ", ".join(f"{(w.confirmation_rate or 0):.0%}" for w in f.windows)
        lines += [
            f"  {f.subcheck_id}:  # confirmation {rates} over {len(f.windows)} windows",
            "    enabled: false",
        ]
    return "\n".join(lines) + "\n"
