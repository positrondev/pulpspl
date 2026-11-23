"""``# codepulse: ignore[...]`` directives (spec 001 FR-011a). Pure parsing, no I/O."""

import re
from dataclasses import dataclass
from datetime import date

from codepulse.core.model import Finding

_DIRECTIVE = re.compile(r"codepulse:\s*ignore\[(?P<ids>[^\]]*)\](?P<rest>.*)", re.IGNORECASE)
_REASON = re.compile(r"""reason\s*=\s*(?:"([^"]*)"|'([^']*)')""")
_UNTIL = re.compile(r"until\s*=\s*(\S+)")
_ID = re.compile(r"^[A-Z][A-Z0-9]*\d{2}(\.[a-z0-9][a-z0-9-]*)?$")


@dataclass(frozen=True, slots=True)
class Suppression:
    line: int  # where the comment sits
    target_line: int  # the code line it applies to
    ids: tuple[str, ...]  # rule ids ("E04") or sub-check ids ("E04.no-timeout")
    reason: str | None
    until: date | None
    until_raw: str | None  # set when `until=` was given; parse failures keep until=None

    def covers(self, finding: Finding) -> bool:
        return finding.rule_id in self.ids or finding.subcheck_id in self.ids

    @property
    def invalid_until(self) -> bool:
        return self.until_raw is not None and self.until is None

    def to_dict(self) -> dict[str, object]:
        return {
            "line": self.line,
            "target_line": self.target_line,
            "ids": list(self.ids),
            "reason": self.reason,
            "until": self.until_raw,
        }


def parse_suppression(comment: str, line: int, target_line: int) -> Suppression | None:
    m = _DIRECTIVE.search(comment)
    if m is None:
        return None
    ids = tuple(i for i in (p.strip() for p in m["ids"].split(",")) if _ID.match(i))
    rest = m["rest"]
    reason_m = _REASON.search(rest)
    reason = (reason_m[1] if reason_m[1] is not None else reason_m[2]) if reason_m else None
    until_m = _UNTIL.search(rest)
    until_raw = until_m[1] if until_m else None
    until = None
    if until_raw is not None:
        try:
            until = date.fromisoformat(until_raw)
        except ValueError:
            until = None
    return Suppression(line, target_line, ids, (reason or "").strip() or None, until, until_raw)
