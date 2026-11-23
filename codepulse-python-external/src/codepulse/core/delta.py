"""What changed since a baseline run (APDD §9, spec 006 FR-601/602). Pure."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from codepulse.core.model import Finding


@dataclass(frozen=True, slots=True)
class BaselineFinding:
    fingerprint: str
    subcheck_id: str
    path: str
    start_line: int
    severity: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "subcheck_id": self.subcheck_id,
            "path": self.path,
            "start_line": self.start_line,
            "severity": self.severity,
        }


@dataclass(frozen=True, slots=True)
class Baseline:
    label: str  # content-derived (file name, store:<sha>), never a run id or timestamp
    findings: tuple[BaselineFinding, ...]

    @classmethod
    def from_findings_json(cls, label: str, data: Mapping[str, Any]) -> "Baseline":
        if data.get("schema") != "codepulse.findings/1":
            raise ValueError(
                f"{label}: not a CodePulse findings.json (schema codepulse.findings/1)"
            )
        rows = [
            BaselineFinding(
                f["fingerprint"],
                f["subcheck_id"],
                f["location"]["path"],
                f["location"]["start_line"],
                f["severity"],
            )
            for f in data.get("findings", [])
        ]
        return cls(label, tuple(rows))


@dataclass(frozen=True, slots=True)
class Delta:
    baseline: str
    new: tuple[str, ...]  # fingerprints, in report order
    fixed: tuple[BaselineFinding, ...]
    unchanged: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline,
            "new": list(self.new),
            "fixed": [f.to_dict() for f in self.fixed],
            "unchanged": self.unchanged,
        }


def compute_delta(
    baseline: Baseline, findings: Iterable[Finding], analyzed: Iterable[str]
) -> Delta:
    """``fixed`` counts only files analyzed now: a branch review never reports untouched
    files as fixed (the same rule the lifecycle reconciler applies)."""
    current = list(findings)
    before = {b.fingerprint for b in baseline.findings}
    now = {f.fingerprint for f in current}
    scope = set(analyzed)
    fixed = sorted(
        (b for b in baseline.findings if b.fingerprint not in now and b.path in scope),
        key=lambda b: (b.path, b.start_line, b.subcheck_id, b.fingerprint),
    )
    return Delta(
        baseline.label,
        tuple(f.fingerprint for f in current if f.fingerprint not in before),
        tuple(fixed),
        len(now & before),
    )
