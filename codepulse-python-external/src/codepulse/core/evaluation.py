"""Measure semantic sub-checks against a labelled corpus (APDD §12, spec 006 FR-605..607).

Pure: cases in, metrics out. The semantic stage that produces verdicts is the same one a
review uses, so evaluation exercises the real egress gate, redaction, and cache.
"""

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from codepulse.core.candidate import Candidate
from codepulse.core.model import Component, Location, Severity
from codepulse.core.semantic import SemanticResult

EVAL_SCHEMA = "codepulse.eval/1"
EVAL_PATH_PREFIX = "eval"


class Label(StrEnum):
    VIOLATION = "violation"
    OK = "ok"


@dataclass(frozen=True, slots=True)
class EvalCase:
    id: str
    subcheck_id: str
    question: str
    snippet: str
    label: Label
    facts: Mapping[str, str] = field(default_factory=dict)

    def to_candidate(self, severity: Severity, component: Component) -> Candidate:
        lines = max(1, self.snippet.count("\n") + 1)
        return Candidate(
            fingerprint=hashlib.sha256(self.id.encode("utf-8")).hexdigest()[:24],
            rule_id=self.subcheck_id.split(".", 1)[0],
            subcheck_id=self.subcheck_id,
            location=Location(f"{EVAL_PATH_PREFIX}/{self.id}", 1, lines, "<eval>"),
            question=self.question,
            snippet=self.snippet,
            facts=dict(self.facts),
            severity=severity,
            component=component,
        )


@dataclass(frozen=True, slots=True)
class Targets:
    min_precision: float = 0.85
    min_recall: float = 0.70
    min_cases: int = 5


@dataclass(frozen=True, slots=True)
class SubcheckMetrics:
    subcheck_id: str
    tp: int
    fp: int
    fn: int
    tn: int
    not_evaluated: int
    precision: float | None
    recall: float | None
    passed: bool
    reason: str  # why it failed; "" when passed

    def to_dict(self) -> dict[str, Any]:
        return {
            "subcheck_id": self.subcheck_id,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "not_evaluated": self.not_evaluated,
            "precision": self.precision,
            "recall": self.recall,
            "passed": self.passed,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class EvalReport:
    backend: str
    prompt_versions: tuple[str, ...]
    targets: Targets
    metrics: tuple[SubcheckMetrics, ...]
    cases: int

    @property
    def passed(self) -> tuple[str, ...]:
        return tuple(m.subcheck_id for m in self.metrics if m.passed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": EVAL_SCHEMA,
            "backend": self.backend,
            "prompt_versions": list(self.prompt_versions),
            "targets": {
                "min_precision": self.targets.min_precision,
                "min_recall": self.targets.min_recall,
                "min_cases": self.targets.min_cases,
            },
            "cases": self.cases,
            "metrics": [m.to_dict() for m in self.metrics],
        }


def parse_cases(entries: Iterable[Any], where: str, known: Sequence[str]) -> list[EvalCase]:
    """Validate raw corpus entries; raises ValueError naming the bad entry."""
    out = []
    for i, e in enumerate(entries):
        at = f"{where}[{i}]"
        if not isinstance(e, dict):
            raise ValueError(f"{at}: expected mapping")
        missing = sorted({"id", "subcheck", "question", "snippet", "label"} - set(e))
        if missing:
            raise ValueError(f"{at}: missing {', '.join(missing)}")
        if e["subcheck"] not in known:
            raise ValueError(f"{at}: {e['subcheck']!r} is not a candidate sub-check")
        try:
            label = Label(e["label"])
        except ValueError:
            raise ValueError(f"{at}: label must be violation or ok") from None
        facts = e.get("facts") or {}
        if not isinstance(facts, dict):
            raise ValueError(f"{at}: facts must be a mapping")
        out.append(
            EvalCase(
                str(e["id"]),
                e["subcheck"],
                str(e["question"]),
                str(e["snippet"]),
                label,
                {str(k): str(v) for k, v in facts.items()},
            )
        )
    return out


def _ratio(num: int, den: int) -> float | None:
    return None if den == 0 else round(num / den, 4)


def score(
    cases: Sequence[EvalCase], result: SemanticResult, backend: str, targets: Targets
) -> EvalReport:
    ids = [c.id for c in cases]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate case id(s): {', '.join(dupes)}")
    flagged = {f.location.path for f in result.findings}
    skipped = {u.candidate.location.path for u in result.unevaluated}
    metrics = []
    for sub in sorted({c.subcheck_id for c in cases}):
        tp = fp = fn = tn = ne = 0
        for c in (c for c in cases if c.subcheck_id == sub):
            path = f"{EVAL_PATH_PREFIX}/{c.id}"
            if path in skipped:
                ne += 1
                continue
            predicted = path in flagged
            actual = c.label is Label.VIOLATION
            tp += predicted and actual
            fp += predicted and not actual
            fn += actual and not predicted
            tn += not predicted and not actual
        precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
        evaluated = tp + fp + fn + tn
        if evaluated < targets.min_cases:
            reason = f"{evaluated} evaluated case(s) < min_cases {targets.min_cases}"
        elif precision is None or precision < targets.min_precision:
            reason = f"precision {precision} < {targets.min_precision}"
        elif recall is None or recall < targets.min_recall:
            reason = f"recall {recall} < {targets.min_recall}"
        else:
            reason = ""
        metrics.append(
            SubcheckMetrics(sub, tp, fp, fn, tn, ne, precision, recall, not reason, reason)
        )
    return EvalReport(backend, result.prompt_versions, targets, tuple(metrics), len(cases))


def validation_status(
    record: Mapping[str, Any] | None,
    backend: str,
    prompt_versions: Iterable[str],
    subchecks: Iterable[str],
) -> str:
    """Is this semantic run covered by a passing evaluation? (FR-607)"""
    if backend == "null":
        return "n/a"
    if record is None:
        return "unvalidated: no validation record (run `codepulse eval`)"
    if record.get("schema") != EVAL_SCHEMA:
        return "unvalidated: validation record is not a codepulse eval.json"
    if record.get("backend") != backend:
        return f"unvalidated: record is for {record.get('backend')}, run used {backend}"
    recorded = set(record.get("prompt_versions", []))
    missing = sorted(set(prompt_versions) - recorded)
    if missing:
        return f"unvalidated: prompt version(s) not evaluated: {', '.join(missing)}"
    passed = {m["subcheck_id"] for m in record.get("metrics", []) if m.get("passed")}
    failing = sorted(set(subchecks) - passed)
    if failing:
        return f"unvalidated: below target or not evaluated: {', '.join(failing)}"
    return "validated"
