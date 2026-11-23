"""Corpus loading and eval output for `codepulse eval` (spec 006 FR-605..607)."""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from codepulse.core.errors import CodePulseError
from codepulse.core.evaluation import EvalCase, EvalReport, parse_cases
from codepulse.core.serialization import canonical_json


def load_corpus(path: Path, known: Sequence[str]) -> list[EvalCase]:
    """Every *.yaml / *.yml under ``path`` (or ``path`` itself), in sorted order."""
    files = (
        sorted(p for p in path.rglob("*") if p.suffix in (".yaml", ".yml"))
        if path.is_dir()
        else [path]
    )
    if not files:
        raise CodePulseError(f"--corpus {path}: no .yaml corpus files found")
    cases: list[EvalCase] = []
    for f in files:
        try:
            raw = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        except (OSError, yaml.YAMLError) as exc:
            raise CodePulseError(f"{f}: cannot read corpus ({exc})") from exc
        if not isinstance(raw, list):
            raise CodePulseError(f"{f}: expected a list of cases")
        try:
            cases += parse_cases(raw, f.name, known)
        except ValueError as exc:
            raise CodePulseError(str(exc)) from exc
    return cases


def read_record(path: str | None) -> dict[str, Any] | None:
    """The validation record named in config; a missing file reads as no record."""
    if path is None:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise CodePulseError(f"semantic.validation_record {path}: cannot read ({exc})") from exc
    return data if isinstance(data, dict) else None


def _pct(v: float | None) -> str:
    return "—" if v is None else f"{v:.0%}"


def render_eval_json(report: EvalReport) -> str:
    return canonical_json(report.to_dict())


def render_eval_markdown(report: EvalReport) -> str:
    t = report.targets
    out = [
        "# CodePulse semantic evaluation",
        "",
        f"Backend `{report.backend}` · {report.cases} cases · targets: precision ≥ "
        f"{t.min_precision:.0%}, recall ≥ {t.min_recall:.0%}, ≥ {t.min_cases} evaluated cases",
        "",
        "| Sub-check | TP | FP | FN | TN | Not evaluated | Precision | Recall | Result |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for m in report.metrics:
        result = "pass" if m.passed else f"fail: {m.reason}"
        out.append(
            f"| `{m.subcheck_id}` | {m.tp} | {m.fp} | {m.fn} | {m.tn} | {m.not_evaluated} | "
            f"{_pct(m.precision)} | {_pct(m.recall)} | {result} |"
        )
    if report.prompt_versions:
        out += ["", "Prompt versions: " + ", ".join(f"`{v}`" for v in report.prompt_versions)]
    return "\n".join(out) + "\n"
