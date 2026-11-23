"""Portfolio sweep (APDD §10.1 "Sweep" mode; spec 004 FR-401/402). Pure manifest + roll-up."""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from codepulse.core.errors import ConfigError
from codepulse.core.model import Severity
from codepulse.core.report import AnalysisReport
from codepulse.core.validation import mapping, require


@dataclass(frozen=True, slots=True)
class SweepEntry:
    name: str
    path: str  # relative to the manifest's directory unless absolute
    team: str | None = None
    config: str | None = None


def parse_manifest(data: object, label: str = "manifest") -> tuple[SweepEntry, ...]:
    root = mapping(data, label, {"repositories"}, required={"repositories"})
    repos = require(root["repositories"], list, f"{label}.repositories", "list")
    entries: list[SweepEntry] = []
    for i, raw in enumerate(repos):
        p = f"{label}.repositories[{i}]"
        d = mapping(raw, p, {"path", "name", "team", "config"}, required={"path"})
        path = require(d["path"], str, f"{p}.path", "string")
        name = require(
            d.get("name") or path.rstrip("/").rsplit("/", 1)[-1], str, f"{p}.name", "string"
        )
        team = d.get("team")
        cfg = d.get("config")
        entries.append(
            SweepEntry(
                name,
                path,
                None if team is None else require(team, str, f"{p}.team", "string"),
                None if cfg is None else require(cfg, str, f"{p}.config", "string"),
            )
        )
    names = [e.name for e in entries]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise ConfigError(f"{label}.repositories: duplicate names {dupes}; set `name:` explicitly")
    if not entries:
        raise ConfigError(f"{label}.repositories: must not be empty")
    return tuple(entries)


@dataclass(frozen=True, slots=True)
class SweepResult:
    entry: SweepEntry
    report: AnalysisReport | None
    error: str | None = None


def rollup(results: Sequence[SweepResult]) -> dict[str, Any]:
    """Deterministic portfolio roll-up: by repository, team, element, and severity."""
    repos = []
    by_team: dict[str, Counter[str]] = {}
    by_rule: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    for r in sorted(results, key=lambda r: r.entry.name):
        team = r.entry.team or "unassigned"
        row: dict[str, Any] = {
            "name": r.entry.name,
            "team": team,
            "status": "ok" if r.report else "error",
        }
        if r.report is None:
            row["error"] = r.error
        else:
            s = r.report.summary()
            row.update(
                files_analyzed=s["files_analyzed"],
                findings=s["findings_total"],
                by_severity=s["by_severity"],
                needs_review=s["needs_review"],
                registry_version=r.report.registry_version,
            )
            t = by_team.setdefault(team, Counter())
            for f in r.report.findings:
                t[str(f.severity)] += 1
                by_rule[f.rule_id] += 1
                by_severity[str(f.severity)] += 1
        repos.append(row)
    return {
        "repositories": repos,
        "succeeded": sum(1 for r in repos if r["status"] == "ok"),
        "failed": sum(1 for r in repos if r["status"] == "error"),
        "by_severity": {str(s): by_severity[str(s)] for s in Severity},
        "by_rule": dict(sorted(by_rule.items())),
        "by_team": {
            team: {str(s): c[str(s)] for s in Severity} for team, c in sorted(by_team.items())
        },
    }


def render_rollup_markdown(data: dict[str, Any]) -> str:
    sev = list(Severity)
    out = [
        "# CodePulse portfolio sweep",
        "",
        f"{data['succeeded']} repositories reviewed · {data['failed']} failed",
        "",
        "| Repository | Team | Status | Files | Findings | "
        + " | ".join(s.capitalize() for s in sev)
        + " | Needs review |",
        "|---|---|---|---|---|" + "---|" * len(sev) + "---|",
    ]
    for r in data["repositories"]:
        if r["status"] == "ok":
            counts = " | ".join(str(r["by_severity"][str(s)]) for s in sev)
            out.append(
                f"| {r['name']} | {r['team']} | ok | {r['files_analyzed']} | {r['findings']} "
                f"| {counts} | {r['needs_review']} |"
            )
        else:
            blanks = " | ".join("—" for _ in sev)
            out.append(
                f"| {r['name']} | {r['team']} | **error**: {r['error']} | — | — | {blanks} | — |"
            )
    out += ["", "## By team", "", "| Team | " + " | ".join(s.capitalize() for s in sev) + " |"]
    out.append("|---|" + "---|" * len(sev))
    for team, counts in data["by_team"].items():
        out.append(f"| {team} | " + " | ".join(str(counts[str(s)]) for s in sev) + " |")
    out += ["", "## By element", ""]
    out += [f"- {rule}: {n}" for rule, n in data["by_rule"].items()] or ["- none"]
    return "\n".join(out) + "\n"
