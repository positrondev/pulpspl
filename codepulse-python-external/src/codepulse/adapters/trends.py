"""Trends and calibration report from the store (APDD §9.4, §10.2; spec 003 FR-308)."""

from collections import Counter
from datetime import date, datetime
from typing import Any

from codepulse.adapters.store_sql import SqlFindingStore
from codepulse.core.lifecycle import IssueStatus, calibrate, median_days_to_resolve
from codepulse.core.model import Severity
from codepulse.core.serialization import canonical_json


def _iso(v: object) -> str | None:
    if isinstance(v, datetime | date):
        return v.isoformat()
    return None if v is None else str(v)


def build_trends(store: SqlFindingStore, repository: str, runs: int, today: date) -> dict[str, Any]:
    recent = store.recent_runs(repository, runs)
    issues = store.issues(repository)
    history = store.history(r["issue_id"] for r in issues)
    confirmed_at: dict[str, datetime] = {}
    spans: list[tuple[datetime, datetime]] = []
    recurrences = 0
    for h in history:
        new = h["new_status"]
        if new == IssueStatus.CONFIRMED and h["issue_id"] not in confirmed_at:
            confirmed_at[h["issue_id"]] = h["changed_at"]
        elif new == IssueStatus.RESOLVED and h["issue_id"] in confirmed_at:
            spans.append((confirmed_at.pop(h["issue_id"]), h["changed_at"]))
        if h["previous_status"] == IssueStatus.RESOLVED and new == IssueStatus.OPEN:
            recurrences += 1
    calibration = calibrate((r["subcheck_id"], IssueStatus(r["status"])) for r in issues)
    status_counts = Counter(r["status"] for r in issues)
    waivers = [
        {
            "fingerprint": r["fingerprint"],
            "subcheck_id": r["subcheck_id"],
            "path": r["path"],
            "justification": r["waiver_justification"],
            "expires": _iso(r["waiver_expires_at"]),
            "expired": bool(r["waiver_expires_at"] and r["waiver_expires_at"] < today),
        }
        for r in issues
        if r["status"] == IssueStatus.WAIVED
    ]

    def rate(v: float | None) -> float | None:
        return None if v is None else round(v, 4)

    return {
        "repository": repository,
        "runs": [
            {
                "run_id": r["run_id"],
                "created_at": _iso(r["created_at"]),
                "mode": r["mode"],
                "target_ref": r["target_ref"],
                "files_analyzed": r["files_eligible"],
                "by_severity": {str(s): int(r["by_severity"].get(str(s), 0)) for s in Severity},
            }
            for r in recent
        ],
        "issues_by_status": {str(s): status_counts.get(str(s), 0) for s in IssueStatus},
        "calibration": [
            {
                "subcheck_id": c.subcheck_id,
                "confirmed": c.confirmed,
                "rejected": c.rejected,
                "waived": c.waived,
                "open": c.open,
                "confirmation_rate": rate(c.confirmation_rate),
                "rejection_rate": rate(c.rejection_rate),
                "actionable_precision": rate(c.actionable_precision),
            }
            for c in calibration
        ],
        "density_by_component": _density(recent[-1]) if recent else {},
        "median_days_confirm_to_resolve": median_days_to_resolve(spans),
        "recurrences": recurrences,
        "waivers": sorted(waivers, key=lambda w: (w["expires"] or "", w["fingerprint"])),
    }


def _density(run: dict[str, Any]) -> dict[str, float]:
    """Unsuppressed findings per eligible file, by component, for one run (APDD §9)."""
    files = run["files_eligible"] or 0
    if not files:
        return {}
    return {str(c): round(n / files, 3) for c, n in sorted(run["by_component"].items())}


def render_trends_json(data: dict[str, Any]) -> str:
    return canonical_json(data)


def _pct(v: float | None) -> str:
    return "—" if v is None else f"{v:.0%}"


def render_trends_markdown(data: dict[str, Any]) -> str:
    out = [f"# CodePulse trends — {data['repository']}", ""]
    out += [
        "## Recent runs",
        "",
        "| Run | Mode | Ref | Files | " + " | ".join(s.capitalize() for s in Severity) + " |",
    ]
    out.append("|---|---|---|---|" + "---|" * len(Severity))
    for r in data["runs"]:
        sev = " | ".join(str(r["by_severity"][str(s)]) for s in Severity)
        when = (r["created_at"] or "")[:16]
        out.append(
            f"| {when} | {r['mode']} | `{r['target_ref']}` | {r['files_analyzed']} | {sev} |"
        )
    if data["density_by_component"]:
        out += ["", "## Defect density (latest run, findings per eligible file)", ""]
        out += [f"- {c}: {d:.3f}" for c, d in data["density_by_component"].items()]
    out += ["", "## Issues by status", ""]
    out += [f"- {s}: {n}" for s, n in data["issues_by_status"].items()]
    out += [
        "",
        "Median days from confirmation to resolution: "
        f"{data['median_days_confirm_to_resolve'] or '—'} · "
        f"recurrences after resolution: {data['recurrences']}",
        "",
        "## Calibration (APDD §10.2)",
        "",
        "| Sub-check | Acted on | Rejected | Waived | Open | Confirmation | Precision |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in data["calibration"]:
        out.append(
            f"| `{c['subcheck_id']}` | {c['confirmed']} | {c['rejected']} | {c['waived']} "
            f"| {c['open']} | {_pct(c['confirmation_rate'])} | {_pct(c['actionable_precision'])} |"
        )
    if data["waivers"]:
        out += [
            "",
            "## Waivers",
            "",
            "| Fingerprint | Sub-check | Expires | Justification |",
            "|---|---|---|---|",
        ]
        for w in data["waivers"]:
            flag = " (expired)" if w["expired"] else ""
            out.append(
                f"| `{w['fingerprint']}` | `{w['subcheck_id']}` | {w['expires']}{flag} "
                f"| {w['justification']} |"
            )
    return "\n".join(out) + "\n"
