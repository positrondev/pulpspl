"""Portfolio dashboard model and tracker export shape (spec 009 FR-908/909). Pure.

The dashboard is built from the store, not from one run: it shows what is open now, what
reviewers decided, and how counts move over time. Each issue also carries a ``tracker`` record
(summary, description, labels, priority) so a later Jira adapter maps fields 1:1.
"""

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from codepulse.core.lifecycle import IssueStatus
from codepulse.core.model import Severity

DASHBOARD_SCHEMA = "codepulse.dashboard/1"
OPEN_STATUSES = frozenset({IssueStatus.OPEN, IssueStatus.CONFIRMED, IssueStatus.IN_PROGRESS})
# Jira's default priority scheme; a different scheme is a mapping change in the adapter.
TRACKER_PRIORITY = {
    Severity.CRITICAL: "Highest",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Lowest",
}
_SUMMARY_MAX = 240  # Jira caps summaries at 255 characters


def tracker_record(repository: str, row: Mapping[str, Any]) -> dict[str, Any]:
    """One issue as a ticket. ``key`` is stable across runs (repository + fingerprint), so
    an exporter can update the same ticket instead of filing duplicates."""
    sev = Severity(row["severity"])
    where = f"{row['path']}:{row['start_line']}"
    message = row.get("description") or row["subcheck_id"]
    summary = f"[{row['subcheck_id']}] {message}"
    if len(summary) > _SUMMARY_MAX:
        summary = summary[: _SUMMARY_MAX - 1] + "…"
    lines = [
        message,
        "",
        f"Location: {where}",
        f"Sub-check: {row['subcheck_id']} ({row['detection']})",
        f"Fingerprint: {row['fingerprint']}",
    ]
    if row.get("remediation"):
        lines += ["", f"Fix: {row['remediation']}"]
    return {
        "key": f"{repository}:{row['fingerprint']}",
        "summary": summary,
        "description": "\n".join(lines),
        "labels": sorted(
            {"codepulse", row["rule_id"], str(row.get("component") or "other"), str(sev)}
        ),
        "priority": TRACKER_PRIORITY[sev],
    }


def _issue(repository: str, row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "repository": repository,
        "fingerprint": row["fingerprint"],
        "rule_id": row["rule_id"],
        "subcheck_id": row["subcheck_id"],
        "severity": row["severity"],
        "status": row["status"],
        "detection": row["detection"],
        "component": row.get("component"),
        "origin": row.get("origin"),
        "path": row["path"],
        "line": row["start_line"],
        "message": row.get("description"),
        "remediation": row.get("remediation"),
        "suppressed": bool(row.get("suppressed")),
        "tracker": tracker_record(repository, row),
    }


def _sev_rank(sev: str) -> int:
    return Severity(sev).rank


def build_dashboard(
    repos: Sequence[tuple[str, Iterable[Mapping[str, Any]], Mapping[str, Any]]],
) -> dict[str, Any]:
    """``repos``: (repository, issue rows from the store, trends dict) per repository."""
    out_repos = []
    all_issues: list[dict[str, Any]] = []
    for name, rows, trends in sorted(repos, key=lambda r: r[0]):
        issues = [_issue(name, r) for r in rows]
        issues.sort(
            key=lambda i: (_sev_rank(i["severity"]), i["path"], i["line"], i["fingerprint"])
        )
        open_ = [i for i in issues if i["status"] in OPEN_STATUSES and not i["suppressed"]]
        sev = Counter(i["severity"] for i in open_)
        runs = trends.get("runs", [])
        out_repos.append(
            {
                "repository": name,
                "latest_run": runs[-1] if runs else None,
                "open_total": len(open_),
                "open_by_severity": {str(s): sev.get(str(s), 0) for s in Severity},
                "open_by_rule": dict(sorted(Counter(i["rule_id"] for i in open_).items())),
                "issues_by_status": trends.get("issues_by_status", {}),
                "runs": runs,
                "density_by_component": trends.get("density_by_component", {}),
                "calibration": trends.get("calibration", []),
                "waivers": trends.get("waivers", []),
                "median_days_confirm_to_resolve": trends.get("median_days_confirm_to_resolve"),
                "recurrences": trends.get("recurrences", 0),
            }
        )
        all_issues += issues
    return {"schema": DASHBOARD_SCHEMA, "repositories": out_repos, "issues": all_issues}
