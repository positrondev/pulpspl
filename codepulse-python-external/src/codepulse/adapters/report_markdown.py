"""Markdown report (APDD §9). Deterministic: no clocks, ids, or absolute paths."""

import html
from collections.abc import Iterable

from codepulse.core.model import Detection, Finding, Origin, Severity
from codepulse.core.report import AnalysisReport
from codepulse.core.resolver import TargetKind

_MODE = {
    TargetKind.BRANCH: "branch diff",
    TargetKind.ALL: "full repository",
    TargetKind.FILES: "file list",
}


def _text(s: str) -> str:
    """Escape for Markdown body text: no raw HTML, no accidental emphasis from `*`/`_`."""
    return html.escape(s, quote=False).replace("*", r"\*").replace("_", r"\_")


def _cell(s: str) -> str:
    return _text(s).replace("|", r"\|").replace("\n", " ")


def _code(s: str) -> str:
    fence = "``" if "`" in s else "`"
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def _counts(items: Iterable[tuple[str, int]]) -> str:
    parts = [f"{n} {label}" for label, n in items]
    return " · ".join(parts) if parts else "none"


def _header(report: AnalysisReport) -> list[str]:
    t = report.target
    s = report.summary()
    if t.mode is TargetKind.BRANCH:
        target = f"{_code(t.head or '?')} vs {_code(t.base or '?')}"
    else:
        target = _MODE[t.mode]
    sev = s["by_severity"]
    origin = s["by_origin"]
    detection = s["by_detection"]
    return [
        f"# CodePulse review — {_text(t.repository)}",
        "",
        "| | |",
        "|---|---|",
        f"| Target | {target}"
        + (f" ({_MODE[t.mode]})" if t.mode is TargetKind.BRANCH else "")
        + " |",
        f"| Files | {s['files_analyzed']} analyzed · {s['files_skipped']} skipped |",
        f"| Findings | **{s['findings_total']}** — "
        + _counts((str(k), sev[str(k)]) for k in Severity)
        + " |",
        "| Origin | "
        + _counts(
            (str(o).replace("_", "-"), origin.get(str(o), 0)) for o in Origin if str(o) in origin
        )
        + " |",
        "| Detection | "
        + _counts((str(d), detection[str(d)]) for d in Detection if str(d) in detection)
        + f" · semantic backend {_code(s['semantic_backend'])} |",
        f"| Needs review | {s['needs_review']} of {s['candidates']} judgment candidates |",
        f"| Suppressed | {s['suppressed']} |",
        *(
            [
                f"| Delta | vs {_code(d.baseline)}: {len(d.new)} new · {len(d.fixed)} fixed · "
                f"{d.unchanged} unchanged |"
            ]
            if (d := report.delta)
            else []
        ),
        *(
            [f"| Semantic validation | {_cell(report.semantic_validation)} |"]
            if report.semantic_backend != "null"
            else []
        ),
        f"| Rule registry | {_code(report.registry_version)} |",
        f"| Config hash | {_code(report.config_hash[:12])} |",
        f"| Tool | CodePulse {_text(report.tool_version)} |",
        "",
    ]


def _finding(f: Finding, rule_name: str) -> list[str]:
    loc = f.location
    span = (
        f"{loc.start_line}"
        if loc.start_line == loc.end_line
        else f"{loc.start_line}\u2013{loc.end_line}"
    )
    lines = [
        f"#### {_code(f'{loc.path}:{span}')} · {_code(f.subcheck_id)}",
        "",
        f"**{_text(f.rule_id)} {_text(rule_name)}** · {f.detection} · "
        f"{str(f.origin).replace('_', '-')} · scope {_code(loc.scope)}",
        "",
        _text(f.message),
        "",
    ]
    if f.remediation:
        lines += [f"**Fix:** {_text(f.remediation)}", ""]
    if f.corroborated_by:
        lines += ["Also reported by " + ", ".join(_code(s) for s in f.corroborated_by), ""]
    lines += [f"Fingerprint {_code(f.fingerprint)}", ""]
    return lines


def render_markdown(report: AnalysisReport) -> str:
    out = _header(report)
    out += ["## Findings", ""]
    if not report.findings:
        out += ["No findings.", ""]
    for sev in Severity:
        group = [f for f in report.findings if f.severity is sev]
        if group:
            out += [f"### {str(sev).capitalize()} ({len(group)})", ""]
            for f in group:
                out += _finding(f, report.rule_names.get(f.rule_id, ""))
    if any(f.detection is Detection.HEURISTIC for f in report.findings):
        out += [
            "> Heuristic findings are reproducible but pattern-based: confirm or reject each "
            "one so the rule's precision is tracked.",
            "",
        ]

    if any(f.detection is Detection.SEMANTIC for f in report.findings):
        out += [
            "> Semantic findings are model judgments: they count as defects only once a reviewer "
            "confirms them.",
            "",
        ]
    if report.needs_review:
        out += [f"## Needs review ({len(report.needs_review)})", ""]
        out += [
            "Judgment questions the deterministic layer could not settle. "
            + (
                "No semantic backend is configured, so each needs a human answer."
                if report.semantic_backend == "null"
                else "The semantic backend could not answer these; each needs a human answer."
            ),
            "",
        ]
        for u in report.needs_review:
            c = u.candidate
            where = _code(f"{c.location.path}:{c.location.start_line}")
            out.append(
                f"- [ ] {where} · {_code(c.subcheck_id)} · scope {_code(c.location.scope)}: "
                f"{_text(c.question)}"
            )
            if c.facts:
                facts = ", ".join(f"{k}={v}" for k, v in sorted(c.facts.items()))
                out.append(f"  - facts: {_text(facts)}")
            if u.reason.value != "backend_disabled":
                detail = f" ({_text(u.detail)})" if u.detail else ""
                out.append(f"  - not evaluated: {u.reason}{detail}")
        out.append("")
    suppressed = [
        (s.finding.location, s.finding.subcheck_id, s.suppression) for s in report.suppressed
    ]
    suppressed += [
        (a.candidate.location, a.candidate.subcheck_id, a.suppression) for a in report.answered
    ]
    if suppressed:
        out += [
            "## Suppressed",
            "",
            "| Location | Sub-check | Reason | Until |",
            "|---|---|---|---|",
        ]
        for loc, sub_id, sup in sorted(
            suppressed, key=lambda x: (x[0].path, x[0].start_line, x[1])
        ):
            out.append(
                f"| {_code(f'{loc.path}:{loc.start_line}')} | {_code(sub_id)} | "
                f"{_cell(sup.reason or '')} | {_cell(sup.until_raw or '—')} |"
            )
        out.append("")
    if report.suppression_issues:
        out += ["## Suppression problems", "", "| Location | Problem | Detail |", "|---|---|---|"]
        for i in report.suppression_issues:
            out.append(f"| {_code(f'{i.path}:{i.line}')} | {i.problem} | {_cell(i.detail)} |")
        out.append("")
    if report.skipped:
        out += ["## Not analyzed", "", "| File | Reason | Detail |", "|---|---|---|"]
        for sk in report.skipped:
            out.append(f"| {_code(sk.path)} | {sk.reason} | {_cell(sk.detail) or '—'} |")
        out.append("")
    if report.rule_errors:
        out += [
            "## Rule errors",
            "",
            "These checks crashed; their results for these files are incomplete.",
            "",
        ]
        out += ["| Sub-check | Location | Error |", "|---|---|---|"]
        for e in report.rule_errors:
            out.append(
                f"| {_code(e.subcheck_id)} | {_code(f'{e.path}:{e.line}')} | {_cell(e.error)} |"
            )
        out.append("")
    if report.ingest_notes:
        out += [
            "## External sources",
            "",
            "| Tool | Status | Issues | Detail |",
            "|---|---|---|---|",
        ]
        for n in report.ingest_notes:
            out.append(f"| {_code(n.tool)} | {n.status} | {n.issues} | {_cell(n.detail) or '—'} |")
        out.append("")
    if report.delta and report.delta.fixed:
        out += [
            f"## Fixed since {_code(report.delta.baseline)} ({len(report.delta.fixed)})",
            "",
            "| Location | Sub-check | Severity | Fingerprint |",
            "|---|---|---|---|",
        ]
        out += [
            f"| {_code(f'{b.path}:{b.start_line}')} | {_code(b.subcheck_id)} | {b.severity} | "
            f"{_code(b.fingerprint)} |"
            for b in report.delta.fixed
        ]
        out.append("")
    if report.unresolved_total:
        out += [
            f"## Unresolved calls ({report.unresolved_total})",
            "",
            "These look like model calls, but their target could not be resolved, so no "
            "provider rule ran on them. Annotate the variable or construct the client in the "
            "module.",
            "",
        ]
        out += [f"- {_code(f'{u.path}:{u.line}')} {_code(u.callee)}" for u in report.unresolved]
        if report.unresolved_total > len(report.unresolved):
            out.append(f"- … {report.unresolved_total - len(report.unresolved)} more")
        out.append("")
    if report.agent_capabilities:
        out += [
            "## Agent capabilities",
            "",
            "What each agent can do (tools), what it reaches (MCP servers), and the approval "
            "guards in scope. A governance inventory, not findings.",
            "",
        ]
        for cap in report.agent_capabilities:
            guards = ", ".join(_code(m) for m in cap.approval_markers) or "none"
            out += [f"### {_code(cap.path)}", "", f"Approval markers in scope: {guards}", ""]
            if cap.sites:
                out += ["| Line | Binder | Tool | Capability |", "|---|---|---|---|"]
                for s in cap.sites:
                    binder = _code(s.binder)
                    if not s.tools:
                        out.append(f"| {s.line} | {binder} | — | — |")
                    out += [
                        f"| {s.line} | {binder} | {_code(t.name)} | {t.capability} |"
                        for t in s.tools
                    ]
                out.append("")
            if cap.mcp_servers:
                out += ["| MCP transport | Kind | Authenticated |", "|---|---|---|"]
                out += [
                    f"| {_code(m.transport)} | {m.kind} | {'yes' if m.authenticated else 'no'} |"
                    for m in cap.mcp_servers
                ]
                out.append("")
    index = report.index
    if index.disabled_checks:
        out += ["## Not run (project index disabled)", ""]
        out += [f"- {_code(sub)}" for sub in index.disabled_checks]
        out += [
            "",
            "These sub-checks need cross-file facts; enable with `index: {enabled: true}`.",
            "",
        ]
    if index.enabled and (index.files_indexed or index.skipped):
        out += [
            "## Project index",
            "",
            f"{index.files_indexed} files indexed for cross-file checks · "
            f"{index.files_not_admitted} not admitted by the gate (never read).",
            "",
        ]
        if index.skipped:
            out += ["| File | Reason | Detail |", "|---|---|---|"]
            out += [
                f"| {_code(sk.path)} | {sk.reason} | {_cell(sk.detail) or '—'} |"
                for sk in index.skipped
            ]
            out.append("")
    if report.experimental_skipped:
        out += ["## Not run (experimental)", ""]
        out += [f"- {_code(sub)}" for sub in report.experimental_skipped]
        out += ["", "Enable with `include_experimental: true` or a per-rule `enabled: true`.", ""]
    if report.unimplemented:
        out += ["## Not yet implemented", ""]
        out += [f"- {_code(sub)}" for sub in report.unimplemented]
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"
