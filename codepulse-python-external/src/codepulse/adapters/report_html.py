"""Self-contained HTML report (spec 003 FR-309): inline CSS and JS only, no external assets."""

import base64
import html
from importlib.resources import files

from codepulse.adapters.report_csv import render_csv
from codepulse.core.model import Finding, Severity
from codepulse.core.report import AnalysisReport

_ORIGINS = (("introduced", "introduced"), ("pre_existing", "pre-existing"), ("n/a", "n/a"))


def _asset(name: str) -> str:
    return files("codepulse").joinpath(f"data/html/{name}").read_text(encoding="utf-8")


def _e(s: object) -> str:
    return html.escape(str(s), quote=True)


def _select(ident: str, label: str, values: list[tuple[str, str]]) -> str:
    opts = "".join(f'<option value="{_e(v)}">{_e(text)}</option>' for v, text in values)
    return f'<select id="{ident}"><option value="">{_e(label)}</option>{opts}</select>'


def _card(f: Finding, rule_name: str) -> str:
    loc = f.location
    corro = f" · also {', '.join(_e(c) for c in f.corroborated_by)}" if f.corroborated_by else ""
    attrs = f'data-sev="{_e(f.severity)}" data-el="{_e(f.rule_id)}" data-org="{_e(f.origin)}"'
    title = f"<code>{_e(loc.path)}:{loc.start_line}</code> · <code>{_e(f.subcheck_id)}</code>"
    meta = (
        f"{_e(f.severity)} · {_e(f.rule_id)} {_e(rule_name)} · {_e(f.detection)} · "
        f"{_e(f.origin)} · scope <code>{_e(loc.scope)}</code>{corro}"
    )
    fix = f'<p class="fix"><b>Fix:</b> {_e(f.remediation)}</p>' if f.remediation else ""
    return (
        f'<article class="f" {attrs}><h3>{title}</h3><p class="meta">{meta}</p>'
        f"<p>{_e(f.message)}</p>{fix}"
        f'<p class="meta">fingerprint <code>{_e(f.fingerprint)}</code></p></article>'
    )


def render_html(report: AnalysisReport) -> str:
    s = report.summary()
    t = report.target
    target = f"{t.head} vs {t.base}" if t.head else str(t.mode)
    sev = s["by_severity"]
    stats = [
        (s["findings_total"], "findings"),
        (sev["critical"] + sev["high"], "critical + high"),
        (s["files_analyzed"], "files analyzed"),
        (s["files_skipped"], "files skipped"),
        (s["needs_review"], "need review"),
        (s["suppressed"], "suppressed"),
    ]
    stat_html = "".join(f'<div class="stat"><b>{n}</b><span>{_e(x)}</span></div>' for n, x in stats)
    elements = sorted({f.rule_id for f in report.findings})
    filters = (
        _select("sev", "All severities", [(str(x), str(x)) for x in Severity])
        + _select("el", "All elements", [(x, x) for x in elements])
        + _select("org", "Any origin", list(_ORIGINS))
        + '<input id="txt" type="search" placeholder="Filter text">'
        + '<span id="count" class="meta"></span>'
    )
    csv_b64 = base64.b64encode(render_csv(report).encode("utf-8")).decode("ascii")
    download = (
        f'<button id="dl" type="button" data-csv="{csv_b64}" '
        f'data-name="{_e(t.repository)}">Download CSV</button>'
    )
    cards = "".join(_card(f, report.rule_names.get(f.rule_id, "")) for f in report.findings)
    rows = "".join(
        f"<tr><td><code>{_e(u.candidate.location.path)}:{u.candidate.location.start_line}</code></td>"
        f"<td><code>{_e(u.candidate.subcheck_id)}</code></td><td>{_e(u.candidate.question)}</td></tr>"
        for u in report.needs_review
    )
    review = (
        f"<h2>Needs review ({len(report.needs_review)})</h2><table><tr><th>Location</th>"
        f"<th>Sub-check</th><th>Question</th></tr>{rows}</table>"
        if rows
        else ""
    )
    caps = _capabilities(report)
    head = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>CodePulse review</title><style>{_asset('report.css')}</style></head>"
    )
    sub = (
        f"{_e(target)} · registry <code>{_e(report.registry_version)}</code> · "
        f"semantic backend <code>{_e(report.semantic_backend)}</code>"
    )
    return (
        f"{head}<body><main><h1>CodePulse review — {_e(t.repository)}</h1>"
        f'<p class="sub">{sub}</p><section class="stats">{stat_html}</section>'
        f'<div class="filters">{filters}{download}</div>'
        + (cards or '<p class="empty">No findings.</p>')
        + review
        + caps
        + f"</main><script>{_asset('report.js')}</script></body></html>\n"
    )


def _capabilities(report: AnalysisReport) -> str:
    """The E16 agent capability map (spec 018 bucket D): a governance inventory, not findings."""
    if not report.agent_capabilities:
        return ""
    blocks = []
    for cap in report.agent_capabilities:
        guards = ", ".join(f"<code>{_e(m)}</code>" for m in cap.approval_markers) or "none"
        parts = [
            f'<h3><code>{_e(cap.path)}</code></h3><p class="meta">approval guards: {guards}</p>'
        ]
        tool_rows = "".join(
            f"<tr><td>{s.line}</td><td><code>{_e(s.binder)}</code></td>"
            f"<td><code>{_e(t.name)}</code></td><td>{_e(t.capability)}</td></tr>"
            for s in cap.sites
            for t in s.tools
        )
        if tool_rows:
            parts.append(
                "<table><tr><th>Line</th><th>Binder</th><th>Tool</th><th>Capability</th></tr>"
                f"{tool_rows}</table>"
            )
        mcp_rows = "".join(
            f"<tr><td><code>{_e(m.transport)}</code></td><td>{_e(m.kind)}</td>"
            f"<td>{'yes' if m.authenticated else 'no'}</td></tr>"
            for m in cap.mcp_servers
        )
        if mcp_rows:
            parts.append(
                "<table><tr><th>MCP transport</th><th>Kind</th><th>Authenticated</th></tr>"
                f"{mcp_rows}</table>"
            )
        blocks.append("".join(parts))
    return "<h2>Agent capabilities</h2>" + "".join(blocks)
