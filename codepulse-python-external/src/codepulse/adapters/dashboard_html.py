"""Self-contained dashboard (spec 009 FR-908): one HTML file, inline CSS/JS, data embedded
as JSON. No network, no CDN: it opens from disk, in a browser or an editor preview."""

import html
from importlib.resources import files
from typing import Any

from codepulse.core.serialization import canonical_json


def _asset(name: str) -> str:
    return files("codepulse").joinpath(f"data/html/{name}").read_text(encoding="utf-8")


def render_dashboard_json(data: dict[str, Any]) -> str:
    return canonical_json(data)


def _embed(data: dict[str, Any]) -> str:
    # JSON inside <script>: "</" and "<!--" must not appear, so escape every "<".
    return canonical_json(data).replace("<", "\\u003c")


def _table(rows: list[list[str]], head: list[str]) -> str:
    th = "".join(f"<th>{html.escape(h)}</th>" for h in head)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return (
        f'<div class="tablewrap"><table><thead><tr>{th}</tr></thead>'
        f"<tbody>{body}</tbody></table></div>"
    )


def _governance(data: dict[str, Any]) -> str:
    e = html.escape
    cal = [
        [
            e(r["repository"]),
            f"<code>{e(c['subcheck_id'])}</code>",
            str(c["confirmed"]),
            str(c["rejected"]),
            str(c["waived"]),
            "—" if c["confirmation_rate"] is None else f"{c['confirmation_rate']:.0%}",
        ]
        for r in data["repositories"]
        for c in r["calibration"]
    ]
    waivers = [
        [
            e(r["repository"]),
            f"<code>{e(w['path'])}</code>",
            f"<code>{e(w['subcheck_id'])}</code>",
            e(w["justification"] or ""),
            e(w["expires"] or "") + (" (expired)" if w["expired"] else ""),
        ]
        for r in data["repositories"]
        for w in r["waivers"]
    ]
    out = "<h2>Calibration</h2>"
    out += (
        _table(cal, ["Repository", "Sub-check", "Acted on", "Rejected", "Waived", "Confirmation"])
        if cal
        else '<p class="muted">No reviewer decisions yet.</p>'
    )
    out += "<h2>Waivers</h2>"
    out += (
        _table(waivers, ["Repository", "Path", "Sub-check", "Justification", "Expires"])
        if waivers
        else '<p class="muted">No waivers.</p>'
    )
    return out


def render_dashboard_html(data: dict[str, Any]) -> str:
    filters = (
        '<input id="f-text" type="search" placeholder="Filter path, rule, message" '
        'aria-label="Filter">'
        '<select id="f-repo" aria-label="Repository">'
        '<option value="">All repositories</option></select>'
        '<select id="f-sev" aria-label="Severity"><option value="">All severities</option></select>'
        '<select id="f-status" aria-label="Status"><option value="">Any status</option></select>'
        '<select id="f-rule" aria-label="Element"><option value="">All elements</option></select>'
        '<label><input id="f-open" type="checkbox" checked> open only</label>'
    )
    table = (
        '<div class="tablewrap"><table><thead><tr><th>Severity</th><th>Status</th>'
        "<th>Repository</th><th>Location</th><th>Sub-check</th><th>Message</th></tr></thead>"
        '<tbody id="issues"></tbody></table></div>'
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>CodePulse dashboard</title>"
        f"<style>{_asset('report.css')}{_asset('dashboard.css')}</style></head><body><main>"
        "<h1>CodePulse dashboard</h1>"
        '<p class="sub">From the local findings store. Click an issue for details and a '
        "ticket-ready export.</p>"
        '<section id="repos" class="repos" aria-label="Repositories"></section>'
        f'<h2>Issues</h2><div class="filters">{filters}</div><p id="count" class="meta"></p>'
        f"{table}{_governance(data)}"
        f'<script type="application/json" id="cp-data">{_embed(data)}</script>'
        f"<script>{_asset('dashboard.js')}</script></main></body></html>\n"
    )
