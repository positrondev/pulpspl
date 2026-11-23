"""CSV output: one row per finding, a flat table for spreadsheets (spec 015 FR-1501).

Findings are already sorted canonically by the engine, so the rows are deterministic. The
format is RFC 4180 (CRLF, quoted fields), which Excel and every spreadsheet tool import
directly. Only confirmed findings are included, not the candidate (needs_review) list.
"""

import csv
import io

from codepulse.core.model import Finding
from codepulse.core.report import AnalysisReport

CSV_COLUMNS = (
    "severity",
    "rule_id",
    "subcheck_id",
    "component",
    "detection",
    "path",
    "start_line",
    "end_line",
    "scope",
    "message",
    "remediation",
    "origin",
    "source_tool",
    "fingerprint",
)


def _row(f: Finding) -> dict[str, object]:
    return {
        "severity": str(f.severity),
        "rule_id": f.rule_id,
        "subcheck_id": f.subcheck_id,
        "component": str(f.component),
        "detection": str(f.detection),
        "path": f.location.path,
        "start_line": f.location.start_line,
        "end_line": f.location.end_line,
        "scope": f.location.scope,
        "message": f.message,
        "remediation": f.remediation or "",
        "origin": str(f.origin),
        "source_tool": f.source_tool or "",
        "fingerprint": f.fingerprint,
    }


def render_csv(report: AnalysisReport) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(CSV_COLUMNS), lineterminator="\r\n")
    writer.writeheader()
    for finding in report.findings:
        writer.writerow(_row(finding))
    return buffer.getvalue()
