"""SARIF 2.1.0 output for IDEs and code-scanning ingestion (spec 002 FR-212)."""

from typing import Any

from codepulse.core.model import Finding, Severity
from codepulse.core.report import AnalysisReport
from codepulse.core.serialization import canonical_json

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _result(f: Finding, rule_index: int) -> dict[str, Any]:
    return {
        "ruleId": f.subcheck_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[f.severity],
        "message": {"text": f.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.path, "uriBaseId": "SRCROOT"},
                    "region": {"startLine": f.location.start_line, "endLine": f.location.end_line},
                },
                "logicalLocations": [{"fullyQualifiedName": f.location.scope}],
            }
        ],
        "partialFingerprints": {"codepulse/v1": f.fingerprint},
        "properties": {
            "severity": str(f.severity),
            "detection": str(f.detection),
            "origin": str(f.origin),
            "component": str(f.component),
            "corroboratedBy": list(f.corroborated_by),
        },
    }


def render_sarif(report: AnalysisReport) -> str:
    rule_ids = sorted({f.subcheck_id for f in report.findings})
    index = {r: i for i, r in enumerate(rule_ids)}
    by_id = {f.subcheck_id: f for f in report.findings}
    rules = [
        {
            "id": r,
            "name": r,
            "shortDescription": {
                "text": f"{by_id[r].rule_id} {report.rule_names.get(by_id[r].rule_id, '')}".strip()
            },
            "help": {"text": by_id[r].remediation or ""},
            "defaultConfiguration": {"level": _LEVEL[by_id[r].severity]},
        }
        for r in rule_ids
    ]
    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodePulse",
                        "version": report.tool_version,
                        "semanticVersion": report.tool_version,
                        "rules": rules,
                    }
                },
                "automationDetails": {
                    "id": f"codepulse/{report.target.repository}/{report.target.mode}"
                },
                "results": [_result(f, index[f.subcheck_id]) for f in report.findings],
                "properties": {
                    "registryVersion": report.registry_version,
                    "configHash": report.config_hash,
                },
            }
        ],
    }
    return canonical_json(doc)
