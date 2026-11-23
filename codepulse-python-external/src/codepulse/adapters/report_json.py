"""Canonical JSON renderings: the deterministic report and the per-run envelope."""

from codepulse.core.report import AnalysisReport, RunEnvelope
from codepulse.core.serialization import canonical_json


def render_json(report: AnalysisReport) -> str:
    return canonical_json(report.to_dict())


def render_envelope(envelope: RunEnvelope) -> str:
    return canonical_json(envelope.to_dict())
