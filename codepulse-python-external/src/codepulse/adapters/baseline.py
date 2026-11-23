"""Read a previous findings.json as a delta baseline (spec 006 FR-601)."""

import json
from pathlib import Path

from codepulse.core.delta import Baseline
from codepulse.core.errors import CodePulseError


def read_baseline(path: Path) -> Baseline:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CodePulseError(f"--baseline {path}: cannot read ({exc})") from exc
    try:
        return Baseline.from_findings_json(path.name, data)
    except (KeyError, TypeError, ValueError) as exc:
        raise CodePulseError(f"--baseline {path}: {exc}") from exc
