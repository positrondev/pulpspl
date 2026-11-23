"""Read existing linter/scanner output into ExternalIssues (spec 002 FR-209).

CodePulse never runs these tools: it reads the files CI already produces.
"""

import json
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

from codepulse.core.errors import CodePulseError
from codepulse.core.external import ExternalIssue

INGEST_TOOLS = ("ruff", "mypy", "bandit", "sarif")


class IngestError(CodePulseError):
    """An external report could not be read or parsed."""


def _rel(path: str, repo: Path) -> str:
    """Repo-relative POSIX path from whatever the tool printed."""
    if path.startswith("file://"):
        path = unquote(urlsplit(path).path)
    p = Path(path)
    if p.is_absolute():
        try:
            return p.resolve().relative_to(repo.resolve()).as_posix()
        except ValueError:
            return p.as_posix()  # outside the repo: dropped later as not analyzed
    return PurePosixPath(path.replace("\\", "/")).as_posix().removeprefix("./")


def _int(v: Any, default: int = 1) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) else default


def parse_ruff(text: str, repo: Path) -> list[ExternalIssue]:
    out = []
    for item in json.loads(text or "[]"):
        line = _int((item.get("location") or {}).get("row"))
        end = _int((item.get("end_location") or {}).get("row"), line)
        out.append(
            ExternalIssue(
                "ruff",
                str(item.get("code") or "ruff"),
                _rel(item["filename"], repo),
                line,
                end,
                str(item.get("message", "")),
            )
        )
    return out


def parse_mypy(text: str, repo: Path) -> list[ExternalIssue]:
    out = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        item = json.loads(raw)
        if item.get("severity") == "note":
            continue
        line = _int(item.get("line"))
        out.append(
            ExternalIssue(
                "mypy",
                str(item.get("code") or "misc"),
                _rel(item["file"], repo),
                line,
                line,
                str(item.get("message", "")),
                str(item.get("severity", "")),
            )
        )
    return out


def parse_bandit(text: str, repo: Path) -> list[ExternalIssue]:
    data = json.loads(text)
    out = []
    for item in data.get("results", []):
        line = _int(item.get("line_number"))
        rng = item.get("line_range") or [line]
        out.append(
            ExternalIssue(
                "bandit",
                str(item.get("test_id", "B000")),
                _rel(item["filename"], repo),
                line,
                _int(rng[-1], line),
                str(item.get("issue_text", "")),
                str(item.get("issue_severity", "")),
            )
        )
    return out


def parse_sarif(text: str, repo: Path) -> list[ExternalIssue]:
    data = json.loads(text)
    out = []
    for run in data.get("runs", []):
        driver = str((((run.get("tool") or {}).get("driver")) or {}).get("name") or "unknown")
        for res in run.get("results", []):
            locs = res.get("locations") or []
            if not locs:
                continue
            phys = locs[0].get("physicalLocation") or {}
            uri = (phys.get("artifactLocation") or {}).get("uri")
            if not uri:
                continue
            region = phys.get("region") or {}
            line = _int(region.get("startLine"))
            out.append(
                ExternalIssue(
                    f"sarif:{driver.lower()}",
                    str(res.get("ruleId") or "rule"),
                    _rel(uri, repo),
                    line,
                    _int(region.get("endLine"), line),
                    str((res.get("message") or {}).get("text", "")),
                    str(res.get("level") or "warning"),
                )
            )
    return out


PARSERS: dict[str, Callable[[str, Path], list[ExternalIssue]]] = {
    "ruff": parse_ruff,
    "mypy": parse_mypy,
    "bandit": parse_bandit,
    "sarif": parse_sarif,
}


def read_report(tool: str, path: Path, repo: Path) -> list[ExternalIssue]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise IngestError(f"{tool}: cannot read {path}: {exc.strerror}") from exc
    try:
        return PARSERS[tool](text, repo)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise IngestError(
            f"{tool}: {path} is not valid {tool} output ({type(exc).__name__}: {exc})"
        ) from exc
