"""SonarQube Web API adapter (APDD §6.3.3). Reads issues; never triggers analysis."""

import base64
import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlencode

from codepulse.core.external import ExternalIssue, IngestNote

PAGE_SIZE = 500
MAX_PAGES = 20  # SonarQube caps search results at 10k
TIMEOUT_S = 30


class SonarQubeAdapter:
    def __init__(
        self,
        base_url: str,
        project_key: str,
        token_env: str = "SONARQUBE_TOKEN",  # noqa: S107 — the env var's name, not a secret
        branch_analysis: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.project_key = project_key
        # Community Build analyzes one branch only and rejects a `branch` parameter.
        self._branch_analysis = branch_analysis
        token = os.environ.get(token_env, "")
        self._headers = {"Accept": "application/json"}
        if token:  # user token as basic-auth username, per SonarQube convention
            self._headers["Authorization"] = (
                "Basic " + base64.b64encode(f"{token}:".encode()).decode()
            )
        self._token_env = token_env

    def _get(self, path: str, params: dict[str, str | int]) -> dict[str, object]:
        url = f"{self.base_url}{path}?{urlencode(params)}"
        req = urllib.request.Request(url, headers=self._headers)  # noqa: S310 — operator-configured internal URL
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:  # noqa: S310 — operator-configured internal URL
            data = json.loads(resp.read().decode("utf-8"))
        return data if isinstance(data, dict) else {}

    def fetch_issues(self, branch: str | None) -> tuple[list[ExternalIssue], IngestNote]:
        """All unresolved issues for the branch. A branch SonarQube has not analyzed yet is
        reported as `pending` and never blocks the run (APDD §6.3.3)."""
        issues: list[ExternalIssue] = []
        params: dict[str, str | int] = {
            "components": self.project_key,  # `componentKeys` is deprecated since 10.2
            "resolved": "false",
            "ps": PAGE_SIZE,
        }
        if branch and self._branch_analysis:
            params["branch"] = branch
        try:
            for page in range(1, MAX_PAGES + 1):
                data = self._get("/api/issues/search", {**params, "p": page})
                batch = data.get("issues")
                if not isinstance(batch, list):
                    break
                issues += [i for item in batch if (i := _issue(item)) is not None]
                paging = data.get("paging")
                total = paging.get("total", 0) if isinstance(paging, dict) else 0
                if not isinstance(total, int) or page * PAGE_SIZE >= total:
                    break
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return [], IngestNote(
                    "sonarqube", "pending", 0, "branch not analyzed by SonarQube yet"
                )
            if exc.code in (401, 403):
                return [], IngestNote(
                    "sonarqube", "error", 0, f"HTTP {exc.code}: check {self._token_env}"
                )
            return [], IngestNote("sonarqube", "error", 0, f"HTTP {exc.code}")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return [], IngestNote("sonarqube", "error", 0, f"{type(exc).__name__}: {exc}")
        return issues, IngestNote("sonarqube", "ok", len(issues))


def _int(value: object, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _issue(item: object) -> ExternalIssue | None:
    if not isinstance(item, dict):
        return None
    component = str(item.get("component", ""))
    path = component.split(":", 1)[1] if ":" in component else component
    line = _int(item.get("line"), 1)
    text_range = item.get("textRange")
    end = _int(text_range.get("endLine"), line) if isinstance(text_range, dict) else line
    return ExternalIssue(
        "sonarqube",
        str(item.get("rule", "")),
        path,
        line,
        end,
        str(item.get("message", "")),
        str(item.get("severity", "")),
    )
