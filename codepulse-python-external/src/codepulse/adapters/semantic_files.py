"""File-backed verdict cache and JSONL egress log (spec 002 FR-204, FR-206)."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class FileVerdictCache:
    """One JSON file per key. Atomic replace, so a crash never leaves a torn verdict."""

    def __init__(self, root: Path) -> None:
        self._root = root

    def _path(self, key: str) -> Path:
        return self._root / key[:2] / f"{key}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        try:
            data = json.loads(self._path(key).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            return None  # unreadable entry: re-evaluate rather than trust it
        return data if isinstance(data, dict) else None

    def put(self, key: str, value: dict[str, Any]) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        tmp.replace(path)


class JsonlEgressLog:
    """Append-only record of every backend call: hashes and metadata, never payloads."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def record(self, entry: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = {"ts": datetime.now(UTC).isoformat(timespec="seconds"), **entry}
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, sort_keys=True) + "\n")
