"""ClassificationPort backed by path globs in config — the Phase 1 stand-in until the
authoritative metadata source is confirmed (APDD open question 1)."""

from codepulse.core.config import ClassificationConfig
from codepulse.core.globs import glob_to_regex


class StaticClassification:
    def __init__(self, cfg: ClassificationConfig) -> None:
        self._default = cfg.default
        self._rules = [(glob_to_regex(r.pattern), r.level) for r in cfg.rules]

    def level_of(self, path: str) -> str:
        for rx, level in self._rules:
            if rx.fullmatch(path):
                return level
        return self._default
