"""Path-qualified validation helpers shared by config and rule-metadata loading."""

from collections.abc import Set
from typing import Any

from codepulse.core.errors import CodePulseError, ConfigError


def require(
    value: object, kind: type, path: str, label: str, err: type[CodePulseError] = ConfigError
) -> Any:
    # bool is an int subclass; never let True satisfy an int/str expectation by accident.
    if not isinstance(value, kind) or (kind is not bool and isinstance(value, bool)):
        raise err(f"{path}: expected {label}, got {type(value).__name__}")
    return value


def str_list(value: object, path: str, err: type[CodePulseError] = ConfigError) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise err(f"{path}: expected list of strings")
    return tuple(value)


def mapping(
    value: object,
    path: str,
    allowed: Set[str],
    err: type[CodePulseError] = ConfigError,
    required: Set[str] = frozenset(),
) -> dict[str, Any]:
    data: dict[str, Any] = require(value, dict, path, "mapping", err)
    unknown = sorted(str(k) for k in set(data) - set(allowed))
    if unknown:
        raise err(f"{path}: unknown key(s): {', '.join(unknown)}")
    missing = sorted(set(required) - set(data))
    if missing:
        raise err(f"{path}.{missing[0]}: required")
    return data
