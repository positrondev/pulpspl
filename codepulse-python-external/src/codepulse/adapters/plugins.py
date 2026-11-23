"""Discover rule packs registered under the ``codepulse.rules`` entry-point group."""

from importlib.metadata import entry_points

from codepulse.core.errors import RegistryError
from codepulse.core.rule import RulePack

ENTRY_POINT_GROUP = "codepulse.rules"


def discover_packs() -> list[RulePack]:
    """Load every pack, ordered by entry-point name. A broken plugin fails the run by name
    rather than silently dropping its rules."""
    packs = []
    for ep in sorted(entry_points(group=ENTRY_POINT_GROUP), key=lambda e: e.name):
        try:
            obj = ep.load()
            if not isinstance(obj, RulePack) and callable(obj):
                obj = obj()
        # Any import-time or factory failure is surfaced with the plugin's name.
        except Exception as exc:
            raise RegistryError(
                f"rule plugin {ep.name!r} ({ep.value}) failed to load: {type(exc).__name__}: {exc}"
            ) from exc
        if not isinstance(obj, RulePack):
            raise RegistryError(
                f"rule plugin {ep.name!r} must provide a RulePack, got {type(obj).__name__}"
            )
        packs.append(obj)
    if not packs:
        # Frozen / compiled builds (Nuitka, PyInstaller, zipapp) carry no entry-point
        # metadata, so the discovery above finds nothing. Load the built-in pack directly
        # so the analyzer still has its rules; third-party packs still need entry points.
        raise RegistryError("No trusted rule packs available. Configure external YAML rule directories.")
    return packs
