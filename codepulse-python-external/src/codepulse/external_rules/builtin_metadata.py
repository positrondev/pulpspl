"""Optional repo-controlled metadata for all E01-E16 built-in AST sub-checks.

Implementation callbacks remain trusted and unchanged. This loader rejects any
missing, added or renamed rule/sub-check to prevent silent partial migrations.
"""
from dataclasses import replace
from pathlib import Path

import yaml
from codepulse.core.errors import ConfigError
from codepulse.core.rule import RulePack


def with_builtin_metadata(packs: list[RulePack], repo: Path, relative: str | None) -> list[RulePack]:
    if relative is None:
        return packs
    root = repo.resolve()
    file = (root / relative).resolve()
    if not file.is_relative_to(root) or not file.is_file():
        raise ConfigError(f'external_rules.builtin_metadata: missing or outside repository: {relative}')
    try:
        metadata = yaml.safe_load(file.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ConfigError(f'external_rules.builtin_metadata: cannot parse {relative}: {exc}') from exc
    builtins = [p for p in packs if p.name == 'builtin']
    if len(builtins) != 1:
        raise ConfigError('external_rules.builtin_metadata: expected exactly one builtin pack')
    original = builtins[0]
    if not isinstance(metadata, dict) or set(metadata) != {'version', 'rules'} or not isinstance(metadata['version'], str) or not isinstance(metadata['rules'], dict):
        raise ConfigError('external_rules.builtin_metadata: expected version and rules')
    expected = {f'{rid}.{sid}' for rid, r in original.metadata['rules'].items() for sid in r['subchecks']}
    actual = {f'{rid}.{sid}' for rid, r in metadata['rules'].items() if isinstance(r, dict) and isinstance(r.get('subchecks'),dict) for sid in r['subchecks']}
    if actual != expected:
        raise ConfigError(f'external_rules.builtin_metadata: rule/sub-check coverage mismatch; missing={sorted(expected-actual)} added={sorted(actual-expected)}')
    if set(metadata['rules']) != set(original.metadata['rules']):
        raise ConfigError('external_rules.builtin_metadata: built-in rule group mismatch')
    # Registry.build performs full option, severity, detection and template validation.
    return [replace(p, metadata=metadata) if p.name == 'builtin' else p for p in packs]
