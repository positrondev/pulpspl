"""Maintain objective coverage inventory for bundled external rules."""
from __future__ import annotations
import csv
from pathlib import Path
import yaml
from codepulse.external_rules.loader import load_rules

BASE=Path(__file__).resolve().parents[1]
source=yaml.safe_load((BASE/'src/codepulse/data/rules.yaml').read_text(encoding='utf-8'))['rules']
rules={r.id:r for r in load_rules(BASE,('rule-packs/core',),allow_external_paths=True)}
rows=[]
for group,meta in source.items():
    for sub,original in meta['subchecks'].items():
        key=f'{group}.{sub}'
        rule=rules.get(key)
        rows.append({
            'original_subcheck_id':key,
            'external_definition':'yes' if rule else 'no',
            'enabled_by_default':'yes' if rule and rule.enabled else 'no',
            'original_detection':original['detection'],
            'external_detection':rule.detection.value if rule else '',
            'original_severity':original['severity'],
            'external_severity':rule.severity.value if rule else '',
            'behavioral_parity_certified':'no',
            'status':('external_definition_unverified' if rule else 'not_migrated')
        })
assert len(rows)==77, f'expected 77, found {len(rows)}'
with (BASE/'MIGRATION_STATUS.csv').open('w',encoding='utf-8',newline='') as fh:
    writer=csv.DictWriter(fh,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
print(f"{len(rules)} YAML definitions, {sum(x['external_definition']=='yes' for x in rows)}/77 legacy subchecks represented")
