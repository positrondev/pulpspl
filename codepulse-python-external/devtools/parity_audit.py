"""Developer-only behavioral comparison of two Code Pulse implementations.

Requires Python >= 3.12, legacy source tree, and external-only source tree.
Uses separate interpreters/import paths; the external runtime never imports legacy rules.
This tool does NOT certify a check merely because no finding was emitted.
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import os
import subprocess
import sys
from pathlib import Path


def execute(source: Path, repository: Path, output: Path, config: Path | None) -> dict:
    env = dict(os.environ, PYTHONPATH=str(source.resolve()))
    cmd = [sys.executable, '-m', 'codepulse', 'review', '--repo', str(repository.resolve()),
           '--all', '--no-store', '--output', str(output), '--format', 'json']
    if config is not None:
        cmd.extend(['--config', str(config.resolve())])
    proc = subprocess.run(cmd, cwd=repository, env=env, text=True, capture_output=True)
    if proc.returncode:
        raise RuntimeError(f'Scan using {source} failed ({proc.returncode}):\n{proc.stderr}\n{proc.stdout}')
    return json.loads((output/'findings.json').read_text(encoding='utf-8'))


def normalized(finding: dict) -> tuple:
    loc = finding['location']
    return (finding['subcheck_id'], loc['path'], loc['start_line'],
            loc['end_line'], finding['severity'], finding['detection'])


def compare(original: dict, external: dict, original_ids: list[str]) -> list[dict]:
    original_by_id: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    external_by_id: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for item in original.get('findings',[]):
        original_by_id[item['subcheck_id']][normalized(item)] += 1
    for item in external.get('findings',[]):
        external_by_id[item['subcheck_id']][normalized(item)] += 1
    rows=[]
    for sid in original_ids:
        legacy=original_by_id[sid]
        current=external_by_id[sid]
        missing=sum((legacy-current).values())
        extra=sum((current-legacy).values())
        # A zero/zero match is NOT proof of parity: fixture must exercise both sides.
        status=('not_exercised' if not legacy and not current else
                'matching_fixture' if not missing and not extra else 'mismatch')
        rows.append({'subcheck_id':sid,'legacy_count':sum(legacy.values()),
                     'external_count':sum(current.values()), 'missing':missing,
                     'extra':extra,'fixture_status':status})
    return rows


def main() -> int:
    parser=argparse.ArgumentParser(description='Compare independent legacy/external Code Pulse engines')
    parser.add_argument('--legacy-src', type=Path, required=True)
    parser.add_argument('--external-src', type=Path, required=True)
    parser.add_argument('--external-config', type=Path, required=True)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)
    with args.inventory.open(newline='',encoding='utf-8') as stream:
        ids=[r['original_subcheck_id'] for r in csv.DictReader(stream)]
    legacy=execute(args.legacy_src,args.repo,args.output/'legacy',None)
    external=execute(args.external_src,args.repo,args.output/'external',args.external_config)
    rows=compare(legacy,external,ids)
    with (args.output/'parity_matrix.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=rows[0].keys())
        writer.writeheader();writer.writerows(rows)
    stats=dict(collections.Counter(r['fixture_status'] for r in rows))
    (args.output/'parity_summary.json').write_text(json.dumps({
        'rule_count':len(ids),'counts':stats,
        'certified_rules':0,
        'note':'Matching on a fixture is not certification; require positive, negative, edge and integration cases.'
    },indent=2),encoding='utf-8')
    print('Rule fixture comparison:',stats,'\nSaved to',args.output)
    return 1 if stats.get('mismatch',0) else 0


if __name__=='__main__':
    raise SystemExit(main())
