"""External rule predicate and repository isolation smoke tests."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from codepulse.external_rules.ast_matcher import query_matches
from codepulse.external_rules.loader import load_rules

ROOT = Path(__file__).resolve().parent
RULES = {rule.id: rule for rule in load_rules(ROOT, ('rule-packs/core',), allow_external_paths=True)}


class ExternalRuleTests(unittest.TestCase):
    def test_raw_request_body_positive(self):
        source = "@app.post('/orders')\ndef handler(request):\n    return request.json()\n"
        self.assertEqual(len(query_matches(source, RULES['E10.unvalidated-body'], 'api.py')), 1)

    def test_raw_request_body_negative(self):
        source = "def helper(request):\n    return request.json()\n"
        self.assertEqual(query_matches(source, RULES['E10.unvalidated-body'], 'helper.py'), [])

    def test_mcp_remote_positive(self):
        source = "sse_client('https://mcp.vendor.org/sse')\n"
        self.assertEqual(len(query_matches(source, RULES['E16.mcp-untrusted-transport'], 'app.py')), 1)

    def test_mcp_remote_auth_negative(self):
        source = "sse_client('https://mcp.vendor.org/sse', headers={'x-api-key': key})\n"
        self.assertEqual(query_matches(source, RULES['E16.mcp-untrusted-transport'], 'app.py'), [])

    def test_mcp_docs_domain_negative(self):
        source = "sse_client('https://example.com/sse')\n"
        self.assertEqual(query_matches(source, RULES['E16.mcp-untrusted-transport'], 'app.py'), [])

    def test_dangerous_tool_positive(self):
        src = "llm.bind_tools([ShellTool()])\n"
        self.assertEqual(len(query_matches(src, RULES['E16.dangerous-tool'], 'agent.py')), 1)

    def test_dangerous_tool_negative(self):
        src = "llm.bind_tools([SearchTool()])\n"
        self.assertEqual(query_matches(src, RULES['E16.dangerous-tool'], 'agent.py'), [])

    def test_core_severities_agree_with_source_metadata(self):
        import yaml
        reference = yaml.safe_load((ROOT/'src/codepulse/data/rules.yaml').read_text())['rules']
        for rule in RULES.values():
            outer, _, inner = rule.id.partition('.')
            meta = reference.get(outer,{}).get('subchecks',{}).get(inner)
            if meta:
                self.assertEqual(rule.severity.value,meta['severity'],rule.id)
                if meta['detection'] in ('deterministic','heuristic'):
                    self.assertEqual(rule.detection.value,meta['detection'],rule.id)

    def test_repository_isolation_and_cli(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            repo = root/'gitfolio'
            repo.mkdir()
            subprocess.run(['git','init','-q',str(repo)],check=True)
            subprocess.run(['git','-C',str(repo),'config','user.email','codepulse@example.invalid'],check=True)
            subprocess.run(['git','-C',str(repo),'config','user.name','CodePulse Test'],check=True)
            (repo/'app.py').write_text("def ok():\n    return 1\n",encoding='utf-8')
            subprocess.run(['git','-C',str(repo),'add','.'],check=True)
            subprocess.run(['git','-C',str(repo),'commit','-qm','initial'],check=True)
            subprocess.run(['git','-C',str(repo),'switch','-qc','test/check'],check=True)
            (repo/'api.py').write_text("@app.post('/orders')\ndef handler(request):\n    return request.json()\n",encoding='utf-8')
            subprocess.run(['git','-C',str(repo),'add','.'],check=True)
            subprocess.run(['git','-C',str(repo),'commit','-qm','add route'],check=True)
            output = root/'results'
            env = dict(os.environ)
            env['PYTHONPATH'] = str(ROOT/'src')
            command = [sys.executable,'-m','codepulse','review','--repo',str(repo),'--config',str(ROOT/'config/codepulse.yaml'),
                       '--branch','test/check','--base','HEAD~1','--no-store','--output',str(output),'--format','json,html,sarif,csv,md']
            p=subprocess.run(command,cwd=ROOT,env=env,text=True,capture_output=True)
            self.assertEqual(p.returncode,0,p.stdout+'\n'+p.stderr)
            self.assertTrue((output/'findings.json').exists())
            self.assertIn('E10.unvalidated-body',(output/'findings.json').read_text())
            self.assertFalse((repo/'.codepulse').exists())
            self.assertFalse((repo/'codepulse.yaml').exists())
            status=subprocess.run(['git','-C',str(repo),'status','--porcelain'],capture_output=True,text=True,check=True)
            self.assertEqual(status.stdout,'')

if __name__ == '__main__':
    unittest.main()
