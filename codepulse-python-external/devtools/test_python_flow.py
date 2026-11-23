"""Tests limited declarative intra-function data flow, including safe negative cases."""
import unittest
import ast
from types import SimpleNamespace
from codepulse.core.errors import ConfigError
from codepulse.external_rules.flow_matcher import flow_matches, validate_flow


def run(source, **overrides):
    defaults={
        'type':'python_flow',
        'source_calls':[r'(?:^|\.)invoke$'],
        'source_parameters':[],
        'sink_calls':[r'(?:^|\.)execute$'],
        'sanitizer_calls':[r'(?:^|\.)model_validate$']
    }
    defaults.update(overrides)
    return flow_matches(source,SimpleNamespace(ast_predicate=validate_flow(defaults,'rule')),'src/demo.py')


class PythonFlowTests(unittest.TestCase):
    def test_direct(self):
        src='def f():\n cursor.execute(llm.invoke("x"))\n'
        self.assertEqual(len(run(src)),1)

    def test_assignment_propagation(self):
        src='def f():\n result=llm.invoke("x")\n value=result\n cursor.execute(value)\n'
        self.assertEqual(len(run(src)),1)

    def test_assignment_kill(self):
        src='def f():\n result=llm.invoke("x")\n result="fixed"\n cursor.execute(result)\n'
        self.assertEqual(len(run(src)),0)

    def test_sanitization(self):
        src='def f():\n result=llm.invoke("x")\n safe=Schema.model_validate(result)\n cursor.execute(safe)\n'
        self.assertEqual(len(run(src)),0)

    def test_parameter_origin(self):
        src='def handle(request):\n x=request\n system_message(x)\n'
        self.assertEqual(len(run(src,source_calls=[],source_parameters=['^request$'],sink_calls=['^system_message$'])),1)

    def test_branch(self):
        src='def f(flag):\n result="ok"\n if flag:\n  result=llm.invoke("x")\n cursor.execute(result)\n'
        self.assertEqual(len(run(src)),1)

    def test_separate_functions(self):
        src='def f():\n x=llm.invoke("x")\ndef g():\n cursor.execute(x)\n'
        self.assertEqual(len(run(src)),0)

    def test_invalid_specifications(self):
        with self.assertRaises(ConfigError):
            validate_flow({'type':'python_flow','source_calls':['['],'sink_calls':['x']},'test')
        with self.assertRaises(ConfigError):
            validate_flow({'type':'python_flow','source_calls':['x']},'test')

if __name__=='__main__': unittest.main()
