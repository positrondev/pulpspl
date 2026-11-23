"""Checks for reusable context predicates and real external rule examples."""
import ast
import unittest
from codepulse.external_rules.ast_matcher import QueryContext, evaluate, validate_query
from codepulse.core.errors import ConfigError


def matching(source, node_type, query):
    module=ast.parse(source)
    facts=QueryContext.build(module)
    out=[]
    def walk(node,ancestors=()):
        if type(node).__name__ == node_type and evaluate(query,node,ancestors,'src/demo.py',source,facts):
            out.append(node)
        for ch in ast.iter_child_nodes(node):walk(ch,(*ancestors,node))
    walk(module)
    return out


class StructuralExpansionTests(unittest.TestCase):
    def test_import_alias(self):
        s='import datetime as dt\nx = dt.datetime.now()\n'
        self.assertEqual(len(matching(s,'Call',{'resolved_callee_regex':r'^datetime\.datetime\.now$'})),1)
        self.assertEqual(len(matching(s,'Call',{'resolved_callee_regex':r'^datetime\.datetime\.today$'})),0)

    def test_import_from_alias(self):
        s='from time import time as get_time\nx = get_time()'
        self.assertEqual(len(matching(s,'Call',{'resolved_callee_regex':r'^time\.time$'})),1)

    def test_aliased_workflow(self):
        s='from temporalio import workflow\nimport random as rnd\n@workflow.defn\nclass W:\n @workflow.run\n async def run(self):\n  return rnd.random()\n'
        p={'all':[{'ancestor_decorator_regex':r'workflow\.run'},{'resolved_callee_regex':r'^random\.random$'}]}
        self.assertEqual(len(matching(s,'Call',p)),1)
        self.assertEqual(len(matching('import random\ndef run():\n return random.random()','Call',p)),0)

    def test_temporal_requires_workflow_class(self):
        src='from temporalio import workflow\nimport random as r\nclass X:\n @workflow.run\n async def run(self):\n  return r.random()'
        p={'all':[{'ancestor_class_decorator_regex':r'workflow\.defn'}, {'resolved_callee_regex':r'^random\.random$'}]}
        self.assertEqual(matching(src,'Call',p),[])

    def test_nested_dictionary(self):
        s='graph.invoke(data,config={"configurable":{"thread_id":"fixed"}})'
        self.assertEqual(len(matching(s,'Call',{'dict_path_literal':'config.configurable.thread_id'})),1)
        s='graph.invoke(data,config={"configurable":{"thread_id":user_id}})'
        self.assertEqual(len(matching(s,'Call',{'dict_path_literal':'config.configurable.thread_id'})),0)

    def test_scope_analysis(self):
        s='def work():\n conn.begin()\n conn.rollback()\ndef bad():\n conn.begin()\n'
        p={'all':[{'callee_regex':r'\.begin$'},{'not':{'scope_call_regex':r'\.rollback$'}}]}
        self.assertEqual(len(matching(s,'Call',p)),1)

    def test_fstring_call(self):
        s='from langchain_core.prompts import PromptTemplate\nPromptTemplate.from_template(f"Dear {user}")\nPromptTemplate.from_template("ok")'
        self.assertEqual(len(matching(s,'Call',{'call_has_fstring_arg':True})),1)

    def test_entropy(self):
        s='x="abC3#r1Q8x9P02Mzt4Nv6"\ny="aaaaaaaaaaaaaaaaaaaaaaaa"'
        self.assertEqual(len(matching(s,'Constant',{'all':[{'string_length_gte':20},{'string_entropy_gte':3.5}]})),1)

    def test_invalid_predicate(self):
        with self.assertRaises(ConfigError):
            validate_query({'node':'Call','where':{'resolved_callee_regex':'('}},'test')
        with self.assertRaises(ConfigError):
            validate_query({'node':'Call','where':{'string_entropy_gte':12}},'test')


if __name__ == '__main__': unittest.main()
