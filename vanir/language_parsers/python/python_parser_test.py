# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for the tree-sitter backed Vanir Python parser."""

from unittest import mock

from absl import logging
import tree_sitter as py_tree_sitter
from vanir.language_parsers import abstract_language_parser
from vanir.language_parsers import common
from vanir.language_parsers.python import python_parser

from absl.testing import absltest
from absl.testing import parameterized


class PythonParserTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.testcode = """\
# This code is for testing the Vanir Python parser.
import os
from typing import Optional, List

class MyClass:
    def simple_method(self, x, y):
        z = x + y  # end of line comment
        return z

    def annotated_method(
        self,
        data: List[str],
        count: int = 0,
    ) -> Optional[bool]:
        # line-level comment
        result = None
        for item in data:
            value = transform(item)
            result = validate(value, count)
        return result

def top_level(arg1: int, arg2: str = "hi") -> bool:
    local_a, local_b = arg1, arg2
    x = 1
    x += 2  # augmented assignment
    if (n := len(arg2)) > 10:
        helper(n)
    return True

async def async_func(items):
    # comment inside an async function
    for i, item in enumerate(items):
        process(item)
"""
    self.testfile = self.create_tempfile('testfile.py', content=self.testcode)
    self.all_function_chunks = {
        'simple_method': common.FunctionChunkBase(
            name='simple_method',
            return_types=[],
            parameters=['self', 'x', 'y'],
            used_data_types=[],
            local_variables=['z'],
            called_functions=[],
            tokens=[
                'def', 'simple_method', '(', 'self', ',', 'x', ',', 'y', ')',
                ':', 'z', '=', 'x', '+', 'y', 'return', 'z',
            ],
        ),
        'annotated_method': common.FunctionChunkBase(
            name='annotated_method',
            return_types=[['Optional', '[', 'bool', ']']],
            parameters=['self', 'data', 'count'],
            used_data_types=[
                ['Optional', '[', 'bool', ']'],
                ['List', '[', 'str', ']'],
                ['int'],
            ],
            local_variables=['result', 'item', 'value'],
            called_functions=['transform', 'validate'],
            tokens=[
                'def', 'annotated_method', '(', 'self', ',', 'data', ':',
                'List', '[', 'str', ']', ',', 'count', ':', 'int', '=', '0',
                ',', ')', '->', 'Optional', '[', 'bool', ']', ':', 'result',
                '=', 'None', 'for', 'item', 'in', 'data', ':', 'value', '=',
                'transform', '(', 'item', ')', 'result', '=', 'validate', '(',
                'value', ',', 'count', ')', 'return', 'result',
            ],
        ),
        'top_level': common.FunctionChunkBase(
            name='top_level',
            return_types=[['bool']],
            parameters=['arg1', 'arg2'],
            used_data_types=[['bool'], ['int'], ['str']],
            local_variables=['local_a', 'local_b', 'x', 'n'],
            called_functions=['len', 'helper'],
            tokens=[
                'def', 'top_level', '(', 'arg1', ':', 'int', ',', 'arg2', ':',
                'str', '=', '"hi"', ')', '->', 'bool', ':', 'local_a', ',',
                'local_b', '=', 'arg1', ',', 'arg2', 'x', '=', '1', 'x', '+=',
                '2', 'if', '(', 'n', ':=', 'len', '(', 'arg2', ')', ')', '>',
                '10', ':', 'helper', '(', 'n', ')', 'return', 'True',
            ],
        ),
        'async_func': common.FunctionChunkBase(
            name='async_func',
            return_types=[],
            parameters=['items'],
            used_data_types=[],
            local_variables=['i', 'item'],
            called_functions=['enumerate', 'process'],
            tokens=[
                'async', 'def', 'async_func', '(', 'items', ')', ':', 'for',
                'i', ',', 'item', 'in', 'enumerate', '(', 'items', ')', ':',
                'process', '(', 'item', ')',
            ],
        ),
    }

  def test_supported_file_types(self):
    self.assertEqual(
        list(python_parser.PythonParser.get_supported_extensions()),
        ['.py'],
        'Claimed supported extensions do not match.',
    )

  def test_parsing_no_line_limit(self):
    results = python_parser.PythonParser(self.testfile.full_path).get_chunks()
    self.assertEmpty(results.parse_errors)
    self.assertLen(results.function_chunks, len(self.all_function_chunks))
    chunks_by_name = {c.name: c for c in results.function_chunks}
    self.assertEqual(list(chunks_by_name), list(self.all_function_chunks))

    for name, expected_chunk in self.all_function_chunks.items():
      actual_chunk = chunks_by_name[name]
      self.assertEqual(actual_chunk.name, expected_chunk.name)
      self.assertEqual(actual_chunk.parameters, expected_chunk.parameters)
      self.assertEqual(actual_chunk.return_types, expected_chunk.return_types)
      self.assertEqual(
          actual_chunk.used_data_types, expected_chunk.used_data_types
      )
      self.assertEqual(
          actual_chunk.local_variables, expected_chunk.local_variables
      )
      self.assertEqual(
          actual_chunk.called_functions, expected_chunk.called_functions
      )
      self.assertEqual(actual_chunk.tokens, expected_chunk.tokens)

  def test_parsing_with_line_limit(self):
    # simple_method is lines 6-8, top_level is lines 22-28.
    results = python_parser.PythonParser(self.testfile.full_path).get_chunks(
        affected_line_ranges_for_functions=[(6, 8), (22, 28)]
    )
    self.assertEmpty(results.parse_errors)
    func_names = [f.name for f in results.function_chunks]
    self.assertEqual(func_names, ['simple_method', 'top_level'])

  @parameterized.named_parameters(
      # Variable assignments
      dict(
          testcase_name='simple_assignment',
          body='x = 1',
          expected_local_variables=['x'],
          expected_called_functions=[],
          expected_used_data_types=[],
      ),
      dict(
          testcase_name='annotated_assignment',
          body='x: Dict[str, int] = {}',
          expected_local_variables=['x'],
          expected_called_functions=[],
          expected_used_data_types=[['Dict', '[', 'str', ',', 'int', ']']],
      ),
      dict(
          testcase_name='augmented_assignment',
          body='total += 1',
          expected_local_variables=['total'],
          expected_called_functions=[],
          expected_used_data_types=[],
      ),
      dict(
          testcase_name='attribute_assignment_ignored',
          body='self.count += 1',
          expected_local_variables=[],
          expected_called_functions=[],
          expected_used_data_types=[],
      ),
      dict(
          testcase_name='duplicate_assignment_recorded_once',
          body='x = 1\n    x = 2',
          expected_local_variables=['x'],
          expected_called_functions=[],
          expected_used_data_types=[],
      ),

      # Function and method calls
      dict(
          testcase_name='direct_call',
          body='helper(a)',
          expected_local_variables=[],
          expected_called_functions=['helper'],
          expected_used_data_types=[],
      ),
      dict(
          testcase_name='indirect_call_ignored',
          body='handlers[0]()\n    get_fn()()\n    (lambda: None)()',
          expected_local_variables=[],
          expected_called_functions=['get_fn'],
          expected_used_data_types=[],
      ),
      dict(
          testcase_name='method_call',
          body='obj.foo()\n    self.bar()',
          expected_local_variables=[],
          expected_called_functions=['foo', 'bar'],
          expected_used_data_types=[],
      ),
      dict(
          testcase_name='module_call',
          body='os.path.join(a)',
          expected_local_variables=[],
          expected_called_functions=['join'],
          expected_used_data_types=[],
      ),
      dict(
          testcase_name='chained_call',
          body='return Foo(a).bar()',
          expected_local_variables=[],
          expected_called_functions=['bar', 'Foo'],
          expected_used_data_types=[],
      ),
      dict(
          testcase_name='duplicate_call_recorded_once',
          body='f()\n    f()',
          expected_local_variables=[],
          expected_called_functions=['f'],
          expected_used_data_types=[],
      ),

      # Loops and named expressions
      dict(
          testcase_name='for_loop_tuple_unpacking',
          body='for (a, b) in pairs:\n        pass',
          expected_local_variables=['a', 'b'],
          expected_called_functions=[],
          expected_used_data_types=[],
      ),
      dict(
          testcase_name='starred_unpacking',
          body='head, *rest = seq',
          expected_local_variables=['head', 'rest'],
          expected_called_functions=[],
          expected_used_data_types=[],
      ),
      dict(
          testcase_name='named_expression',
          body='total = (n := 1)',
          expected_local_variables=['total', 'n'],
          expected_called_functions=[],
          expected_used_data_types=[],
      ),

      # Context managers and exception handlers
      # Note: Variables bound by 'as' in 'with' and 'except' clauses are not
      # recorded as local variables, matching JavaParser behavior (where
      # enterResourceSpecification and enterCatchClause are unimplemented).
      dict(
          testcase_name='with_statement',
          body='with open(p) as fh:\n        data = fh.read()',
          expected_local_variables=['data'],
          expected_called_functions=['open', 'read'],
          expected_used_data_types=[],
      ),
      dict(
          testcase_name='with_statement_multiple_items',
          body='with open(a) as src, open(b) as dst:\n        pass',
          expected_local_variables=[],
          expected_called_functions=['open'],
          expected_used_data_types=[],
      ),
      dict(
          testcase_name='except_clause',
          body=(
              'try:\n        pass\n    except ValueError as err:\n'
              '        log(err)'
          ),
          expected_local_variables=[],
          expected_called_functions=['log'],
          expected_used_data_types=[],
      ),
  )
  def test_function_body_extraction(
      self,
      body,
      expected_local_variables,
      expected_called_functions,
      expected_used_data_types,
  ):
    code = f'def f(self):\n    {body}\n'
    testfile = self.create_tempfile('body.py', content=code)
    results = python_parser.PythonParser(testfile.full_path).get_chunks()
    self.assertEmpty(results.parse_errors)
    self.assertLen(results.function_chunks, 1)
    chunk = results.function_chunks[0]
    self.assertEqual(chunk.local_variables, expected_local_variables)
    self.assertEqual(chunk.called_functions, expected_called_functions)
    self.assertEqual(chunk.used_data_types, expected_used_data_types)

  def test_parameter_variations(self):
    code = """\
def untyped_fn(a, b=1, /, *args, **kwargs):
    pass

def typed_fn(a: int, /, b: str = 'x', *args: int, **kwargs: dict):
    pass
"""
    testfile = self.create_tempfile('params.py', content=code)
    results = python_parser.PythonParser(testfile.full_path).get_chunks()
    self.assertEmpty(results.parse_errors)
    self.assertLen(results.function_chunks, 2)

    untyped = results.function_chunks[0]
    self.assertEqual(untyped.parameters, ['a', 'b', 'args', 'kwargs'])
    self.assertEmpty(untyped.used_data_types)

    typed = results.function_chunks[1]
    self.assertEqual(typed.parameters, ['a', 'b', 'args', 'kwargs'])
    self.assertIn(['int'], typed.used_data_types)
    self.assertIn(['str'], typed.used_data_types)
    self.assertIn(['dict'], typed.used_data_types)

  def test_nested_functions(self):
    code = """\
def outer_fn(x):
    outer_var = x + 1
    def inner_fn(y):
        inner_var = y * 2
        inner_call(inner_var)
        return inner_var
    outer_call(outer_var)
    return outer_var
"""
    testfile = self.create_tempfile('nested.py', content=code)
    results = python_parser.PythonParser(testfile.full_path).get_chunks()
    self.assertEmpty(results.parse_errors)
    self.assertLen(results.function_chunks, 2)

    outer_chunk = results.function_chunks[0]
    inner_chunk = results.function_chunks[1]

    self.assertEqual(outer_chunk.name, 'outer_fn')
    self.assertEqual(outer_chunk.parameters, ['x'])
    self.assertEqual(outer_chunk.local_variables, ['outer_var'])
    self.assertEqual(outer_chunk.called_functions, ['outer_call'])

    self.assertEqual(inner_chunk.name, 'inner_fn')
    self.assertEqual(inner_chunk.parameters, ['y'])
    self.assertEqual(inner_chunk.local_variables, ['inner_var'])
    self.assertEqual(inner_chunk.called_functions, ['inner_call'])

  def test_parsing_with_syntax_error(self):
    error_code = """\
import os
class MyClass:
    def func(self):
        0xe8 0xe8  # should throw an error but continue on
        var: int
"""
    error_testfile = self.create_tempfile(
        'error_testfile.py', content=error_code
    )
    expected_tokens_with_errors = {
        1: ['import', 'os'],
        2: ['class', 'MyClass', ':'],
        3: ['def', 'func', '(', 'self', ')', ':'],
        4: ['0xe8', '0xe8'],
        5: ['var', ':', 'int'],
    }
    expected_function_chunks_with_errors = [
        common.FunctionChunkBase(
            name='func',
            return_types=[],
            parameters=['self'],
            used_data_types=[['int']],
            local_variables=['var'],
            called_functions=[],
            tokens=['def', 'func', '(', 'self', ')', ':', '0xe8', '0xe8', 'var',
                    ':', 'int'],
        ),
    ]
    expected_parse_errors = [
        common.ParseError(
            line=4,
            column=8,
            bad_token='0xe8',
            message="PythonParser: syntax error near '0xe8'",
        ),
    ]

    results = python_parser.PythonParser(error_testfile.full_path).get_chunks()
    self.assertSequenceEqual(
        results.parse_errors, expected_parse_errors, 'errors do not match'
    )
    self.assertDictEqual(
        results.line_chunk.tokens,
        expected_tokens_with_errors,
        'line chunk tokens do not match.',
    )
    self.assertSequenceEqual(
        results.function_chunks,
        expected_function_chunks_with_errors,
        'function chunks do not match.',
    )

  def test_python_parser_with_non_utf8_file(self):
    latin1_code = '# \xE0\n'
    testfile = self.create_tempfile(
        'testfile_latin1.py',
        content=latin1_code,
        encoding='LATIN-1',
    )
    with self.assertLogs(level=logging.INFO) as logs:
      parser = python_parser.PythonParser(testfile.full_path)
      results = parser.get_chunks()
      self.assertEmpty(results.parse_errors)
    self.assertRegex(logs.output[0], r'Converting.*to UTF-8.')

  def test_python_parser_with_known_encoding_file(self):
    latin1_str = '# \xE0\n'
    testfile = self.create_tempfile(
        'testfile_latin1.py',
        content=self.testcode + latin1_str,
        encoding='LATIN-1',
    )
    # Delete latin-1 from the alternative encoding.
    with mock.patch.object(
        abstract_language_parser,
        'ALTERNATIVE_ENCODINGS',
        (),
    ):
      with self.assertRaisesRegex(ValueError, 'Failed to decode'):
        python_parser.PythonParser(testfile.full_path).get_chunks()

  def test_extract_function_details_missing_name_returns_none(self):
    mock_node = mock.create_autospec(
        py_tree_sitter.Node, instance=True, spec_set=True
    )
    mock_node.child_by_field_name.return_value = None
    parser = python_parser.PythonParser(self.testfile.full_path)
    self.assertIsNone(parser._extract_function_details(mock_node))

  def test_decorator_tokens_excluded_from_chunk(self):
    code = """\
import functools

class MyClass:
    @staticmethod
    @functools.lru_cache(maxsize=1)
    def decorated(x):
        return x
"""
    testfile = self.create_tempfile('decorated.py', content=code)
    results = python_parser.PythonParser(testfile.full_path).get_chunks()
    self.assertEmpty(results.parse_errors)
    self.assertLen(results.function_chunks, 1)

    chunk = results.function_chunks[0]
    self.assertEqual(chunk.name, 'decorated')
    self.assertEqual(chunk.parameters, ['x'])
    self.assertEqual(chunk.called_functions, [])
    # Chunk starts at 'def', excluding decorator tokens.
    self.assertEqual(
        chunk.tokens, ['def', 'decorated', '(', 'x', ')', ':', 'return', 'x']
    )

if __name__ == '__main__':
  absltest.main()
