# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

import tree_sitter_python
import tree_sitter as py_tree_sitter
from vanir.language_parsers import tree_sitter_base

from absl.testing import absltest

_PYTHON_LANGUAGE = py_tree_sitter.Language(tree_sitter_python.language())


class _DummyPythonParser(tree_sitter_base.TreeSitterParserBase):
  CONFIG = tree_sitter_base.TreeSitterLanguageConfig(
      language=_PYTHON_LANGUAGE,
      error_tag='PythonParser',
      extensions=('.py',),
      node_types_to_skip=frozenset({'comment'}),
      node_types_to_collapse=frozenset({'string'}),
      func_node_types=frozenset({'function_definition'}),
  )

  def _extract_function_details(
      self, func_node: py_tree_sitter.Node
  ) -> tree_sitter_base.FunctionDetails | None:
    name_node = func_node.child_by_field_name('name')
    name = name_node.text.decode('utf-8') if name_node else ''
    return tree_sitter_base.FunctionDetails(name=name)

  def _visit_body_node(
      self,
      node: py_tree_sitter.Node,
      details: tree_sitter_base.FunctionDetails,
  ) -> None:
    if node.type == 'identifier':
      details.local_variables.append(node.text.decode('utf-8'))


class TreeSitterBaseTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.parser = tree_sitter_base._create_parser(_PYTHON_LANGUAGE)
    self.dummy_parser = _DummyPythonParser('dummy.py')

  def test_line_tokens_cursor(self):
    code = b"def foo():\n  # comment\n  return 'hello'"
    tree = self.parser.parse(code)
    tokens_by_line = self.dummy_parser.line_tokens_cursor(tree.root_node)
    self.assertEqual(tokens_by_line[1], ['def', 'foo', '(', ')', ':'])
    self.assertNotIn(2, tokens_by_line)
    self.assertEqual(tokens_by_line[3], ['return', "'hello'"])

  def test_flat_tokens_cursor(self):
    code = b"def foo():\n  # comment\n  return 'hello'"
    tree = self.parser.parse(code)
    tokens = self.dummy_parser.flat_tokens_cursor(tree.root_node)
    self.assertEqual(tokens, ['def', 'foo', '(', ')', ':', 'return', "'hello'"])

  def test_collect_errors_cursor(self):
    code = b'def foo():\n  return 0xe8()'
    tree = self.parser.parse(code)
    errors = tree_sitter_base._collect_errors_cursor(tree.root_node, 'Test')
    # Valid Python or error check
    self.assertIsInstance(errors, list)

  def test_generic_treesitter_parser_abstract_methods(self):
    class _IncompleteParser(tree_sitter_base.TreeSitterParserBase):
      CONFIG = tree_sitter_base.TreeSitterLanguageConfig(
          language=_PYTHON_LANGUAGE,
          error_tag='PythonParser',
          extensions=('.py',),
          node_types_to_skip=frozenset(),
          node_types_to_collapse=frozenset(),
          func_node_types=frozenset(),
      )

    with self.assertRaises(TypeError):
      _IncompleteParser('dummy.py')

  def test_generic_treesitter_parser_get_supported_extensions(self):
    self.assertEqual(_DummyPythonParser.get_supported_extensions(), ('.py',))

  def test_generic_treesitter_parser_get_chunks_error_tag(self):
    temp_file = self.create_tempfile(content='def foo(\n')
    parser = _DummyPythonParser(temp_file.full_path)
    results = parser.get_chunks()
    self.assertNotEmpty(results.parse_errors)
    self.assertStartsWith(results.parse_errors[0].message, 'PythonParser: ')

  def test_generic_treesitter_parser_get_chunks(self):
    temp_file = self.create_tempfile(
        content='def foo():\n  # comment\n  x = 1\n  return x\n'
    )
    parser = _DummyPythonParser(temp_file.full_path)
    results = parser.get_chunks()
    self.assertEmpty(results.parse_errors)
    self.assertIn(1, results.line_chunk.tokens)
    self.assertEqual(
        results.line_chunk.tokens[1], ['def', 'foo', '(', ')', ':']
    )
    self.assertNotIn(2, results.line_chunk.tokens)
    self.assertLen(results.function_chunks, 1)
    chunk = results.function_chunks[0]
    self.assertEqual(chunk.name, 'foo')
    self.assertIn('x', chunk.local_variables)

  def test_generic_treesitter_parser_affected_lines_filter(self):
    temp_file = self.create_tempfile(
        content='def foo():\n  return 1\n'
    )
    parser = _DummyPythonParser(temp_file.full_path)
    results = parser.get_chunks(
        affected_line_ranges_for_functions=[(10, 20)]
    )
    self.assertEmpty(results.function_chunks)


if __name__ == '__main__':
  absltest.main()
