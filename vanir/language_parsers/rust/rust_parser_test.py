# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for Vanir Rust parser."""

from vanir import normalizer
from vanir.language_parsers import common
from vanir.language_parsers.rust import rust_parser

from absl.testing import absltest


class RustParserTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.testcode = """
      //! A documentation comment.
      /// A documentation comment of a function.
      pub fn outer(count: u32, names: Vec<String>) -> Option<u32> {
        // A line comment.
        let mut total: u32 = 0;
        let value = compute(count);
        if let Some(name) = lookup(names) {
          total += name.len();
        }
        while let Some(next) = iterator.next() {
          total = total + next;
        }
        for item in items {
          use_item(item);
        }
        match value {
          Some(v) => v,
          None => 0,
        };
        unsafe { danger(); }
        let closure = |x: u32| x + 1;
        pr_err!("a value: {}", total);
        Some(total)
      }

      struct Holder;

      impl Holder {
        fn method(&self, input: u8) -> u8 {
          input
        }
      }

      trait Shape {
        fn area(&self) -> f64;
        fn scaled_area(&self) -> f64 {
          self.area() * 2.0
        }
      }
    """
    self.testfile = self.create_tempfile('testfile.rs', content=self.testcode)

  def test_supported_file_types(self):
    self.assertEqual(
        list(rust_parser.RustParser.get_supported_extensions()),
        ['.rs'],
        'Claimed supported extensions do not match.',
    )

  def test_language_id(self):
    self.assertEqual(rust_parser.RustParser.get_language_id(), 'rust')

  def test_the_protected_keywords_of_the_language(self):
    self.assertEqual(
        rust_parser.RustParser.PROTECTED_KEYWORDS, frozenset({'mut'}))

  def test_is_test_file(self):
    for path in (
        'external/crosvm/tests/foo.rs',
        'external/crosvm/benches/bar.rs',
        'external/crosvm/examples/baz.rs',
        'a/b/tests/c/d.rs',
    ):
      self.assertTrue(
          rust_parser.RustParser.is_test_file(path),
          f'{path} should be recognized as a Rust test file.')

  def test_is_not_test_file(self):
    for path in (
        'external/crosvm/src/foo.rs',
        'rust/kernel/irq/request.rs',
        'src/testing/foo.rs',
        'foo/test.rs',
        'foo/testing.rs',
    ):
      self.assertFalse(
          rust_parser.RustParser.is_test_file(path),
          f'{path} should not be recognized as a Rust test file.')

  def test_the_function_names(self):
    results = self._parse()
    names = [chunk.name for chunk in results.function_chunks]
    self.assertIn('outer', names)
    self.assertIn('method', names)
    self.assertIn('scaled_area', names)
    # A trait method without a body is not a chunk.
    self.assertNotIn('area', names)

  def test_the_parameters_of_a_function(self):
    results = self._parse()
    chunk = self._chunk(results, 'outer')
    self.assertIn('count', chunk.parameters)
    self.assertIn('names', chunk.parameters)

  def test_the_parameters_of_a_method_include_self(self):
    results = self._parse()
    chunk = self._chunk(results, 'method')
    self.assertIn('self', chunk.parameters)
    self.assertIn('input', chunk.parameters)

  def test_the_local_variables_of_a_function(self):
    results = self._parse()
    chunk = self._chunk(results, 'outer')
    self.assertIn('total', chunk.local_variables)
    self.assertIn('value', chunk.local_variables)
    self.assertIn('name', chunk.local_variables)
    self.assertIn('next', chunk.local_variables)
    self.assertIn('item', chunk.local_variables)

  def test_the_called_functions_of_a_function(self):
    results = self._parse()
    chunk = self._chunk(results, 'outer')
    self.assertIn('compute', chunk.called_functions)
    self.assertIn('use_item', chunk.called_functions)
    self.assertIn('danger', chunk.called_functions)

  def test_the_name_of_a_macro_is_a_called_function(self):
    results = self._parse()
    chunk = self._chunk(results, 'outer')
    self.assertIn('pr_err', chunk.called_functions)

  def test_the_types_of_a_function(self):
    results = self._parse()
    chunk = self._chunk(results, 'outer')
    self.assertIn(['Option', '<', 'u32', '>'], chunk.used_data_types)

  def test_the_type_of_a_parameter_is_a_used_type(self):
    code = """
      fn a_function(
          names: Vec<String>,
          buffer: [u8; 4],
          text: &str,
          count: u32,
      ) {}
    """
    testfile = self.create_tempfile('testfile.rs', content=code)
    results = rust_parser.RustParser(testfile.full_path).get_chunks()
    chunk = self._chunk(results, 'a_function')
    self.assertIn(['Vec', '<', 'String', '>'], chunk.used_data_types)
    self.assertIn(['[', 'u8', ';', '4', ']'], chunk.used_data_types)
    self.assertIn(['&', 'str'], chunk.used_data_types)
    self.assertIn(['u32'], chunk.used_data_types)

  def test_the_name_of_a_method_call_is_a_called_function(self):
    code = """
      fn a_function() {
        let value = holder.method();
        let other = Vec::new();
        free_function(value, other);
      }
    """
    testfile = self.create_tempfile('testfile.rs', content=code)
    results = rust_parser.RustParser(testfile.full_path).get_chunks()
    chunk = self._chunk(results, 'a_function')
    self.assertIn('method', chunk.called_functions)
    self.assertIn('new', chunk.called_functions)
    self.assertIn('free_function', chunk.called_functions)

  def test_the_parameters_of_a_closure_are_the_parameters_of_the_function(self):
    code = """
      fn a_function() {
        let closure = |value: u32, other: u32| value + other;
        closure(1, 2);
      }
    """
    testfile = self.create_tempfile('testfile.rs', content=code)
    results = rust_parser.RustParser(testfile.full_path).get_chunks()
    chunk = self._chunk(results, 'a_function')
    self.assertIn('value', chunk.parameters)
    self.assertIn('other', chunk.parameters)

  def test_a_match_arm_declares_the_variable_it_binds(self):
    code = """
      fn a_function(value: Option<u32>) -> u32 {
        match value {
          Some(bound) => bound,
          None => 0,
        }
      }
    """
    testfile = self.create_tempfile('testfile.rs', content=code)
    results = rust_parser.RustParser(testfile.full_path).get_chunks()
    chunk = self._chunk(results, 'a_function')
    self.assertIn('bound', chunk.local_variables)
    # The name of the variant is not a variable.
    self.assertNotIn('Some', chunk.local_variables)
    self.assertNotIn('None', chunk.local_variables)

  def test_the_comments_are_not_part_of_the_tokens(self):
    results = self._parse()
    chunk = self._chunk(results, 'outer')
    self.assertNotIn('A', chunk.tokens)
    self.assertNotIn('documentation', chunk.tokens)
    self.assertNotIn('comment', chunk.tokens)

  def test_a_string_literal_is_kept_whole(self):
    results = self._parse()
    chunk = self._chunk(results, 'outer')
    self.assertIn('"a value: {}"', chunk.tokens)

  def test_the_visibility_is_not_part_of_the_tokens_of_the_function(self):
    results = self._parse()
    chunk = self._chunk(results, 'outer')
    self.assertNotIn('pub', chunk.tokens)
    # The visibility is still part of the tokens of the lines of the file.
    lines = [
        tokens for tokens in results.line_chunk.tokens.values()
        if 'pub' in tokens
    ]
    self.assertNotEmpty(lines)

  def test_the_function_modifiers_are_part_of_the_tokens(self):
    results = self._parse()
    chunk = self._chunk(results, 'outer')
    self.assertIn('unsafe', chunk.tokens)

  def test_a_test_function_is_not_a_chunk(self):
    code = """
      #[test]
      fn a_test() {}

      fn a_real_function() {}
    """
    testfile = self.create_tempfile('testfile.rs', content=code)
    results = rust_parser.RustParser(testfile.full_path).get_chunks()
    names = [chunk.name for chunk in results.function_chunks]
    self.assertNotIn('a_test', names)
    self.assertIn('a_real_function', names)

  def test_a_function_of_a_cfg_test_module_is_not_a_chunk(self):
    code = """
      #[cfg(test)]
      mod tests {
        fn a_helper() {}

        #[test]
        fn a_test() {}
      }

      fn a_real_function() {}
    """
    testfile = self.create_tempfile('testfile.rs', content=code)
    results = rust_parser.RustParser(testfile.full_path).get_chunks()
    names = [chunk.name for chunk in results.function_chunks]
    self.assertNotIn('a_helper', names)
    self.assertNotIn('a_test', names)
    self.assertIn('a_real_function', names)

  def test_the_tokens_of_the_lines_of_a_file(self):
    results = self._parse()
    lines = [
        tokens for tokens in results.line_chunk.tokens.values()
        if 'outer' in tokens
    ]
    self.assertNotEmpty(lines)
    self.assertIn('fn', lines[0])

  def test_a_macro_definition_is_not_a_chunk(self):
    code = """
      macro_rules! my_macro {
        () => {};
      }

      fn a_real_function() {}
    """
    testfile = self.create_tempfile('testfile.rs', content=code)
    results = rust_parser.RustParser(testfile.full_path).get_chunks()
    names = [chunk.name for chunk in results.function_chunks]
    self.assertNotIn('my_macro', names)
    self.assertIn('a_real_function', names)

  def test_the_normalizer_keeps_the_mutability_of_a_reference(self):
    chunk = common.FunctionChunkBase(
        name='f',
        return_types=[],
        parameters=[],
        used_data_types=[],
        local_variables=[],
        called_functions=[],
        tokens=[
            'f', '(', ')', '{', 'x', '.', 'borrow', '(', '&', 'mut', 'T', ')',
            ';', '}',
        ],
        protected_keywords=frozenset({'mut'}),
    )
    normalized = normalizer.normalize_function_chunk(chunk)
    self.assertIn('mut', normalized)

  def test_the_normalizer_keeps_the_mutability_of_a_local(self):
    chunk = common.FunctionChunkBase(
        name='f',
        return_types=[],
        parameters=[],
        used_data_types=[],
        local_variables=['x'],
        called_functions=[],
        tokens=['f', '(', ')', '{', 'let', 'mut', 'x', ';', '}'],
        protected_keywords=frozenset({'mut'}),
    )
    normalized = normalizer.normalize_function_chunk(chunk)
    self.assertIn('mut', normalized)

  def _parse(self):
    results = rust_parser.RustParser(self.testfile.full_path).get_chunks()
    self.assertEmpty(results.parse_errors)
    return results

  def _chunk(self, results, name):
    for chunk in results.function_chunks:
      if chunk.name == name:
        return chunk
    self.fail(f'No chunk named {name} was found.')


if __name__ == '__main__':
  absltest.main()
