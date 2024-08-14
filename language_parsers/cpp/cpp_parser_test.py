# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for parser_core Pybind wrapped by cpp_parser."""

from unittest import mock

from absl import logging
from vanir.language_parsers.cpp import cpp_parser

from absl.testing import absltest
from pybind11_abseil import status


class ParserCoreTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.testcode = """
      /* This code is for testing Vanir Parser. */ int test_globalvar = 10;
      int test_func1(const unsigned int64 test_arg) {
        const struct teststruct *testvar = (struct teststruct *)globalvar->data;
        test_func2(test_arg, testvar);  // some comment.
        /* additional comment line. */
        0xe8();  // broken code -- won't be counted as func call.
        return 0;
      }
      void test_func_decl(int myarg);
      void test_func_def(int myarg) {}
      """
    testfile = self.create_tempfile('testfile.c', content=self.testcode)
    self.test_filename = testfile.full_path
    self.expected_tokens = {
        2: ['int', 'test_globalvar', '=', '10', ';'],
        3: [
            'int', 'test_func1', '(', 'const', 'unsigned', 'int64', 'test_arg',
            ')', '{'
        ],
        4: [
            'const', 'struct', 'teststruct', '*', 'testvar', '=', '(', 'struct',
            'teststruct', '*', ')', 'globalvar', '->', 'data', ';'
        ],
        5: ['test_func2', '(', 'test_arg', ',', 'testvar', ')', ';'],
        7: ['0xe8', '(', ')', ';'],
        8: ['return', '0', ';'],
        9: ['}'],
        10: ['void', 'test_func_decl', '(', 'int', 'myarg', ')', ';'],
        11: ['void', 'test_func_def', '(', 'int', 'myarg', ')', '{', '}']
    }

  def test_cpp_parser_with_line_limits(self):
    parser = cpp_parser.CppParser(self.test_filename)

    results = parser.get_chunks([(5, 7)])
    self.assertEmpty(results.parse_errors)
    self.assertLen(results.function_chunks, 1)
    self.assertEqual(results.function_chunks[0].name, 'test_func1')
    self.assertEqual(results.function_chunks[0].return_types, [['int']])
    self.assertEqual(results.function_chunks[0].parameters, ['test_arg'])
    self.assertEqual(
        results.function_chunks[0].used_data_types,
        [['const', 'unsigned', 'int64'], ['const', 'struct', 'teststruct'],
         ['struct', 'teststruct']])
    self.assertEqual(results.function_chunks[0].local_variables, ['testvar'])
    self.assertEqual(
        results.function_chunks[0].called_functions, ['test_func2'])

    self.assertEqual(results.line_chunk.tokens, self.expected_tokens)

  def test_cpp_parser_without_line_limits(self):
    parser = cpp_parser.CppParser(self.test_filename)

    results = parser.get_chunks()
    self.assertEmpty(results.parse_errors)
    self.assertLen(results.function_chunks, 2)
    self.assertEqual(results.function_chunks[0].name, 'test_func1')
    self.assertEqual(results.function_chunks[0].parameters, ['test_arg'])
    self.assertEqual(
        results.function_chunks[0].used_data_types,
        [['const', 'unsigned', 'int64'], ['const', 'struct', 'teststruct'],
         ['struct', 'teststruct']])
    self.assertEqual(results.function_chunks[0].local_variables, ['testvar'])
    self.assertEqual(
        results.function_chunks[0].called_functions, ['test_func2'])
    self.assertEqual(results.function_chunks[1].name, 'test_func_def')
    self.assertEqual(results.function_chunks[1].return_types, [['void']])
    self.assertEqual(results.function_chunks[1].parameters, ['myarg'])

    self.assertEqual(results.line_chunk.tokens, self.expected_tokens)

  def test_cpp_parser_with_nonexistent_file_failure(self):
    filename = 'NonExistingFile.c'
    with self.assertRaisesRegex(status.StatusNotOk, 'Failed to open file:.*'):
      _ = cpp_parser.CppParser(filename)

  def test_cpp_parser_with_non_utf8_file(self):
    latin1_str = '  // \xE0'
    testfile = self.create_tempfile(
        'testfile_latein1.c',
        content=self.testcode + latin1_str,
        encoding='LATIN-1',
    )
    with self.assertLogs(level=logging.INFO) as logs:
      parser = cpp_parser.CppParser(testfile.full_path)
      results = parser.get_chunks([(5, 7)])
      self.assertEmpty(results.parse_errors)
      self.assertLen(results.function_chunks, 1)
    self.assertIn(
        'is not encoded in UTF-8. Trying altneratives.', logs.output[0]
    )

  def test_cpp_parser_with_known_encoding_file(self):
    latin1_str = '  // \xE0'
    testfile = self.create_tempfile(
        'testfile_latein1.c',
        content=self.testcode + latin1_str,
        encoding='LATIN-1',
    )
    # Delete latin-1 from the alternative encoding.
    with mock.patch.object(cpp_parser, '_ALTNERNATIVE_ENCODINGS', []):
      with self.assertRaisesRegex(ValueError, 'Failed to deocde'):
        cpp_parser.CppParser(testfile.full_path)


if __name__ == '__main__':
  absltest.main()
