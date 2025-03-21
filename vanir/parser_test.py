# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for parser."""

from vanir import parser

from absl.testing import absltest
from pybind11_abseil import status


class ParserTest(absltest.TestCase):

  def test_parser(self):
    testcode = """
      /* This code is for testing Vanir Parser. */ int test_globalvar = 10;
      int test_func1(const unsigned int64 test_arg) {
        const struct teststruct *testvar = (struct teststruct *)globalvar->data;
        test_func2(test_arg, testvar);  // some comment.
        /* additional comment line. */
        0xe8();  // broken code -- won't be counted as func call.
        return 0;
      }
      int test_func_decl(int myarg);
      """
    testfile = self.create_tempfile('testfile.c', content=testcode)
    filename = testfile.full_path
    test_target_file = 'foo/bar/testfile.c'
    test_parser = parser.Parser(filename, test_target_file)
    function_chunks = test_parser.get_function_chunks()
    line_chunk = test_parser.get_line_chunk()

    self.assertLen(function_chunks, 1)
    self.assertEqual(function_chunks[0].base.name, 'test_func1')
    self.assertEqual(function_chunks[0].base.parameters, ['test_arg'])
    self.assertCountEqual(
        function_chunks[0].base.used_data_types,
        [['const', 'unsigned', 'int64'], ['const', 'struct', 'teststruct'],
         ['struct', 'teststruct']])
    self.assertEqual(function_chunks[0].base.local_variables, ['testvar'])
    self.assertEqual(function_chunks[0].base.called_functions, ['test_func2'])
    self.assertEqual(function_chunks[0].target_file, test_target_file)
    self.assertIsNotNone(function_chunks[0].normalized_code)
    self.assertIsNotNone(function_chunks[0].function_hash)

    expected_tokens = {
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
        10: ['int', 'test_func_decl', '(', 'int', 'myarg', ')', ';']
    }
    self.assertEqual(line_chunk.base.tokens, expected_tokens)
    self.assertEqual(line_chunk.target_file, test_target_file)
    self.assertIsNotNone(line_chunk.normalized_code)
    self.assertIsNotNone(line_chunk.line_hashes)
    self.assertIsNotNone(line_chunk.used_lines)

  def test_parser_with_affected_ranges(self):
    testcode = r"""
      int unaffected_function1(void) { printk("ok"); }
      void affected_function1(void) {
        printk("this line is vulnerable. %s", sensitive_info);
      }
      int unaffected_function2(void) { printk("this is fine."); }
      void affected_function2(void) {
        printk("this line is also vulnerable. %s", sensitive_info);
      }
      int unaffected_function3(void) { printk("this is fine, too."); }
      void affected_function3(void) {
        printk("this line is also vulnerable. %s", sensitive_info);
      }
      int unaffected_function4(void) { printk("this is fine, too."); }
      """
    affected_ranges = [(4, 4), (7, 7), (13, 13)]
    testfile = self.create_tempfile('testfile.c', content=testcode)
    filename = testfile.full_path
    test_target_file = 'foo/bar/testfile.c'
    test_parser = parser.Parser(filename, test_target_file, affected_ranges)
    function_chunks = test_parser.get_function_chunks()
    line_chunk = test_parser.get_line_chunk()

    self.assertLen(function_chunks, 3)
    self.assertEqual(function_chunks[0].base.name, 'affected_function1')
    self.assertEqual(function_chunks[1].base.name, 'affected_function2')
    self.assertEqual(function_chunks[2].base.name, 'affected_function3')

    expected_tokens = {
        2: [
            'int', 'unaffected_function1', '(', 'void', ')', '{', 'printk', '(',
            '"ok"', ')', ';', '}'
        ],
        3: ['void', 'affected_function1', '(', 'void', ')', '{'],
        4: [
            'printk', '(', '"this line is vulnerable. %s"', ',',
            'sensitive_info', ')', ';'
        ],
        5: ['}'],
        6: [
            'int', 'unaffected_function2', '(', 'void', ')', '{', 'printk', '(',
            '"this is fine."', ')', ';', '}'
        ],
        7: ['void', 'affected_function2', '(', 'void', ')', '{'],
        8: [
            'printk', '(', '"this line is also vulnerable. %s"', ',',
            'sensitive_info', ')', ';'
        ],
        9: ['}'],
        10: [
            'int', 'unaffected_function3', '(', 'void', ')', '{', 'printk', '(',
            '"this is fine, too."', ')', ';', '}'
        ],
        11: ['void', 'affected_function3', '(', 'void', ')', '{'],
        12: [
            'printk', '(', '"this line is also vulnerable. %s"', ',',
            'sensitive_info', ')', ';'
        ],
        13: ['}'],
        14: [
            'int', 'unaffected_function4', '(', 'void', ')', '{', 'printk', '(',
            '"this is fine, too."', ')', ';', '}'
        ]
    }
    self.assertEqual(line_chunk.base.tokens, expected_tokens)
    self.assertEqual(line_chunk.target_file, test_target_file)
    self.assertIsNotNone(line_chunk.normalized_code)
    self.assertIsNotNone(line_chunk.line_hashes)
    self.assertIsNotNone(line_chunk.used_lines)

  def test_parser_with_init_failure(self):
    filename = 'NonExistingFile.c'
    test_target_file = 'foo/bar/testfile.c'
    with self.assertRaisesRegex(status.StatusNotOk, 'Failed to open file:.*'):
      parser.Parser(filename, test_target_file)


if __name__ == '__main__':
  absltest.main()
