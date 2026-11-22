# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for the Vanir Kotlin parser."""

from unittest import mock

from absl import logging
from vanir import normalizer
from vanir.language_parsers import abstract_language_parser
from vanir.language_parsers import common
from vanir.language_parsers.cpp import cpp_parser
from vanir.language_parsers.kotlin import kotlin_parser

from absl.testing import absltest


class KotlinParserTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.testcode = """
        /* This code is for testing the Vanir Kotlin parser.
          It is taken from SystemUI's ControlAdapter.kt. */
        package com.android.systemui.controls.management

        import android.view.View

        class ControlAdapter(private val context: Context) : RecyclerView.Adapter<Holder>() {
            private var mControls: List<Control> = emptyList()

            val size: Int
                get() = mControls.size

            var title: String = ""
                set(value) {
                    field = value
                }

            constructor(context: Context, controls: List<Control>) : this(context) {
                mControls = controls
            }

            init {
                Log.d(TAG, "ControlAdapter created")
            }

            fun bind(control: Control?) {
                val name: String? = control?.name
                if (name != null) {
                    title = name
                }
            }

            fun helper(): Int {
                fun local(): Int = 42
                return local()
            }

            fun onClick(view: View) {
                view.setOnClickListener { onClick(view) }
            }
        }
    """
    self.testfile = self.create_tempfile('testfile.kt', content=self.testcode)
    self.expected_tokens = {
        4: ['package', 'com', '.', 'android', '.', 'systemui', '.', 'controls',
            '.', 'management'],
        6: ['import', 'android', '.', 'view', '.', 'View'],
        8: ['class', 'ControlAdapter', '(', 'private', 'val', 'context', ':',
            'Context', ')', ':', 'RecyclerView', '.', 'Adapter', '<', 'Holder',
            '>', '(', ')', '{'],
        9: ['private', 'var', 'mControls', ':', 'List', '<', 'Control', '>',
            '=', 'emptyList', '(', ')'],
        11: ['val', 'size', ':', 'Int'],
        12: ['get', '(', ')', '=', 'mControls', '.', 'size'],
        14: ['var', 'title', ':', 'String', '=', '""'],
        15: ['set', '(', 'value', ')', '{'],
        16: ['field', '=', 'value'],
        17: ['}'],
        19: ['constructor', '(', 'context', ':', 'Context', ',', 'controls',
             ':', 'List', '<', 'Control', '>', ')', ':', 'this', '(', 'context',
             ')', '{'],
        20: ['mControls', '=', 'controls'],
        21: ['}'],
        23: ['init', '{'],
        24: ['Log', '.', 'd', '(', 'TAG', ',', '"ControlAdapter created"',
             ')'],
        25: ['}'],
        27: ['fun', 'bind', '(', 'control', ':', 'Control', '?', ')', '{'],
        28: ['val', 'name', ':', 'String', '?', '=', 'control', '?.', 'name'],
        29: ['if', '(', 'name', '!=', 'null', ')', '{'],
        30: ['title', '=', 'name'],
        31: ['}'],
        32: ['}'],
        34: ['fun', 'helper', '(', ')', ':', 'Int', '{'],
        35: ['fun', 'local', '(', ')', ':', 'Int', '=', '42'],
        36: ['return', 'local', '(', ')'],
        37: ['}'],
        39: ['fun', 'onClick', '(', 'view', ':', 'View', ')', '{'],
        40: ['view', '.', 'setOnClickListener', '{', 'onClick', '(', 'view',
             ')', '}'],
        41: ['}'],
        42: ['}'],
    }
    self.all_function_chunks = {
        'size.get': common.FunctionChunkBase(
            name='size.get',
            return_types=[],
            parameters=[],
            used_data_types=[],
            local_variables=[],
            called_functions=[],
            tokens=['get', '(', ')', '=', 'mControls', '.', 'size'],
            protected_keywords=frozenset({'?'})),
        'title.set': common.FunctionChunkBase(
            name='title.set',
            return_types=[],
            parameters=[],
            used_data_types=[],
            local_variables=[],
            called_functions=[],
            tokens=['set', '(', 'value', ')', '{', 'field', '=', 'value', '}'],
            protected_keywords=frozenset({'?'})),
        'ControlAdapter': common.FunctionChunkBase(
            name='ControlAdapter',
            return_types=[],
            parameters=['context', 'controls'],
            used_data_types=[['Context'], ['List', '<', 'Control', '>']],
            local_variables=[],
            called_functions=[],
            tokens=[
                'constructor', '(', 'context', ':', 'Context', ',', 'controls',
                ':', 'List', '<', 'Control', '>', ')', ':', 'this', '(',
                'context', ')', '{', 'mControls', '=', 'controls', '}'],
            protected_keywords=frozenset({'?'})),
        'ControlAdapter.init': common.FunctionChunkBase(
            name='ControlAdapter.init',
            return_types=[],
            parameters=[],
            used_data_types=[],
            local_variables=[],
            called_functions=['d'],
            tokens=[
                'init', '{', 'Log', '.', 'd', '(', 'TAG', ',',
                '"ControlAdapter created"', ')', '}'],
            protected_keywords=frozenset({'?'})),
        'bind': common.FunctionChunkBase(
            name='bind',
            return_types=[],
            parameters=['control'],
            used_data_types=[['Control', '?'], ['String', '?']],
            local_variables=['name'],
            called_functions=[],
            tokens=[
                'fun', 'bind', '(', 'control', ':', 'Control', '?', ')', '{',
                'val', 'name', ':', 'String', '?', '=', 'control', '?.', 'name',
                'if', '(', 'name', '!=', 'null', ')', '{', 'title', '=', 'name',
                '}', '}'],
            protected_keywords=frozenset({'?'})),
        'helper': common.FunctionChunkBase(
            name='helper',
            return_types=[['Int']],
            parameters=[],
            used_data_types=[['Int']],
            local_variables=[],
            called_functions=['local'],
            tokens=[
                'fun', 'helper', '(', ')', ':', 'Int', '{', 'fun', 'local', '(',
                ')', ':', 'Int', '=', '42', 'return', 'local', '(', ')', '}'],
            protected_keywords=frozenset({'?'})),
        'local': common.FunctionChunkBase(
            name='local',
            return_types=[['Int']],
            parameters=[],
            used_data_types=[['Int']],
            local_variables=[],
            called_functions=[],
            tokens=['fun', 'local', '(', ')', ':', 'Int', '=', '42'],
            protected_keywords=frozenset({'?'})),
        'onClick': common.FunctionChunkBase(
            name='onClick',
            return_types=[],
            parameters=['view'],
            used_data_types=[['View']],
            local_variables=[],
            called_functions=['setOnClickListener', 'onClick'],
            tokens=[
                'fun', 'onClick', '(', 'view', ':', 'View', ')', '{', 'view',
                '.', 'setOnClickListener', '{', 'onClick', '(', 'view', ')',
                '}', '}'],
            protected_keywords=frozenset({'?'})),
    }

  def test_supported_file_types(self):
    self.assertEqual(
        list(kotlin_parser.KotlinParser.get_supported_extensions()),
        ['.kt'],
        'Claimed supported extensions do not match.')
    self.assertNotIn(
        '.kts',
        kotlin_parser.KotlinParser.get_supported_extensions(),
        'The build scripts of Kotlin are not shipped code.')

  def test_the_language_id(self):
    self.assertEqual(kotlin_parser.KotlinParser.get_language_id(), 'kotlin')

  def test_the_protected_keywords_of_the_language(self):
    self.assertEqual(
        kotlin_parser.KotlinParser.PROTECTED_KEYWORDS, frozenset({'?'}))

  def test_is_test_file(self):
    test_files = [
        'framework/base/tests/foo/BarTest.kt',
        'tests/BarTest.kt',
        'multivalentTests/foo/BarTests.kt',
        'androidTest/foo/BarTestCase.kt',
        'src/test/java/foo/BarTest.kt',
        'src/androidTest/foo/BarTestBase.kt',
        'testing/foo/BarTest.kt',
    ]
    for path in test_files:
      self.assertTrue(
          kotlin_parser.KotlinParser.is_test_file(path),
          f'{path} should be recognized as a Kotlin test file.')

  def test_is_not_test_file(self):
    not_test_files = [
        'framework/base/core/foo/Bar.kt',
        'src/main/foo/BarTest.kt',
        'src/testsuite/foo/BarTest.kt',
        'tests/foo/Bar.kt',
        'foo/BarTest.kt',
        'foo/BarTest.kt.bak',
    ]
    for path in not_test_files:
      self.assertFalse(
          kotlin_parser.KotlinParser.is_test_file(path),
          f'{path} should not be recognized as a Kotlin test file.')

  def test_nonexistent_file_failure(self):
    filename = 'NonExistingFile.kt'
    with self.assertRaisesRegex(common.LanguageParserError,
                                'Failed to open file'):
      _ = kotlin_parser.KotlinParser(filename).get_chunks()

  def test_parsing_no_line_limit(self):
    results = kotlin_parser.KotlinParser(
        self.testfile.full_path).get_chunks()
    self.assertEmpty(results.parse_errors)
    self.assertDictEqual(results.line_chunk.tokens, self.expected_tokens,
                         'line chunk tokens do not match.')
    self.assertSequenceEqual(
        results.function_chunks,
        list(self.all_function_chunks.values()),
        'function chunks do not match.')

  def test_parsing_with_line_limit(self):
    results = kotlin_parser.KotlinParser(
        self.testfile.full_path).get_chunks(
            affected_line_ranges_for_functions=[[19, 25], [39, 39]])
    self.assertEmpty(results.parse_errors)
    self.assertDictEqual(results.line_chunk.tokens, self.expected_tokens,
                         'line chunk tokens do not match.')
    self.assertSequenceEqual(
        results.function_chunks,
        [
            self.all_function_chunks['ControlAdapter'],
            self.all_function_chunks['ControlAdapter.init'],
            self.all_function_chunks['onClick'],
        ],
        'function chunks do not match.')

  def test_parsing_with_parser_syntax_error(self):
    error_code = """
        package com.google.test

        class MyClass {
            fun func() {
                val x =
            }
        }
    """
    error_testfile = self.create_tempfile(
        'error_testfile.kt', content=error_code)
    results = kotlin_parser.KotlinParser(
        error_testfile.full_path).get_chunks()
    self.assertNotEmpty(results.parse_errors)
    self.assertEqual(results.parse_errors[0].line, 6)
    self.assertStartsWith(results.parse_errors[0].message, 'KotlinParser: ')
    # The parser continues after the error, so the function is still found.
    self.assertLen(results.function_chunks, 1)
    self.assertEqual(results.function_chunks[0].name, 'func')

  def test_kotlin_parser_with_non_utf8_file(self):
    latin1_str = '  // \xE0'
    testfile = self.create_tempfile(
        'testfile_latein1.kt',
        content=self.testcode + latin1_str,
        encoding='LATIN-1',
    )
    with self.assertLogs(level=logging.INFO) as logs:
      parser = kotlin_parser.KotlinParser(testfile.full_path)
      results = parser.get_chunks()
      self.assertEmpty(results.parse_errors)
    self.assertRegex(logs.output[0], r'Converting.*to UTF-8.')

  def test_kotlin_parser_with_known_encoding_file(self):
    latin1_str = '  // \xE0'
    testfile = self.create_tempfile(
        'testfile_latein1.kt',
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
        kotlin_parser.KotlinParser(testfile.full_path).get_chunks()

  def test_constructor_takes_the_name_of_the_class(self):
    code = """
        class Adapter {
            constructor(context: Context) : this(context, null) {
            }
        }
    """
    testfile = self.create_tempfile('constructor.kt', content=code)
    results = kotlin_parser.KotlinParser(testfile.full_path).get_chunks()
    self.assertLen(results.function_chunks, 1)
    self.assertEqual(results.function_chunks[0].name, 'Adapter')
    self.assertEqual(results.function_chunks[0].parameters, ['context'])

  def test_accessor_names(self):
    code = """
        class Adapter {
            val size: Int
                get() = 0
            var title: String = ""
                set(value) {
                    field = value
                }
        }
    """
    testfile = self.create_tempfile('accessors.kt', content=code)
    results = kotlin_parser.KotlinParser(testfile.full_path).get_chunks()
    self.assertEqual(
        [chunk.name for chunk in results.function_chunks],
        ['size.get', 'title.set'])

  def test_init_block_name(self):
    code = """
        class Adapter {
            init {
                Log.d(TAG, "created")
            }
        }
    """
    testfile = self.create_tempfile('init.kt', content=code)
    results = kotlin_parser.KotlinParser(testfile.full_path).get_chunks()
    self.assertLen(results.function_chunks, 1)
    self.assertEqual(results.function_chunks[0].name, 'Adapter.init')

  def test_local_function_becomes_a_chunk(self):
    code = """
        fun helper(): Int {
            fun local(): Int = 42
            return local()
        }
    """
    testfile = self.create_tempfile('local_function.kt', content=code)
    results = kotlin_parser.KotlinParser(testfile.full_path).get_chunks()
    self.assertEqual(
        [chunk.name for chunk in results.function_chunks], ['helper', 'local'])
    # The body of the local function belongs to its own chunk.
    self.assertEqual(results.function_chunks[0].called_functions, ['local'])
    self.assertEmpty(results.function_chunks[1].called_functions)

  def test_lambda_stays_inside_its_parent(self):
    code = """
        fun onClick(view: View) {
            view.setOnClickListener { onClick(view) }
        }
    """
    testfile = self.create_tempfile('lambda.kt', content=code)
    results = kotlin_parser.KotlinParser(testfile.full_path).get_chunks()
    self.assertLen(results.function_chunks, 1)
    self.assertEqual(results.function_chunks[0].name, 'onClick')
    self.assertEqual(
        results.function_chunks[0].called_functions,
        ['setOnClickListener', 'onClick'])

  def test_anonymous_function_stays_inside_its_parent(self):
    code = """
        fun helper() {
            val f = fun(x: Int): Int { return x }
            f(1)
        }
    """
    testfile = self.create_tempfile('anonymous_function.kt', content=code)
    results = kotlin_parser.KotlinParser(testfile.full_path).get_chunks()
    self.assertLen(results.function_chunks, 1)
    self.assertEqual(results.function_chunks[0].name, 'helper')
    self.assertEqual(results.function_chunks[0].called_functions, ['f'])
    self.assertIn('x', results.function_chunks[0].parameters)

  def test_call_of_a_navigation_expression_is_its_last_segment(self):
    code = """
        fun helper(view: View) {
            view.setOnClickListener { onClick(view) }
            a.b.c()
        }
    """
    testfile = self.create_tempfile('calls.kt', content=code)
    results = kotlin_parser.KotlinParser(testfile.full_path).get_chunks()
    self.assertLen(results.function_chunks, 1)
    self.assertEqual(
        results.function_chunks[0].called_functions,
        ['setOnClickListener', 'onClick', 'c'])

  def test_for_loop_variables_are_local_variables(self):
    code = """
        fun helper(list: List<String>) {
            for (item in list) {
                println(item)
            }
            for ((key, value) in map) {
                println(key)
            }
        }
    """
    testfile = self.create_tempfile('for_loop.kt', content=code)
    results = kotlin_parser.KotlinParser(testfile.full_path).get_chunks()
    self.assertLen(results.function_chunks, 1)
    self.assertEqual(
        results.function_chunks[0].local_variables, ['item', 'key', 'value'])

  def test_catch_parameters_are_parameters(self):
    code = """
        fun helper() {
            try {
                risky()
            } catch (exception: IllegalStateException) {
                println(exception)
            }
        }
    """
    testfile = self.create_tempfile('catch.kt', content=code)
    results = kotlin_parser.KotlinParser(testfile.full_path).get_chunks()
    self.assertLen(results.function_chunks, 1)
    self.assertEqual(results.function_chunks[0].parameters, ['exception'])
    self.assertEqual(results.function_chunks[0].called_functions, ['risky',
                                                                   'println'])

  def test_lambda_parameters_are_parameters(self):
    code = """
        fun helper(list: List<String>) {
            list.forEach { item -> println(item) }
        }
    """
    testfile = self.create_tempfile('lambda_parameters.kt', content=code)
    results = kotlin_parser.KotlinParser(testfile.full_path).get_chunks()
    self.assertLen(results.function_chunks, 1)
    self.assertEqual(results.function_chunks[0].parameters, ['list', 'item'])

  def test_modifiers_are_not_part_of_the_function_tokens(self):
    code = """
        class Adapter {
            @Deprecated("use other")
            private fun helper(): Int = 0
        }
    """
    testfile = self.create_tempfile('modifiers.kt', content=code)
    results = kotlin_parser.KotlinParser(testfile.full_path).get_chunks()
    self.assertLen(results.function_chunks, 1)
    self.assertEqual(
        results.function_chunks[0].tokens,
        ['fun', 'helper', '(', ')', ':', 'Int', '=', '0'])
    # The tokens of the lines of the file still hold the annotation.
    self.assertEqual(
        results.line_chunk.tokens[3],
        ['@', 'Deprecated', '(', '"use other"', ')'])
    self.assertEqual(
        results.line_chunk.tokens[4],
        ['private', 'fun', 'helper', '(', ')', ':', 'Int', '=', '0'])

  def test_comments_are_skipped_and_literals_are_kept_whole(self):
    code = """
        fun helper() {
            // a line comment
            /* a block comment */
            val text = "a string"
            val multi = \"\"\"
                a multi line string
            \"\"\"
            val character = 'a'
        }
    """
    testfile = self.create_tempfile('comments.kt', content=code)
    results = kotlin_parser.KotlinParser(testfile.full_path).get_chunks()
    self.assertLen(results.function_chunks, 1)
    tokens = results.function_chunks[0].tokens
    self.assertNotIn('a line comment', tokens)
    self.assertNotIn('a block comment', tokens)
    self.assertIn('"a string"', tokens)
    self.assertIn("'a'", tokens)
    self.assertTrue(
        any(token.startswith('"""') for token in tokens),
        f'The multi line string literal is not kept whole: {tokens}')

  def test_the_chunks_carry_the_protected_keywords(self):
    results = kotlin_parser.KotlinParser(
        self.testfile.full_path).get_chunks()
    for chunk in results.function_chunks:
      self.assertEqual(chunk.protected_keywords, frozenset({'?'}))

  def test_nullable_type_survives_the_normalization(self):
    code = """
        fun nullable(name: String?): String? {
            return name
        }

        fun plain(name: String): String {
            return name
        }
    """
    testfile = self.create_tempfile('nullable.kt', content=code)
    results = kotlin_parser.KotlinParser(testfile.full_path).get_chunks()
    normalized = {
        chunk.name: normalizer.normalize_function_chunk(chunk)
        for chunk in results.function_chunks
    }
    self.assertEqual(
        normalized['nullable'],
        'fun FUNCNAME ( PARAM : ? DTYPE ) : ? DTYPE { return PARAM }')
    self.assertEqual(
        normalized['plain'],
        'fun FUNCNAME ( PARAM : DTYPE ) : DTYPE { return PARAM }')
    self.assertNotEqual(normalized['nullable'], normalized['plain'])

  def test_the_default_protected_keywords_are_unchanged(self):
    """The languages that do not opt in keep the keywords of today."""
    code = (
        'int get_size(const char *name) {\n'
        '  return name[0];\n'
        '}\n'
    )
    testfile = self.create_tempfile('default.c', content=code)
    results = cpp_parser.CppParser(testfile.full_path).get_chunks()
    normalized = [
        normalizer.normalize_function_chunk(chunk)
        for chunk in results.function_chunks
    ]
    self.assertTrue(normalized)
    for normalized_code in normalized:
      self.assertIn('const', normalized_code)


if __name__ == '__main__':
  absltest.main()
