# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for Vanir Java parser."""

from vanir.language_parsers import common
from vanir.language_parsers.java import java_parser
from absl.testing import absltest
from pybind11_abseil import status


class JavaParserTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    testcode = """
        /* This code is for testing Vanir parser.
          It is taken from frameworks/base's AudioPolicy.java. */
        package android.media.audiopolicy;
        import android.annotation.IntDef;

        public class AudioPolicy {
            private int mStatus;
            private AudioPolicy(AudioPolicyConfig config, Context ctx) {
                super(config);
                mConfig = config; // end of line comment
                Object looper = Looper.getMainLooper();
                new EventHandler(this, looper).show();
            }
            public AudioPolicy builder() {
                // line-level comment
                ArrayList<AudioMix> mMixes;
                mMixes = new ArrayList<AudioMix>();
                return makeAudioPolicy(mMixes);
            }

            public static class Config {
                public void topMethod(String... args) { return; }
                private int bottomMethod() { var x = y;}
            }
        }
    """
    self.testfile = self.create_tempfile('testfile.java', content=testcode)
    self.expected_tokens = {
        4: ['package', 'android', '.', 'media', '.', 'audiopolicy', ';'],
        5: ['import', 'android', '.', 'annotation', '.', 'IntDef', ';'],
        7: ['public', 'class', 'AudioPolicy', '{'],
        8: ['private', 'int', 'mStatus', ';'],
        9: ['private', 'AudioPolicy', '(', 'AudioPolicyConfig', 'config', ',',
            'Context', 'ctx', ')', '{'],
        10: ['super', '(', 'config', ')', ';'],
        11: ['mConfig', '=', 'config', ';'],
        12: ['Object', 'looper', '=', 'Looper', '.', 'getMainLooper', '(', ')',
             ';'],
        13: ['new', 'EventHandler', '(', 'this', ',', 'looper', ')', '.',
             'show', '(', ')', ';'],
        14: ['}'],
        15: ['public', 'AudioPolicy', 'builder', '(', ')', '{'],
        17: ['ArrayList', '<', 'AudioMix', '>', 'mMixes', ';'],
        18: ['mMixes', '=', 'new', 'ArrayList', '<', 'AudioMix', '>', '(', ')',
             ';'],
        19: ['return', 'makeAudioPolicy', '(', 'mMixes', ')', ';'],
        20: ['}'],
        22: ['public', 'static', 'class', 'Config', '{'],
        23: ['public', 'void', 'topMethod', '(', 'String', '...', 'args', ')',
             '{', 'return', ';', '}'],
        24: ['private', 'int', 'bottomMethod', '(', ')', '{', 'var', 'x', '=',
             'y', ';', '}'],
        25: ['}'],
        26: ['}']}
    self.all_function_chunks = {
        'AudioPolicy': common.FunctionChunkBase(
            name='AudioPolicy',
            return_types=[[]],
            parameters=['config', 'ctx'],
            used_data_types=[['AudioPolicyConfig'], ['Context'], ['Object']],
            local_variables=['looper'],
            called_functions=['getMainLooper', 'EventHandler', 'show'],
            tokens=[
                'AudioPolicy', '(', 'AudioPolicyConfig', 'config', ',',
                'Context', 'ctx', ')', '{', 'super', '(', 'config', ')', ';',
                'mConfig', '=', 'config', ';', 'Object', 'looper', '=',
                'Looper', '.', 'getMainLooper', '(', ')', ';', 'new',
                'EventHandler', '(', 'this', ',', 'looper', ')', '.', 'show',
                '(', ')', ';', '}'
            ]),
        'builder': common.FunctionChunkBase(
            name='builder',
            return_types=[['AudioPolicy']],
            parameters=[],
            used_data_types=[
                ['AudioPolicy'],
                ['ArrayList', '<', 'AudioMix', '>'],
                ['AudioMix']],
            local_variables=['mMixes'],
            called_functions=['ArrayList<AudioMix>', 'makeAudioPolicy'],
            tokens=[
                'AudioPolicy', 'builder', '(', ')', '{', 'ArrayList',
                '<', 'AudioMix', '>', 'mMixes', ';', 'mMixes', '=', 'new',
                'ArrayList', '<', 'AudioMix', '>', '(', ')', ';', 'return',
                'makeAudioPolicy', '(', 'mMixes', ')', ';', '}']),
        'topMethod': common.FunctionChunkBase(
            name='topMethod',
            return_types=[['void']],
            parameters=['args'],
            used_data_types=[['String']],
            local_variables=[],
            called_functions=[],
            tokens=[
                'void', 'topMethod', '(', 'String', '...', 'args', ')', '{',
                'return', ';', '}']),
        'bottomMethod': common.FunctionChunkBase(
            name='bottomMethod',
            return_types=[['int']],
            parameters=[],
            used_data_types=[['int']],
            local_variables=['x'],
            called_functions=[],
            tokens=['int', 'bottomMethod', '(', ')', '{', 'var', 'x', '=', 'y',
                    ';', '}'])
    }

  def test_supported_file_types(self):
    self.assertEqual(
        list(java_parser.JavaParser.get_supported_extensions()),
        ['.java'],
        'Claimed supported extensions do not match.'
    )

  def test_nonexistent_file_failure(self):
    filename = 'NonExistingFile.java'
    with self.assertRaisesRegex(status.StatusNotOk, 'Failed to open:.*'):
      _ = java_parser.JavaParser(filename).get_chunks()

  def test_parsing_no_line_limit(self):
    results = java_parser.JavaParser(
        self.testfile.full_path).get_chunks()
    self.assertEmpty(results.parse_errors)
    self.assertDictEqual(results.line_chunk.tokens, self.expected_tokens,
                         'line chunk tokens do not match.')
    self.assertSequenceEqual(
        results.function_chunks,
        list(self.all_function_chunks.values()),
        'function chunks do not match.')

  def test_parsing_with_line_limit(self):
    results = java_parser.JavaParser(
        self.testfile.full_path).get_chunks(
            affected_line_ranges_for_functions=[[7, 15], [23, 23]])
    self.assertEmpty(results.parse_errors)
    self.assertDictEqual(results.line_chunk.tokens, self.expected_tokens,
                         'line chunk tokens do not match.')
    self.assertSequenceEqual(
        results.function_chunks,
        [
            self.all_function_chunks['AudioPolicy'],
            self.all_function_chunks['builder'],
            self.all_function_chunks['topMethod']
        ],
        'function chunks do not match.')

  def test_parsing_with_parser_syntax_error(self):
    error_code = """
        package com.google.test;
        public class MyClass {
            void func() {
                0xe8(); // should throw an error but continue on
                int var;
            }
        }
    """
    error_testfile = self.create_tempfile(
        'error_testfile.java', content=error_code)
    expected_tokens_with_errors = {
        2: ['package', 'com', '.', 'google', '.', 'test', ';'],
        3: ['public', 'class', 'MyClass', '{'],
        4: ['void', 'func', '(', ')', '{'],
        5: ['0xe8', '(', ')', ';',],
        6: ['int', 'var', ';'],
        7: ['}'],
        8: ['}'],
    }
    expected_function_chunks_with_errors = [
        common.FunctionChunkBase(
            name='func',
            return_types=[['void']],
            parameters=[],
            used_data_types=[['int']],
            local_variables=['var'],
            called_functions=[],
            tokens=['void', 'func', '(', ')', '{', '0xe8', '(', ')', ';', 'int',
                    'var', ';', '}']),
    ]
    expected_parse_errors = [
        common.ParseError(
            line=5, column=20, bad_token='(',
            message=("JavaParser: missing ';' at '('")),
        common.ParseError(
            line=5, column=22, bad_token=';',
            message=("JavaParser: mismatched input ';' expecting '->'"))
    ]

    results = java_parser.JavaParser(error_testfile.full_path).get_chunks()
    self.assertSequenceEqual(
        results.parse_errors, expected_parse_errors, 'errors do not match')
    self.assertDictEqual(
        results.line_chunk.tokens,
        expected_tokens_with_errors,
        'line chunk tokens do not match.')
    self.assertSequenceEqual(
        results.function_chunks,
        expected_function_chunks_with_errors,
        'function chunks do not match.')

  def test_parsing_with_lexer_syntax_error(self):
    error_code = """
        package com.google.test;
        #bad_comment
        public class MyClass {
        }
    """
    error_testfile = self.create_tempfile(
        'error_testfile.java', content=error_code)
    expected_parse_error = common.ParseError(
        line=3, column=8, bad_token='',
        message=("JavaLexer: token recognition error at: '#'")
    )
    results = java_parser.JavaParser(error_testfile.full_path).get_chunks()
    self.assertIn(expected_parse_error, results.parse_errors)

if __name__ == '__main__':
  absltest.main()
