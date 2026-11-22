# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

from vanir.language_parsers import language_parsers
from vanir.language_parsers.cpp import cpp_parser
from vanir.language_parsers.java import java_parser
from vanir.language_parsers.kotlin import kotlin_parser
from vanir.language_parsers.python import python_parser

from absl.testing import absltest


class LanguageParsersTest(absltest.TestCase):

  def test_get_parser_class(self) -> None:
    self.assertIs(
        language_parsers.get_parser_class('x.py'), python_parser.PythonParser
    )
    self.assertIs(
        language_parsers.get_parser_class('x.cpp'), cpp_parser.CppParser
    )
    self.assertIs(
        language_parsers.get_parser_class('x.java'), java_parser.JavaParser
    )
    self.assertIs(
        language_parsers.get_parser_class('x.kt'), kotlin_parser.KotlinParser
    )
    self.assertIsNone(language_parsers.get_parser_class('x.unknown'))

  def test_get_parser_class_by_language_id(self) -> None:
    self.assertIs(
        language_parsers.get_parser_class_by_language_id('kotlin'),
        kotlin_parser.KotlinParser,
    )
    self.assertIsNone(
        language_parsers.get_parser_class_by_language_id('cobol'))

  def test_parse_unsupported_file(self) -> None:
    with self.assertRaises(NotImplementedError):
      language_parsers.parse_file('x.unknown')


if __name__ == '__main__':
  absltest.main()
