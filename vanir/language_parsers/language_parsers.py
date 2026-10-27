# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Collection of Parsers to extract function/line blocks from the code snippets.

This module is the common entry point for parsers of different languages that
Vanir supports. A Language Parser implements the AbstractLanguageParser class,
and which parser to use for a particular file will be selected automatically
by file extensions.
"""

from collections.abc import Sequence
import inspect
import os
from typing import TypeVar

from vanir.language_parsers import abstract_language_parser
from vanir.language_parsers import common

# Simply importing the parsers will register them as subclasses of the abstract
# parser class and therefore available for use.
# pylint: disable=unused-import
from vanir.language_parsers.cpp import cpp_parser
from vanir.language_parsers.java import java_parser
from vanir.language_parsers.python import python_parser

# pylint: enable=unused-import

_P = TypeVar('_P', bound=abstract_language_parser.AbstractLanguageParser)


def _get_all_subclasses(cls: type[_P]) -> Sequence[type[_P]]:
  """Recursively finds all subclasses of a given class."""
  subclasses = []
  for subclass in cls.__subclasses__():
    subclasses.append(subclass)
    subclasses.extend(_get_all_subclasses(subclass))
  return subclasses


def get_parser_class(filename: str) -> type[_P] | None:
  """Returns the language parser class that handles the given file, or None."""
  ext = os.path.splitext(filename)[1]
  for parser_class in _get_all_subclasses(
      abstract_language_parser.AbstractLanguageParser
  ):
    if inspect.isabstract(parser_class):
      continue
    if ext in parser_class.get_supported_extensions():
      return parser_class  # pyrefly: ignore[bad-return]
  return None


def parse_file(
    filename: str,
    functions_line_ranges: Sequence[tuple[int, int]] | None = None,
) -> common.ParseResults:
  """Parses the given file and extract function and line chunks.

  Args:
    filename: the absolute path to the file to analyze.
    functions_line_ranges: list of line ranges of interest to filter function
      chunks on.

  Returns:
    A tuple of function and line chunks extracted by the language parser, as
    well as a Sequence of errors returned by the parser.
  """
  parser_class = get_parser_class(filename)
  if not parser_class:
    raise NotImplementedError(f'File {filename} is not supported.')

  return parser_class(filename).get_chunks(functions_line_ranges)
