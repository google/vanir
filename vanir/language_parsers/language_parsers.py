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

import os
from typing import Optional, Sequence, Tuple, Type, TypeVar

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


def _all_subclasses(cls):
  """Recursively collect all concrete (non-abstract) subclasses of cls."""
  result = []
  for sub in cls.__subclasses__():
    if not sub.__abstractmethods__:
      result.append(sub)
    result.extend(_all_subclasses(sub))
  return result


def get_parser_class(filename: str) -> Optional[Type[_P]]:
  """Returns the language parser class that handles the given file, or None."""
  parsers = _all_subclasses(abstract_language_parser.AbstractLanguageParser)
  ext = os.path.splitext(filename)[1]
  for parser_class in parsers:
    if ext in parser_class.get_supported_extensions():
      return parser_class
  return None


def parse_file(
    filename: str,
    functions_line_ranges: Optional[Sequence[Tuple[int, int]]] = None,
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
