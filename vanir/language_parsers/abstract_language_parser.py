# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Abstract Parser base class that all parsers implement.
"""

import abc
import tempfile
from typing import Optional, Sequence, Tuple

from absl import logging

from vanir.language_parsers import common

ALTERNATIVE_ENCODINGS = ('LATIN-1',)


class AbstractLanguageParser(abc.ABC):
  """Abstract language parser interface that all language parsers implement.

  A Parser object parses one file, optionally only on a set of select line
  ranges, and presents methods to extract function and line chunks to Vanir
  signature generation and scanning.

  A Parser supports a set of file extensions, given by each implementation as
  the return value of get_supported_extensions().
  """

  @classmethod
  @abc.abstractmethod
  def get_supported_extensions(cls) -> Sequence[str]:
    """Returns a list of supported file extensions. Should include the dot."""

  def __init__(self, filename: str):
    """Construct the Parser object for given filename.

    Args:
      filename: the absolute path to the file to analyze.
    """

  @abc.abstractmethod
  def get_chunks(
      self,
      affected_line_ranges_for_functions: Optional[
          Sequence[Tuple[int, int]]
      ] = None,
  ) -> common.ParseResults:
    """Parse the file and return the line chunk and function chunks.

    Args:
      affected_line_ranges_for_functions: list of line ranges of interest to
        filter function chunks on. A parser should return only functions that
        contains at least one line in this range. If
        affected_line_ranges_for_functions is empty, return all functions.
    Return: A ParseResults object containing all the parsing output.
    """

  # The id of the language of the parser, e.g. 'kotlin'. It is empty for a
  # parser whose language is not identified yet.
  language_id: str = ''

  @classmethod
  def get_language_id(cls) -> str:
    """Returns the id of the language of the parser, e.g. 'kotlin'.

    Returns:
      The id of the language, or an empty string.
    """
    return cls.language_id

  @classmethod
  def is_test_file(cls, file_path: str) -> bool:
    """Returns whether the given file is a test file of this language.

    A parser of a language that knows how its test files are named overrides
    this hook, so that the generation of the signatures can skip them. The
    default is False, i.e. a language whose parser does not know its test
    files signs them.

    Args:
      file_path: the path of the file relative to the root of the source tree.

    Returns:
      True if the file is a test file.
    """
    del file_path  # unneeded
    return False

  @classmethod
  def _convert_to_utf8_bytes(cls, filename: str) -> bytes:
    """Reads a file and converts its content to UTF-8 bytes."""
    logging.info('Converting %s to UTF-8.', filename)
    for encoding in ALTERNATIVE_ENCODINGS:
      try:
        with open(filename, encoding=encoding, mode='r') as file:
          return file.read().encode('utf-8')
      except ValueError:  # Try other encodings on decoding failure
        continue
    alt_encodings_str = ', '.join(ALTERNATIVE_ENCODINGS)
    raise ValueError(
        f'Failed to decode {filename}. Tried encodings: UTF-8,'
        f' {alt_encodings_str}'
    )

  @classmethod
  def _convert_to_utf8(cls, filename: str) -> str:
    """Creates a new file with UTF-8 encoding and returns the file name."""
    content = cls._convert_to_utf8_bytes(filename)
    new_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
    new_file.write(content)
    new_file.close()
    return new_file.name
