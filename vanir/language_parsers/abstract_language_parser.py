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

_ALTERNATIVE_ENCODINGS = ['LATIN-1']


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

  @classmethod
  def _convert_to_utf8(cls, filename) -> str:
    """Creates a new file with UTF-8 encoding and returns the file name."""
    logging.info('Converting %s to UTF-8.', filename)
    for encoding in _ALTERNATIVE_ENCODINGS:
      try:
        with open(filename, encoding=encoding, mode='r') as file:
          new_file = tempfile.NamedTemporaryFile(
              encoding='UTF-8', mode='w', delete=False,
          )
          new_file.write(file.read())
          new_file.close()
          return new_file.name
      except ValueError:  # Try other encodings on decoding failure
        continue
    raise ValueError(
        'Failed to decode %s. Tried encodings: UTF-8, %s'
        % (filename, ', '.join(_ALTERNATIVE_ENCODINGS))
    )
