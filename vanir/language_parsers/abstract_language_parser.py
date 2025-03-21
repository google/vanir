# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Abstract Parser base class that all parsers implement.
"""

import abc
from typing import Optional, Sequence, Tuple

from vanir.language_parsers import common


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
