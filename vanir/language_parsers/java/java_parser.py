# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Vanir Java parser.

This module implements an AbstractLanguageParser that handles all .java files.
"""

from typing import Iterable, Optional, Sequence, Tuple

from vanir.language_parsers import abstract_language_parser
from vanir.language_parsers import common
from vanir.language_parsers.java.python import parser_core


class JavaParser(abstract_language_parser.AbstractLanguageParser):
  """Vanir Java parser.

  This class implements the AbstractLanguageParser base class.
  """

  def __init__(self, filename: str):
    self.parser = parser_core.ParserCore(filename)

  @classmethod
  def get_supported_extensions(cls) -> Iterable[str]:
    return ['.java']

  def get_chunks(
      self,
      affected_line_ranges_for_functions: Optional[
          Sequence[Tuple[int, int]]
      ] = None,
  ) -> common.ParseResults:
    if not affected_line_ranges_for_functions:
      affected_line_ranges_for_functions = []

    function_chunks_raw, line_chunk_raw, errors_raw = self.parser.parse(
        affected_line_ranges_for_functions)
    function_chunks = []
    for function_chunk_raw in function_chunks_raw:
      function_chunks.append(
          common.FunctionChunkBase(
              name=function_chunk_raw.name,
              return_types=[function_chunk_raw.return_type],
              parameters=function_chunk_raw.parameters,
              used_data_types=function_chunk_raw.used_data_types,
              local_variables=function_chunk_raw.local_variables,
              called_functions=function_chunk_raw.called_functions,
              tokens=function_chunk_raw.tokens,
          )
      )

    errors = []
    for error_raw in errors_raw:
      errors.append(common.ParseError(
          error_raw.line, error_raw.column,
          error_raw.bad_token,
          error_raw.message))

    return common.ParseResults(
        function_chunks, common.LineChunkBase(line_chunk_raw.tokens_), errors)
