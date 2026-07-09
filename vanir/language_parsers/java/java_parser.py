# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Vanir Java parser.

This module implements an AbstractLanguageParser that handles all .java files.
"""

import os
from typing import Iterable, Optional, Sequence, Tuple

from vanir.language_parsers import abstract_language_parser
from vanir.language_parsers import common
from vanir.language_parsers.java.python import parser_core

from pybind11_abseil import status

_ANTLR4_DECODE_ERROR = 'UTF-8 string contains an illegal byte sequence'


class JavaParser(abstract_language_parser.AbstractLanguageParser):
  """Vanir Java parser.

  This class implements the AbstractLanguageParser base class.
  """

  def __init__(self, filename: str):
    self._filename = filename

  @classmethod
  def get_supported_extensions(cls) -> Iterable[str]:  # pyrefly: ignore[bad-override]
    return ['.java']

  def get_chunks(
      self,
      affected_line_ranges_for_functions: Optional[
          Sequence[Tuple[int, int]]
      ] = None,
  ) -> common.ParseResults:
    if not affected_line_ranges_for_functions:
      affected_line_ranges_for_functions = []

    try:
      parser = parser_core.ParserCore(self._filename)
      function_chunks_raw, line_chunk_raw, errors_raw = parser.parse(
          affected_line_ranges_for_functions)
    except status.StatusNotOk as e:
      if (
          e.code == status.StatusCode.INVALID_ARGUMENT.value  # pyrefly: ignore[missing-attribute]
          and e.message == _ANTLR4_DECODE_ERROR
      ):
        # If encoding problem, try again after converting to UTF-8.
        temp_filename = self._convert_to_utf8(self._filename)
        try:
          parser = parser_core.ParserCore(temp_filename)
          function_chunks_raw, line_chunk_raw, errors_raw = parser.parse(
              affected_line_ranges_for_functions
          )
        finally:
          os.remove(temp_filename)
      else:
        raise e

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
