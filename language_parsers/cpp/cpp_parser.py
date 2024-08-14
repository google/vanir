# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Vanir C/C++ parser.

This module interfaces with the native Antlr FuzzyC parser.
"""
import os
import tempfile
from typing import Iterable, Optional, Sequence, Tuple

from absl import logging
from vanir.language_parsers import abstract_language_parser
from vanir.language_parsers import common
from vanir.language_parsers.cpp.python import parser_core

from pybind11_abseil import status

_ANTLR4_DECODE_ERROR = 'UTF-8 string contains an illegal byte sequence'
_ALTNERNATIVE_ENCODINGS = ['LATIN-1']


class CppParser(abstract_language_parser.AbstractLanguageParser):
  """Vanir C/C++ parser.

  This class implements the AbstractLanguageParser base class.
  """

  def __init__(self, filename: str):
    try:
      self.parser_core = parser_core.ParserCore(filename)
      self.parser_core.init()
    except status.StatusNotOk as e:
      if (
          e.code == status.StatusCode.INVALID_ARGUMENT.value
          and e.message == _ANTLR4_DECODE_ERROR
      ):
        # If encoding problem, try again after converting to UTF-8.
        logging.info('%s is not encoded in UTF-8. Trying altneratives.')
        self._temp_filename = self._convert_to_utf8(filename)
        self.parser_core = parser_core.ParserCore(self._temp_filename)
        self.parser_core.init()
      else:
        raise e

  def __del__(self):
    if getattr(self, '_temp_filename', None):
      os.unlink(self._temp_filename)

  @classmethod
  def get_supported_extensions(cls) -> Iterable[str]:
    return ['.c', '.h', '.cc', '.hh', '.cpp', '.hpp', '.cxx', '.hxx']

  @classmethod
  def _convert_to_utf8(cls, filename) -> str:
    """Creates a new file with UTF-8 encoding and returns the file name."""
    for encoding in _ALTNERNATIVE_ENCODINGS:
      try:
        with open(filename, encoding=encoding, mode='r') as file:
          new_file = tempfile.NamedTemporaryFile(
              encoding='UTF-8', mode='w', delete=False
          )
          new_file.write(file.read())
          new_file.close()
          return new_file.name
      except ValueError:  # Try other encodings on decoding failure
        continue
    raise ValueError(
        'Failed to deocde %s. Tried encodings: UTF-8, %s'
        % (filename, ', '.join(_ALTNERNATIVE_ENCODINGS))
    )

  def _to_standard_function_chunk_base(
      self, chunk: parser_core.FunctionChunkRaw
  ) -> common.FunctionChunkBase:
    return common.FunctionChunkBase(
        chunk.name,
        [chunk.return_type],
        chunk.parameters,
        chunk.used_data_types,
        chunk.local_variables,
        chunk.called_functions,
        chunk.tokens,
    )

  def get_chunks(
      self,
      affected_line_ranges_for_functions: Optional[
          Sequence[Tuple[int, int]]
      ] = None,
  ) -> common.ParseResults:
    if affected_line_ranges_for_functions is None:
      affected_line_ranges_for_functions = []
    function_chunks = [
        self._to_standard_function_chunk_base(function_chunk_raw)
        for function_chunk_raw in self.parser_core.get_function_chunks(
            affected_line_ranges_for_functions)
    ]
    line_chunk = common.LineChunkBase(self.parser_core.get_line_chunk().tokens)
    errors = [
        common.ParseError(e.line, e.column, e.bad_token, e.message)
        for e in self.parser_core.get_parse_errors()
    ]
    return common.ParseResults(function_chunks, line_chunk, errors)
