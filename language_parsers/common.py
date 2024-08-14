# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Common data types for Vanir language parser."""

import dataclasses
from typing import Mapping, Sequence


@dataclasses.dataclass(frozen=True)
class FunctionChunkBase:
  """Data class representing a function and metadata extracted by a parser.

  Attributes:
    name: function name
    return_types: sequence of return types. Each return type is a sequence of
      tokens representing the type. E.g. [['struct', 'foo'], ['int']]
    parameters: sequence of parameter names that the function accepts
    used_data_types: sequence of all data types used by the function. Similar
      to return_types, each entry is a sequence of tokens for the type.
    local_variables: sequence of names of all local variables.
    called_functions: sequence of other function names called.
    tokens: sequence of tokens consisting of the function body.
  """
  name: str
  return_types: Sequence[Sequence[str]]
  parameters: Sequence[str]
  used_data_types: Sequence[Sequence[str]]
  local_variables: Sequence[str]
  called_functions: Sequence[str]
  tokens: Sequence[str]


@dataclasses.dataclass(frozen=True)
class LineChunkBase:
  """Data class for meaningful tokenized lines extracted by a parser."""
  tokens: Mapping[int, Sequence[str]]


@dataclasses.dataclass(frozen=True)
class ParseError:
  """Data class for holding an error found during parsing."""
  line: int
  column: int
  bad_token: str
  message: str


@dataclasses.dataclass(frozen=True)
class ParseResults:
  """Data class holding all parsing results (function/line chunk, errors)."""
  function_chunks: Sequence[FunctionChunkBase]
  line_chunk: LineChunkBase
  parse_errors: Sequence[ParseError]
