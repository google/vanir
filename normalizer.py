# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Normalizer preprocesses code snippets for making signatures more generic."""

import collections
import enum
from typing import Iterator, Mapping, Sequence, Tuple

from vanir.language_parsers import common


@enum.unique
class _AbstractedToken(str, enum.Enum):
  """Enumeration of abstracted text of token(s)."""

  FUNCTION_NAME = 'FUNCNAME'
  PARAMETER = 'PARAM'
  DATA_TYPE = 'DTYPE'
  LOCAL_VARIABLE = 'VAR'
  FUNCTION_CALL = 'FUNCCALL'


# Use integer keys to indicate special nodes in _TokenTrie.
@enum.unique
class _NodeType(int, enum.Enum):
  LEAF = 0


# Security-sensitive keywords that shouldn't be abstraced away.
_PROTECTED_KEYWORDS = frozenset(['const', 'signed', 'unsigned'])


def _get_trie() -> collections.defaultdict:
  """Returns a trie implemented with recursive default dict.

  Usage:
      x = _get_trie()
      x[key1][key2][key3] = value

  Returns:
    a defaultdict having another defaultdict as a default value.
  """
  return collections.defaultdict(_get_trie)


class _TokenTrie:
  """Trie datastructure for searching a normalized token for token stream.

  Usage:
    token_trie = _TokenTrie()
    token_trie.insert_entry(['myvar'], _AbstractedToken.LOCAL_VARIABLE)
    token_trie.insert_entry(['int'], _AbstractedToken.DATA_TYPE)
    token_trie.insert_entry(['struct', 'mem'], _AbstractedToken.DATA_TYPE)
    tokens = ['int', 'myvar', ';', 'struct', 'mem', 'unknownvar', ';']
    normalized_tokens = list(token_trie.generate_normalized_tokens(tokens))

    Then, normalized_tokens == ['DTYPE', 'VAR', ';', 'DTYPE', 'unknownvar', ';']
  """

  def __init__(self):
    self._trie = _get_trie()

  def insert_entry(self, key_tokens: Sequence[str],
                   abstracted_token: _AbstractedToken):
    """Insert |key_tokens| as a chained key and |abstracted_token| as its leaf.

    If any protected keywords are included in token, the leaf node will have the
    protected keywords prefixed to |abstracted_token|.
    E.g., insert_entry(['struct', 'mem'], 'DTYPE') adds a trie entry:
      _trie['struct']['mem'][_NodeType.LEAF] = 'DTYPE'.
    E.g., insert_entry(['const', 'unsigned', 'int'], 'DTYPE') adds a trie entry:
      _trie['const']['unsigned']['int'][_NodeType.LEAF] = 'const unsigned DTYPE'

    Args:
      key_tokens: list of tokens to match for the entry.
      abstracted_token: the abstracted token to replace matched token stream.
    """
    if not key_tokens:
      return
    subtrie = self._trie
    for token in key_tokens:
      if not token:
        continue  # Empty string token is not valid. Skip.
      subtrie = subtrie[token]

    if subtrie == self._trie:  # No valid token in |key_tokens|.
      return

    protected_keywords_in_datatype = _PROTECTED_KEYWORDS.intersection(
        key_tokens)
    if protected_keywords_in_datatype:
      subtrie[_NodeType.LEAF] = ' '.join(
          sorted(protected_keywords_in_datatype) + [abstracted_token])
    else:
      subtrie[_NodeType.LEAF] = abstracted_token

  def generate_normalized_tokens(self, tokens: Sequence[str]) -> Iterator[str]:
    """Iterates |tokens| and yields abstraction of each longest matching tokens.

    Args:
      tokens: a normalization target token list.

    Yields:
      The normalized string for the longest matching stream of the tokens.
      If nothing matches, yield the token string as is after lowercasing.
    """

    index = 0
    while index < len(tokens):
      normalized_token, index = self._get_next_normalized_token(tokens, index)
      yield normalized_token

  def _get_next_normalized_token(self, tokens: Sequence[str],
                                 index: int) -> Tuple[str, int]:
    """Returns the normalized token for the next longest matching tokens.

    Search for the longest matching trie entry in |tokens[index:]| and returns
    the entry's normalized token.

    Args:
      tokens: the list of the tokens to normalize.
      index: the index of token to resume normalization in |tokens|.
    Returns: a tuple (normalized_token, next_index), where |normalized_token| is
      the normalized token for |tokens[index:next_index]|, and next_index is the
      index of the token to resume scanning from.

    Raises:
      IndexError: if the |index| is out of the valid range of |tokens|.
    """
    normalized_token = None
    next_index = None

    if index >= len(tokens):
      raise IndexError('Index:%d is out of boundary of tokens (max:%d)' %
                       (index, len(tokens) - 1))

    end_index = index
    subtrie = self._trie
    while end_index < len(tokens):
      token = tokens[end_index]
      if not token:  # Ignore empty string.
        end_index += 1
        continue
      if token in subtrie:
        subtrie = subtrie[token]
        if _NodeType.LEAF in subtrie:  # Found new longest matching trie entry.
          normalized_token = subtrie[_NodeType.LEAF]
          next_index = end_index + 1
        end_index += 1
        continue
      break  # Deadend. Return the current longest matching entry.

    if normalized_token is None:
      # If no matching entry, use the token as-is after lowercasing.
      return (tokens[index].lower(), index + 1)
    return (normalized_token, next_index)


def normalize_function_chunk(
    function_chunk_base: common.FunctionChunkBase) -> str:
  """Normalizes and abstracts the given chunk.

  This involves lower casing and replacing identifiers.
  Note that generally, the lexer already removed comments and whitespaces while
  tokenizing the code before giving us a FunctionChunkBase object.

  Args:
    function_chunk_base: the function chunk base containing the function body
      tokens and function metadata.

  Returns:
    The normalized function chunk code string.
  """
  token_trie = _TokenTrie()
  token_trie.insert_entry([function_chunk_base.name],
                          _AbstractedToken.FUNCTION_NAME)
  for param in function_chunk_base.parameters:
    token_trie.insert_entry([param], _AbstractedToken.PARAMETER)
  for local_var in function_chunk_base.local_variables:
    token_trie.insert_entry([local_var], _AbstractedToken.LOCAL_VARIABLE)
  for called_function in function_chunk_base.called_functions:
    token_trie.insert_entry([called_function], _AbstractedToken.FUNCTION_CALL)
  for data_type in function_chunk_base.used_data_types:
    token_trie.insert_entry(data_type, _AbstractedToken.DATA_TYPE)
  token_trie.insert_entry(sum(function_chunk_base.return_types, []),
                          _AbstractedToken.DATA_TYPE)

  normalized_code = ' '.join(
      token_trie.generate_normalized_tokens(function_chunk_base.tokens))
  return normalized_code


def normalize_line_chunk(
    line_chunk_base: common.LineChunkBase) -> Mapping[int, str]:
  """Normalizes the given line chunk.

  This function normalizes the tokens of the given |chunk| and stores the
  normalized string at |chunk.normalized_code|. Currently the only
  normallization step done here is lowercasing.
  Note that generally, the lexer already removed comments and whitespaces while
  tokenizing the code before giving us a LineChunkBase object.

  Args:
    line_chunk_base: the line chunk base containing the line tokens.

  Returns:
    The normalized line chunk string dictionary where each key is a line number
    and its value is the normalized code string.
  """
  token_map = line_chunk_base.tokens
  normalized_code = {}
  for line_number in token_map:
    normalized_code[line_number] = ' '.join(token_map[line_number]).lower()
  return normalized_code
