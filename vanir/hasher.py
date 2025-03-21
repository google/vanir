# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Hasher to generate signature hashes for the given code snippets."""

import functools
from typing import Mapping, Optional, Sequence, Tuple

from absl import logging
import mmh3

# For experimental purpose, the n-gram size can be adjusted, but note that any
# change on the line n-gram size requires regeneration of entire signatures.
# Generally, decreasing n-gram size may end up with increase of findings,
# including both true positives and false positives.
_LINE_SIGNATURE_NGRAM_SIZE = 4

_HASH = functools.partial(mmh3.hash128, seed=0, x64arch=True, signed=False)


class _LineNgram:
  """Class for maintaining an n-gram where the units are code lines."""

  def __init__(self,
               normalized_code: Mapping[int, str],
               line_numbers: Sequence[int],
               is_first: Optional[bool] = False,
               is_last: Optional[bool] = False):
    """Initializes the line n-gram.

    The first and last ngram of a file must be explicitly marked through
    |is_first| and |is_last| in order to cover patch hunks adding lines at the
    top or the bottom of the file. Internally, the first ngram will be regarded
    as ranging from the line number negative infinity, and the last ngram
    ranging to the line number infinity.

    Args:
      normalized_code: dictionary of normalized code lines including (but not
        limited to) the lines for the n-gram. Each key is a line number, and the
        value is normalized line in string.
      line_numbers: the list of line numbers comprising the n-gram. Each line
        number must be a valid line number existing in |normalized_code|.
      is_first: True if the n-gram is the first n-gram of the target file.
      is_last: True if the n-gram is the last n-gram of the target file.

    Raises:
      ValueError: raises value error if any line number in |line_numbers| is not
      a valid line number in |normalized_code|.
    """

    self._normalized_code = normalized_code
    self._line_numbers = sorted(line_numbers)
    self._is_first = is_first
    self._is_last = is_last

  def is_overlapping(self, line_range: Tuple[int, int]) -> bool:
    """Returns true if the line ngram range overlaps with given |line_range|."""
    if self._is_first and self._is_last:
      # This n-gram is the first and the last n-gram, covering the entire file.
      return True

    range_start, range_end = line_range
    if range_start > range_end:
      raise ValueError(f'line_range: start ({range_start}) cannot be greater '
                       f'than end ({range_end})')

    # For given ranges r1 and r2, if r1.start <= r2.end && r1.end >= r2.start,
    # r1 and r2 overlaps.
    if self._is_first:
      return self._line_numbers[-1] >= range_start
    if self._is_last:
      return self._line_numbers[0] <= range_end
    return (self._line_numbers[0] <= range_end and
            self._line_numbers[-1] >= range_start)

  def get_ngram_string(self) -> str:
    """Returns the actual string of the n-gram."""
    try:
      return ' '.join([
          self._normalized_code[line_number]
          for line_number in self._line_numbers
      ])
    except KeyError as e:
      raise KeyError(
          f'Invalid line numbers for ngram: {self._line_numbers}. This is a '
          'bug and should never have happened. A _LineNgram object should only '
          'be initialized with line_numbers being a subset of normalized_code.'
      ) from e

  def get_line_numbers(self) -> Sequence[int]:
    """Returns the line numbers comprising the n-gram."""
    return self._line_numbers


def hash_function_chunk(normalized_code: str) -> int:
  """Computes hash for the normalized code of a function chunk.

  A function chunk signature is a Murmur3 128-bit x64 hash of the normalized
  function code.

  Args:
    normalized_code: a normalized function code in string.

  Returns:
    The 128-bit hash in integer.
  """
  return _HASH(normalized_code)


def hash_line_chunk(
    normalized_code: Mapping[int, str],
    affected_line_ranges: Sequence[Tuple[int, int]]
) -> Tuple[Sequence[int], Sequence[int]]:
  """Computes hash for the normalized code of a line chunk.

  A line chunk signature is a set of n-gram line hashes. Each n-gram consists
  of affected lines and their context lines (up to n - 1 lines before and
  after the affected lines). Note that any empty lines / comment lines are not
  regarded as valid lines so the actual context lines can be located further
  than n - 1 lines of an affected line.

  Args:
    normalized_code: a normalized code of a line chunk.
    affected_line_ranges: list of the ranges indicating the lines changed by the
      patch in the chunk's target file. The line numbers are based on the
      unpatched file. Inclusive.

  Returns:
    A tuple of the hash list and used line list. The hash list is a list of
    128-bit line n-gram hashes. The used line list is a list of integer line
    numbers used as elements of the n-grams.
  """
  valid_line_numbers = sorted(normalized_code.keys())
  if not valid_line_numbers:
    logging.debug('No valid line found from the normalized code. Returning '
                  'empty lists.')
    return [], []

  if not affected_line_ranges:
    # If no affected line range is specified, regard all lines as affected.
    affected_line_ranges = [
        (valid_line_numbers[0], valid_line_numbers[-1])
    ]

  # Make a list of all valid line ngrams.
  ngrams = []
  if len(valid_line_numbers) < _LINE_SIGNATURE_NGRAM_SIZE:
    # If the number of valid lines in a file is shorter than n-gram size,
    # just use all valid lines.
    ngrams.append(
        _LineNgram(
            normalized_code, valid_line_numbers, is_first=True, is_last=True))
  else:
    ngram_first_line_indices = range(
        len(valid_line_numbers) - _LINE_SIGNATURE_NGRAM_SIZE + 1)
    for line_index in ngram_first_line_indices:
      ngram_line_numbers = valid_line_numbers[
          line_index:_LINE_SIGNATURE_NGRAM_SIZE + line_index]
      is_first = line_index == ngram_first_line_indices[0]
      is_last = line_index == ngram_first_line_indices[-1]
      ngrams.append(
          _LineNgram(normalized_code, ngram_line_numbers, is_first, is_last))

  # For only "valid & affected" ngrams, compute ngram hashes.
  line_hashes = []
  used_lines = set()
  for affected_range in affected_line_ranges:
    for ngram in ngrams.copy():
      if ngram.is_overlapping(affected_range):
        ngram_hash = _HASH(ngram.get_ngram_string())
        line_hashes.append(ngram_hash)
        used_lines.update(ngram.get_line_numbers())
        ngrams.remove(ngram)

  return line_hashes, sorted(used_lines)
