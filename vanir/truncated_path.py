# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Module implementing Truncated Path algorithm.

Truncated Path algorithm is designed to compute an applicability of Vanir
signatures against a given directory with toeralance on directory structure
changes. For a given path p, a truncated path of p with level-L is the modified
path preserving only L-th terminal directory names and the file name. For
instance, for a file path 'foo/bar/baz/qux.c', level-0, 1, 2 and 3 Truncated
Paths are 'qux.c', 'baz/qux.c', 'bar/baz/qux.c' and 'foo/bar/baz/qux.c'.

Truncated Path Match algorithm utilizes Truncated Paths of known target file
paths with empirically obtained levels to check if a given file matches each
signature's target file. For example, for a signature's target file
'foo/bar/baz/qux.c' with truncated path level-1, if a scanned directory contains
'guux/corge/grault/corge/baz/qux.c', Truncated Path algorithm will regard the
file as mactching since its level-1 Truncated Path matches the signature's
Truncated Path.
"""

import collections
from collections.abc import Mapping, Sequence
import functools
import os
from typing import FrozenSet, Optional, Set


class PathLevelError(ValueError):
  """Raised when the Truncated Path level is improper."""


class TruncatedPath:
  """This class represents a Truncated Path."""

  @classmethod
  @functools.cache
  def _normalize_path(cls, file_path: str) -> Sequence[str]:
    normalized_path = os.path.normpath(file_path)
    return normalized_path.split(os.sep)

  @classmethod
  def is_level_ok(cls, file_path: str, level: int) -> bool:
    path_elements = cls._normalize_path(file_path)
    if level + 1 > len(path_elements) or level < 0:
      return False
    return True

  @classmethod
  def get_max_level(cls, file_path: str) -> int:
    """Returns the maximum truncated path level of the given file path."""
    path_elements = cls._normalize_path(file_path)
    return len(path_elements) - 1

  def __init__(self, file_path: str, level: int):
    """Instantiate a Truncated Path for given file path with given level.

    Args:
      file_path: a string path or TruncatedPath object to be computed.
      level: truncated path level.

    Returns:
      The truncated path.

    Raises:
      PathLevelError: if the given level is too large for the given path.
    """

    if not self.is_level_ok(file_path, level):
      raise PathLevelError(
          f'Given path {file_path} does not have enough directories or the'
          f' given level is negative (level: {level}).'
      )
    path_elements = self._normalize_path(file_path)
    self._path_elements = path_elements[-(level + 1) :]
    self._path = os.path.join(*(self._path_elements))

  def __str__(self):
    return self._path

  def __hash__(self):
    return hash(self._path)

  def __eq__(self, other: 'TruncatedPath'):
    return self._path_elements == other._path_elements

  @functools.cached_property
  def level(self):
    return len(self._path_elements) - 1

  def truncate(self, level: int) -> Optional['TruncatedPath']:
    """Truncates the given Truncated Path with the new level."""
    return TruncatedPath(self._path, level)


class MinLevelUniqueTruncatedPathFinder:
  """Finds min levels of uniquely identifiable Truncated Paths.

  This class maintains a list of file paths representing a system, and finds
  a minimum level of unique Truncated Path of the given file among all Truncated
  Paths of the given reference file list.
  """

  def __init__(self, ref_file_list: Sequence[str]):
    """Initializes with the full list of files representing a system.

    Args:
      ref_file_list: the full list of files representing a system. Each file is
        supposed to be in a relative path format as follows:
        ['mm/backing-dev.c', 'mm/balloon_compaction.c', ...]
    """
    self._ref_file_list = ref_file_list

  @functools.lru_cache(128)
  def _get_ref_truncated_path_counter(
      self, level: int
  ) -> Mapping[TruncatedPath, int]:
    """Returns Truncated Path to matched file counter map."""
    ref_truncated_path_counter = collections.defaultdict(int)
    for file_path in self._ref_file_list:
      if not TruncatedPath.is_level_ok(file_path, level):
        continue
      tp = TruncatedPath(file_path, level)
      ref_truncated_path_counter[tp] += 1
    return ref_truncated_path_counter

  def find(self, file_path: str) -> Optional[TruncatedPath]:
    """Returns the min level of uniquely identifiable TP for the given file.

    Args:
      file_path: a relative path of a file.

    Returns:
      Minimum level Truncated Path making the path uniquely identifiable among
      the reference files. Returns None if the given path has no unique
      truncated path at any level.
    """
    for level in range(0, TruncatedPath.get_max_level(file_path) + 1):
      tp = TruncatedPath(file_path, level)
      ref_tp_counters = self._get_ref_truncated_path_counter(level)
      if ref_tp_counters.get(tp, 0) <= 1:  # Unique if counter is 0 or 1.
        return tp
    return None


@functools.cache
def _get_levels(truncated_path_set: FrozenSet[TruncatedPath]) -> Set[int]:
  return {tp.level for tp in truncated_path_set}


def check_inclusion(
    truncated_path_set: Set[TruncatedPath], file_path: str
) -> bool:
  """Check inclusion of a file path in a set of Truncated Path.

  Args:
    truncated_path_set: a set of truncated path.
    file_path: a file path to be checked against the given truncated path set.

  Returns:
    Returns True if any level of truncated path of the given file path is
    included the given Truncated Path Set. Returns False, otherwise.
  """
  levels = _get_levels(frozenset(truncated_path_set))
  for level in levels:
    if not TruncatedPath.is_level_ok(file_path, level):
      continue
    tp = TruncatedPath(file_path, level)
    if tp in truncated_path_set:
      return True
  return False


def check_inclusion_rate_of_truncated_paths_in_file_list(
    truncated_path_set: FrozenSet[TruncatedPath], file_list: Sequence[str]
) -> float:
  """Check inclusion rate of a list of Truncated Paths in the list of files.

  Args:
    truncated_path_set: a set of truncated path.
    file_list: a list of file paths.

  Returns:
    Returns the truncated path inclusion rate of |truncated_path_set| in
    |file_list|.
  """
  file_tps = set()
  levels = _get_levels(frozenset(truncated_path_set))
  for level in levels:
    for file_path in file_list:
      if not TruncatedPath.is_level_ok(file_path, level):
        continue
      file_tps.add(TruncatedPath(file_path, level))
  intersection = file_tps.intersection(truncated_path_set)
  return len(intersection) / len(truncated_path_set)
