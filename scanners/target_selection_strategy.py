# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Module for managing various scanning target file selection strategies."""

import abc
import enum
import os
from typing import Iterator, Sequence, Tuple

from vanir import parser
from vanir import signature
from vanir import truncated_path
from vanir.scanners import package_identifier


class _Strategy(metaclass=abc.ABCMeta):
  """Abstract Strategy class defining target selection behavior.

  |_Strategy| class instances are expected to select targets in different ways.
  Each child of |_Strategy| class implements |get_target_files()| method in
  order to identify the target files with its own methodology.
  """

  @abc.abstractmethod
  def get_target_files_from_file_list(
      self,
      file_list: Sequence[str],
      signature_bundle: signature.SignatureBundle,
  ) -> Tuple[Sequence[str], int]:
    """Returns all selected target files and the number of unselected files.

    This method takes a list of files to be scanned and a bundle of signatures
    to be used for the scanning, and returns only the files selected by the
    current strategy as target files for further analysis.

    Args:
      file_list: a list of the paths of files to be scanned. The path should be
        a relative path having the package's top level directory as a root.
        E.g., `drivers/scsi/mac53c94.h' for the Linux SCSI driver file.
      signature_bundle: bundle of all relevant signatures.

    Returns:
      A sequence of relative paths of all selected target files, and the number
      of unselected files.
    """

  def get_target_files(
      self, code_location: str, signature_bundle: signature.SignatureBundle
  ) -> Tuple[Sequence[str], int]:
    """Returns all selected target files and the number of unselected files.

    This method takes the path to the target directory root |code_location| and
    a bundle of signatures to be used for the scanning, and returns only the
    absolute paths of the files selected by the current strategy as target files
    for further analysis.

    Args:
      code_location: the path to the root directory of the system to conduct
        missing patch scanning against.
      signature_bundle: bundle of all relevant signatures.

    Returns:
      A sequence of absolute paths of all selected target files, and the number
      of unselected files.
    """
    abs_file_list = list(self.walk_path_for_files(code_location))
    file_map = {}  # key: relative path, value: absolute path
    for abs_file_path in abs_file_list:
      rel_file_path = os.path.relpath(abs_file_path, start=code_location)
      file_map[rel_file_path] = abs_file_path
    selected_rel_file_list, skipped = self.get_target_files_from_file_list(
        file_list=list(file_map.keys()), signature_bundle=signature_bundle
    )
    selected_abs_file_list = [
        file_map[selected_rel_file]
        for selected_rel_file in selected_rel_file_list
    ]
    return selected_abs_file_list, skipped

  @classmethod
  def walk_path_for_files(cls, code_location) -> Iterator[str]:
    """Yields files supported by Vanir under the given code location."""
    for root, _, files in os.walk(code_location):
      for file in files:
        next_file_path = os.path.join(root, file)
        if not os.path.isfile(next_file_path) or not parser.is_supported_type(
            file
        ):
          continue
        yield next_file_path


class _AllFiles(_Strategy):
  """Strategy that simply scan all files."""

  def get_target_files_from_file_list(
      self,
      file_list: Sequence[str],
      signature_bundle: signature.SignatureBundle,
  ) -> Tuple[Sequence[str], int]:
    return file_list, 0


class _ExactPathMatch(_Strategy):
  """Strategy to scan files that exactly matches the known target paths.

  This strategy simply assumes the target directory starts from the standard
  root of the known target package and select files that exactly matches the
  known target paths of the signatures. For instance, if a signature's target
  file is 'mm/huge_memory.c', and if the given target code location is
  '~/my_kernel/', it checks if '~/my_kernel/mm/huge_memory.c' exists, and add
  its absolute path to the returning scan target list if exists.
  """

  def get_target_files_from_file_list(
      self,
      file_list: Sequence[str],
      signature_bundle: signature.SignatureBundle,
  ) -> Tuple[Sequence[str], int]:
    target_file_paths = set()
    for sign in signature_bundle.signatures:
      target_file_paths.add(sign.target_file)

    to_scan = []
    total_skipped = 0
    for file_path in file_list:
      if file_path in target_file_paths:
        to_scan.append(file_path)
      else:
        total_skipped += 1
    return to_scan, total_skipped


class _TruncatedPathMatch(_Strategy):
  """Heuristic strategy to identify affected files using truncated paths.

  This strategy utilizes Truncated Path defined in Truncated Path module to
  identify files possibly corresponding to the signature's known target file
  path. This strategy includes all exactly matching files and additional
  partially matching files. Further description on Truncated Path Matching can
  be found from the Truncated Path module docstring.
  """

  def get_target_files_from_file_list(
      self,
      file_list: Sequence[str],
      signature_bundle: signature.SignatureBundle,
  ) -> Tuple[Sequence[str], int]:
    # Change target files to target truncated paths.
    target_file_paths = set()  # For the exact path match.
    target_truncated_path_set = set()
    for sign in signature_bundle.signatures:
      target_file_paths.add(sign.target_file)
      level = sign.truncated_path_level
      if level is None:
        level = min(
            package_identifier.DEFAULT_TRUNCATED_PATH_LEVEL,
            truncated_path.TruncatedPath.get_max_level(sign.target_file)
        )
      try:
        tp = truncated_path.TruncatedPath(sign.target_file, level)
      except truncated_path.PathLevelError as error:
        # The signature's TP level is invalid.
        raise ValueError(
            'The signature %s has invalid Truncated Path Level.'
            % (sign.signature_id)
        ) from error
      target_truncated_path_set.add(tp)

    # Compute all levels of truncated paths of files in the scanned directory
    # and check if any match.
    to_scan = []
    total_skipped = 0
    for file_path in file_list:
      # Always try exact path match first.
      if file_path in target_file_paths:
        to_scan.append(file_path)
      elif truncated_path.check_inclusion(target_truncated_path_set, file_path):
        to_scan.append(file_path)
      else:
        total_skipped += 1
    return to_scan, total_skipped


@enum.unique
class Strategy(enum.Enum):
  """Enumeration of Vanir's target file identification strategies.

  Enumeration of supported target file selection strategies. Each enum value
  is an instance of |_Strategy| class.

  Usage:
    Strategy['ALL_FILES'].get_target_files(...)
    Strategy.ALL_FILES.get_target_files(...)
  """

  ALL_FILES = _AllFiles()
  EXACT_PATH_MATCH = _ExactPathMatch()
  TRUNCATED_PATH_MATCH = _TruncatedPathMatch()

  def get_target_files(
      self, code_location: str, signature_bundle: signature.SignatureBundle
  ) -> Tuple[Sequence[str], int]:
    """Wrapper of the strategy object's |get_target_files()|."""
    return self.value.get_target_files(code_location, signature_bundle)

  def get_target_files_from_file_list(
      self,
      file_list: Sequence[str],
      signature_bundle: signature.SignatureBundle,
  ) -> Tuple[Sequence[str], int]:
    """Wrapper of the strategy object's |get_target_files_from_file_list()|."""
    return self.value.get_target_files_from_file_list(
        file_list, signature_bundle
    )
