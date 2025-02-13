# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Sign Generator handles generating Vanir signatures for patches."""

import abc
import collections
import concurrent
import concurrent.futures
import dataclasses
import multiprocessing
import os
import re
from typing import Mapping, Optional, Sequence

from absl import logging
import requests
from vanir import parser
from vanir import signature
from vanir import truncated_path
from vanir.code_extractors import code_extractor_base

from pybind11_abseil import status

_LINE_SIGNATURE_THRESHOLD = 0.9


class FileFilter(abc.ABC):
  """A filter used to exclude files during signature generation."""

  @abc.abstractmethod
  def should_filter_out(
      self,
      ecosystem: str,
      package_name: str,
      commit: code_extractor_base.Commit,
      target_file: str,
      unpatched_file_content_path: str,
  ) -> bool:
    """Returns true if the given file should be excluded.

    Args:
      ecosystem: the ecosystem that the file belongs to. E.g., "Android".
      package_name: the name of the package that the file belongs to. E.g.,
        ":linux_kernel:", ":linux_kernel:Qualcomm", "platform/frameworks/base"
      commit: the |Commit| object that the file belongs to.
      target_file: file path to be patched, as mentioned in the patch.
      unpatched_file_content_path: path to the temporary file on disk containing
        the content of the target_file before applying the fix patch.
    """


class EcosystemAndFileNameFilter(FileFilter):
  """A filter that excludes files matching a name pattern in given ecosystem."""

  def __init__(self, ecosystem: str, name_pattern: str):
    self._ecosystem = ecosystem
    self._name_pattern = name_pattern

  def should_filter_out(
      self,
      ecosystem: str,
      package_name: str,
      commit: code_extractor_base.Commit,
      target_file: str,
      unpatched_file_content_path: str
  ) -> bool:
    del package_name, commit, unpatched_file_content_path  # unneeded
    return (
        ecosystem == self._ecosystem
        and re.fullmatch(self._name_pattern, target_file) is not None)


class TruncatedPathLevelFinder:
  """Finds Truncated Path Level for signatures.

  This class is to find a proper |truncated_path_level| field values for each
  signature.
  """

  def __init__(
      self,
      ref_file_lists: Mapping[str, Mapping[str, Sequence[str]]],
      conditions: Mapping[str, Mapping[str, re.Pattern[str]]],
  ):
    """Initializes the finder.

    Args:
      ref_file_lists: map of reference file lists representing entire files of
        each target ecosystem/package. The first key is ecosystem, the second
        key is package name and the value is a file list.
      conditions: map of regex pattern that file paths should match to be
        qualified to have truncated path level value for each ecosystem/package.
        The first key is ecosystem, the second key is package name and the value
        is a regex pattern.
    """

    self._tp_finders = collections.defaultdict(dict)
    for ecosystem in ref_file_lists:
      for package_name in ref_file_lists[ecosystem]:
        self._tp_finders[ecosystem][package_name] = (
            truncated_path.MinLevelUniqueTruncatedPathFinder(
                ref_file_lists[ecosystem][package_name]
            )
        )
    self._conditions = conditions

  def find(
      self, file_path: str, ecosystem: str, package_name: str
  ) -> Optional[int]:
    """Returns the truncated path level if |file_path| matches |condition|.

    Args:
      file_path: a relative path of a file in the package.
      ecosystem: the ecosystem that the file belongs to. E.g., "Android".
      package_name: the name of the package that the file belongs to. E.g.,
        ":linux_kernel:", ":linux_kernel:Qualcomm", "platform/frameworks/base"
    """
    pattern = self._conditions.get(ecosystem, {}).get(package_name)
    if not pattern:
      return None
    if pattern.fullmatch(file_path):
      tp_finder = self._tp_finders.get(ecosystem, {}).get(package_name)
      if not tp_finder:
        return None
      tp = tp_finder.find(file_path)
      if tp:
        return tp.level
      # If |file_path| has no unique TP, just return the max level.
      logging.info('No unique TP found for %s. Returning max level.', file_path)
      return truncated_path.TruncatedPath.get_max_level(file_path)
    return None


@dataclasses.dataclass(frozen=True)
class CustomLineSignatureThreshold:
  """Dataclass for customizing a line signature's threshold.

  Example:
    CustomLineSignatureThreshold(
      commit_url='https://android.googlesource.com/kernel/common/+/050fad7c',
      target_file='artd/artd_main.cc', threshold=0.75)

  Attributes:
    commit_url: the fix commit URL of the line signature.
    target_file: path of the signature's target file, relative to the root of
      the target source tree. E.g., arch/x86/pci/irq.c in Linux Kernel.
    threshold: the custom threshold for the designated line signature. A
      threshold must be between 0 and 1.
  """

  commit_url: str
  target_file: str
  threshold: float

  def __post_init__(self):
    if not 0 < self.threshold <= 1:
      raise ValueError(
          'Custom line signature threshold entry %s is not'
          ' valid. A threshold must be between 0 and 1.' % self
      )


class SignGenerator:
  """Generates known vulnerability signatures for Vanir.

  Signature generator retrieves vulns from OSV, extracts corresponding patch
  files from source repositories, parses the files, extracts common code
  patterns and builds them into Vanir signatures.
  """

  def __init__(
      self,
      line_signature_threshold: float = _LINE_SIGNATURE_THRESHOLD,
      custom_line_signature_thresholds: Optional[
          Sequence[CustomLineSignatureThreshold]
      ] = (),
      session: Optional[requests.sessions.Session] = None,
      filters: Sequence[FileFilter] = (),
      truncated_path_level_finder: Optional[TruncatedPathLevelFinder] = None,
  ):
    """Initializes Sign Generator.

    Args:
      line_signature_threshold: the default threshold for line signatures.
      custom_line_signature_thresholds: optional arg to individually specify
        line signature thresholds. Each individual entry of the sequence
        specifies a threshold value for a line signature. Init will fail if
        there are multiple thresholds set for a line signature.
      session: request session to use for retrieving vulns and patches. If none,
        a new session will be used.
      filters: optional list of filters to be used during generation.
      truncated_path_level_finder: TruncatedPathLevelFinder instance. If set,
        the instance will be utilized to update truncated path level field of
        the signatures.
    """
    if not 0 < line_signature_threshold <= 1:
      raise ValueError('Line signature threshold %f is not valid. '
                       'A threshold must be between 0 and 1.' %
                       line_signature_threshold)
    self._line_signature_threshold = line_signature_threshold
    self._custom_line_signature_threshold_map = {}
    for custom_threshold in custom_line_signature_thresholds:
      key = (custom_threshold.commit_url, custom_threshold.target_file)
      if key in self._custom_line_signature_threshold_map:
        raise ValueError(
            'Found more than one custom threshold entries for the following '
            'line signature:\n  commit_url:%s\n  target_file:%s' % key
        )
      self._custom_line_signature_threshold_map[key] = (
          custom_threshold.threshold
      )
    self._session = session or requests.sessions.Session()
    self._filters = filters
    self._tp_level_finder = truncated_path_level_finder
    # Cache for parsed files. Key is a tuple of (commit_url, target_file).
    # Note that line_range is not included in the key because each
    # (commit_url, file) pair has a unique line_range.
    self._parsers_cache = {}

  def generate_signatures_for_commit(
      self,
      ecosystem: str,
      package_name: str,
      commit: code_extractor_base.Commit,
      signature_factory: signature.SignatureFactory,
  ) -> Sequence[signature.Signature]:
    """Generates signatures for a commit.

    Args:
      ecosystem: the ecosystem that the commit belongs to. E.g., "Android".
      package_name: the name of the package that the commit belongs to. E.g.,
        ":linux_kernel:", ":linux_kernel:Qualcomm", "platform/frameworks/base"
      commit: a |Commit| object containing a patch.
      signature_factory: signature factory object to use. All signatures in a
        factory will have unique IDs; conversely, signatures in different
        factories may have ID collisions.
    Returns:
      A sequence of signatures generated for the given |commit|.
    """
    url = commit.get_url()

    # Build the list of relevant files and files that need parsing
    # (i.e. not in cache)
    relevant_target_files = set()
    files_to_parse = set()
    for target_file, temp_file_path in commit.get_unpatched_files().items():
      should_filter_out = any(
          file_filter.should_filter_out(
              ecosystem, package_name, commit, target_file, temp_file_path
          )
          for file_filter in self._filters
      )
      if should_filter_out:
        continue
      if not parser.is_supported_type(target_file):
        continue
      relevant_target_files.add(target_file)

      if (url, target_file) not in self._parsers_cache:
        files_to_parse.add((target_file, temp_file_path))

    # Parse the files that are not cached
    if files_to_parse:
      result_futures = []
      with concurrent.futures.ProcessPoolExecutor(
          max_workers=min(len(files_to_parse), os.cpu_count()),
          mp_context=multiprocessing.get_context('forkserver'),
      ) as executor:
        for target_file, temp_file_path in files_to_parse:
          result_futures.append(
              executor.submit(
                  parser.Parser,
                  temp_file_path,
                  target_file,
                  commit.get_affected_line_ranges(target_file),
              )
          )
      for (target_file, _), future in zip(files_to_parse, result_futures):
        try:
          self._parsers_cache[(url, target_file)] = future.result()
        except concurrent.futures.process.BrokenProcessPool:
          logging.error(
              'A worker died unexpectedly while processing file %s in %s',
              target_file, url,
          )
          relevant_target_files.remove(target_file)
        except status.StatusNotOk as e:
          logging.exception(
              'Failed to parse file %s in %s (error: %s). Skipping. ',
              target_file, url, e
          )
          relevant_target_files.remove(target_file)

    # Generate signatures for the relevant files.
    signatures = []
    for target_file in relevant_target_files:
      file_parser = self._parsers_cache[(url, target_file)]
      tp_level = (
          self._tp_level_finder.find(target_file, ecosystem, package_name)
          if self._tp_level_finder
          else None
      )
      signatures.extend([
          signature_factory.create_from_function_chunk(chunk, url, tp_level)
          for chunk in file_parser.get_function_chunks()
      ])
      threshold = self._custom_line_signature_threshold_map.get(
          (url, target_file),
          self._line_signature_threshold,
      )
      signatures.append(
          signature_factory.create_from_line_chunk(
              file_parser.get_line_chunk(), url, threshold, tp_level,
          )
      )
    return signatures
