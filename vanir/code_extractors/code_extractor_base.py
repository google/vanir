# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Base interface and data types for code extractors.

A code extractor for an OSV ecosystem will need to implement the Commit and
CodeExtractor abstract classes.
"""

import abc
import dataclasses
import tempfile
from typing import Collection, Mapping, Optional, Sequence, Tuple, Union

import unidiff
from vanir import vulnerability


class CommitDataFetchError(Exception):
  """An error that is raised when failed to fetch commit data from the Web."""


class IncompatibleUrlError(ValueError):
  """An error when the given URL does not conform with known URL patterns."""


class Commit(metaclass=abc.ABCMeta):
  """Class to extract commit files/patches/messages for the given commit URL."""

  def __init__(self, url: str, **kwargs):
    """Sets up a commit object for the given |url| address.

    Args:
      url: URL of a commit.
      **kwargs: additional arguments to pass to the Commit objects' constructor.

    Raises:
      IncompatibleUrlError: when the given URL is pointing a source repo
        incompatible with the current Commit class. Note that the URL may be
        compatible with other Commit classes.
      CommitDataFetchError: when fails to extract valid commit data from |url|.
      ValueError: when the given URL is pointing a compatible source repo but
        malformatted.
    """
    del kwargs  # Unused.
    # self._working_dir is used to store all files created by _create_temp_file.
    # It will be deleted when the object is destroyed.
    self._working_dir = tempfile.TemporaryDirectory()
    self._original_url = url
    self._url = self._normalize_url()
    self._patch = self._extract_patch()
    self._affected_line_ranges = self._compute_affected_line_ranges()
    self._patched_files = self._extract_patched_files()
    self._unpatched_files = self._extract_unpatched_files()

  def _create_temp_file(
      self, file_content: Union[bytes, str], suffix: Optional[str] = None
  ) -> str:
    """Creates a temporary file and write |file_content| into it.

    Args:
      file_content: file content to be written to the temporary file.
      suffix: suffix of the temporary file.

    Returns:
      Path to the temporary file.
    """
    mode = 'wb' if isinstance(file_content, bytes) else 'wt'
    with tempfile.NamedTemporaryFile(
        delete=False, suffix=suffix, mode=mode, dir=self._working_dir.name,
    ) as f:
      f.write(file_content)
      return f.name

  @abc.abstractmethod
  def _extract_patch(self) -> unidiff.PatchSet:
    """Extracts a |unidiff.PatchSet| object corresponding to this commit."""

  @abc.abstractmethod
  def _extract_patched_files(self) -> Mapping[str, str]:
    """Extracts patched files affected by the commit.

    Returns:
      A file path map where a key is a relative path of the target file in the
      target source tree and the value is the absoulte path to the extracted
      patched version of the file.
    """

  @abc.abstractmethod
  def _extract_unpatched_files(self) -> Mapping[str, str]:
    """Extracts unpatched files affected by the commit.

    Returns:
      A file path map where a key is a relative path of the target file in the
      target source tree and the value is the absoulte path to the extracted
      unpatched version of the file.
    """

  @abc.abstractmethod
  def _normalize_url(self) -> str:
    """Validates the URL in self._original_url and returns the normalized URL."""

  @property
  def url(self) -> str:
    """Returns the normalized registered commit URL."""
    return self._url

  @property
  def original_url(self) -> str:
    """Returns the original commit URL."""
    return self._original_url

  def _compute_affected_line_ranges(
      self
  ) -> Mapping[str, Sequence[Tuple[int, int]]]:
    """Returns a dictionary of affected line ranges for each file."""
    all_affected_lines = {}
    for patched_file in self._patch:
      affected_lines = []
      for hunk in patched_file:
        # The number of context lines can differ based on diff config, so
        # we don't rely on the context info provided by hunk. We calculate
        # start and stop lines ourselves.
        start: int
        stop: int
        # A non-context line is either an added line or a removed line.
        non_context_lines = [line for line in hunk if not line.is_context]
        first_change = non_context_lines[0]
        last_change = non_context_lines[-1]

        # Compute the affected line start.
        if first_change.is_removed:
          start = first_change.source_line_no
        else:
          # Index of the line just before the first changed line.
          context_line_index = hunk.index(first_change) - 1
          if context_line_index < 0:  # Even no context.
            start = hunk.source_start
          else:
            start = hunk[context_line_index].source_line_no

        # Compute the affected line stop.
        if last_change.is_removed:
          stop = last_change.source_line_no
        else:
          # Index of the line just after the last changed line.
          context_line_index = hunk.index(last_change) + 1
          if context_line_index >= len(hunk):  # Even no context.
            # Source length can be 0 when context is 0 & no added line exists.
            stop = (
                hunk.source_start + hunk.source_length - 1
                if hunk.source_length else hunk.source_start)
          else:
            stop = hunk[context_line_index].source_line_no - 1
        # When no context line is provided, start can be greater than stop
        # Adjust the range in this case to contain at least 1 line.
        if start > stop:
          stop = start

        affected_lines.append((start, stop))
      all_affected_lines[patched_file.path] = affected_lines
    return all_affected_lines

  def get_affected_line_ranges(
      self, file_path: str
  ) -> Sequence[Tuple[int, int]]:
    """Returns a list of ranges of lines affected by this patch for the file.

    Each affected range starts from the first line changed in the hunk and ends
    at the last line changed in the hunk. All line numbers are based on the
    unpatched versions of the target files. For added lines, since they do not
    have line numbers in the unpatched version of the file, the line numbers
    of their surrounding context lines are used.

    Args:
      file_path: relative path to the file in the original code base. E.g.,
        'fs/ext4/file.c'

    Returns:
      The list of ranges that include all affected lines. If the file is not
      affected by this commit, returns an empty list.
    """
    return self._affected_line_ranges.get(file_path, [])

  @property
  def patched_files(self) -> Mapping[str, str]:
    """Returns modified version of the files patched by the given commit.

    Returns:
      A dictionary with each original file path in the target source tree as a
      key and its corresponding temporary file path as the value.
    """
    return self._patched_files

  @property
  def unpatched_files(self) -> Mapping[str, str]:
    """Returns unmodified version of the files patched by the given commit.

    Returns:
      A dictionary with each original file path in the target source tree as a
      key and its corresponding temporary file path as the value.
    """
    return self._unpatched_files

  @abc.abstractmethod
  def get_file_at_rev(self, file_path: str) -> str:
    """Downloads a file at the commit's revision and returns the local path.

    Args:
      file_path: path to file in source control system.

    Returns:
      Local path to the temp file.
    """


@dataclasses.dataclass(frozen=True)
class FailedCommitUrl:
  """Dataclass to inform a commit URL caused error during commit extraction."""
  url: str
  error: Exception


class AbstractCodeExtractor(abc.ABC):
  """Retrieves corresponding patch files for the given affected package.

  For each commit, this class extracts the following data:
  1. commit message
  2. per-file patch (diff)
  3. unmodified & modified versions of the files changed by the patch
  """

  @classmethod
  @abc.abstractmethod
  def is_supported_ecosystem(cls, ecosystem: str) -> bool:
    """Returns whether the given ecosystem is supported by this extractor."""

  @abc.abstractmethod
  def extract_commits_for_affected_entry(
      self, affected: vulnerability.AffectedEntry, **kwargs,
  ) -> Tuple[Sequence[Commit], Sequence[FailedCommitUrl]]:
    """For the given package of the given CVE, download the unpatched files.

    Args:
      affected: the Affected object to extract fix commits from, in the OSV CVE
        dictionary format
      **kwargs: additional arguments to pass to the Commit objects' constructor.

    Returns:
      A tuple where the first item is the list of |Commit| objects pertaining
      to that affected package in the given |cve|, and the second item is the
      list of URLs found but failed to convert to |Commit| objects.
    Raises:
      ValueError: raise ValueError when the given |cve| is mal-formatted.
    """

  @abc.abstractmethod
  def extract_files_at_tip_of_unaffected_versions(
      self,
      package_name: str,
      versions: Sequence[str],
      files: Collection[str],
      **kwargs,
  ) -> Tuple[Sequence[Commit], Sequence[FailedCommitUrl]]:
    """Extracts files tip of unaffected versions of the given package.

    This method checks the list of given versions and determine the active tips
    of branches that are not mentioned in the list and extract the listed files
    at the those tips.

    Args:
      package_name: the name of the package.
      versions: the list of versions of the package. Tip of versions not in this
        list will be extracted.
      files: the list of files to include.
      **kwargs: additional arguments to pass to the Commit objects' constructor.

    Returns:
      A tuple where the first item is the list of |Commit| objects pertaining
      to the tip of a version not mentioned in |versions|, and the second item
      is the list of tip URLs failed to convert to |Commit| objects.
    """
