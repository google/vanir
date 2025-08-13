# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Common base class for Vanir scanners as well as helper utilities.

A Vanir Scanner is a component that read files from an arbitrary target, parses
source code, checks their likelihood of missing security patches and returns
the analysis result in a structured data format (Findings). There are multiple
classes of scanners, and the scanner you want to use vary depending on the
structure of the target system you want to scan. For instance, if you want to
scan a directory and all files under it against a set of signatures on a local
json file, you should use offline_directory_scanner; if you want to scan
multiple repositories defined in a repo tool's manifest file, you should use
repo_scanner instead.

Each Scanner usually constructs its own set of signatures to use for scanning
based on the scan target, but this can be overriden by passing in a custom
|override_vuln_manager|.

Vanir Scanners are called by Vanir Detectors, which are a top-level components
that directly interacts with end-users, processes user inputs, translates them
into the proper runtime options, runs scanners by following the requested
options and parameters, processes the results returned by scanner, handles
additional requests other than Vanir core scanning and displays result in
various ways that fit to the purpose.

There will be various Detectors and they take input in different ways and also
display result in different ways. For instance, detector_runner is a CLI tool
that allows calling Scanners from the command line, passing command-line
arguments to the Scanner used, and display the analysis result in console log
and various report files. Other Detectors may be added in the future, for
example one that runs as a test target (detector-as-a-test), or a Detector with
a web-based interface.
"""

import abc
import collections
import concurrent
import concurrent.futures
import dataclasses
import multiprocessing
import os
import typing
from typing import Collection, Mapping, Optional, Sequence, Tuple, Union

from absl import logging
from vanir import parser
from vanir import signature
from vanir import vulnerability
from vanir import vulnerability_manager
from vanir import vulnerability_overwriter
from vanir.scanners import target_selection_strategy

Findings = Mapping[
    signature.Signature,
    Sequence[Union[signature.FunctionChunk, signature.LineChunk]],
]

# A package can be either a string corresponding to an OSV package name or a
# |MetaPackage|.
Package = Union[str, vulnerability.MetaPackage]

_DEFAULT_FUNC_LENGTH_THRESHOLD = 100


class FindingsFilter(metaclass=abc.ABCMeta):
  """Abstract class to filter out elements from findings."""

  @abc.abstractmethod
  def filter(self, findings: Findings) -> Findings:
    """Filters out unnecessary elements from |findings|."""


class ShortFunctionFilter(FindingsFilter):
  """Filters out short functions from the findings.

  This filter checks if the normalized string length of each function signature
  exceeds the configured threshold, and filters out its findings if not meet
  the threshold.
  """

  def __init__(self,
               function_length_threshold: int = _DEFAULT_FUNC_LENGTH_THRESHOLD,
               filter_exatct_match: bool = False):
    """Initializes the function signature findings filter.

    Args:
      function_length_threshold: the function signature length threshold. Any
        function signature having length less than this value will be regarded
        as a short function signature and their findings will be filtered out.
      filter_exatct_match: If False, even if a function signature has a length
        shorter than the threshold, if its target file and target function
        exactly matches the file and function name of the chunk, the exactly
        machting (sign, chunk) pair won't be filtered out. If True, the exactly
        matching finding of the short function signature will be filtered out
        just as its other findings.
    """
    self._min_function_length = function_length_threshold
    self._filter_exatct_match = filter_exatct_match

  def filter(self, findings: Findings) -> Findings:
    filtered_findings = {}
    for sign, chunks in findings.items():
      if sign.signature_type != signature.SignatureType.FUNCTION_SIGNATURE:
        filtered_findings[sign] = chunks
        continue
      sign = typing.cast(signature.FunctionSignature, sign)
      if sign.length >= self._min_function_length:
        filtered_findings[sign] = chunks
        continue
      if self._filter_exatct_match:
        # Filter out all findings of this function signature.
        continue
      exact_match_findings = []
      target_file = sign.target_file
      target_function = sign.target_function
      for chunk in chunks:
        chunk = typing.cast(signature.FunctionChunk, chunk)
        if (target_file == chunk.target_file
            and target_function == chunk.base.name):
          exact_match_findings.append(chunk)
      if exact_match_findings:
        filtered_findings[sign] = exact_match_findings
    return filtered_findings


class PathPrefixFilter(FindingsFilter):
  """Removes findings where the scanned file path starts with the prefix."""

  def __init__(self, prefix: str):
    self._prefix = prefix

  def filter(self, findings: Findings) -> Findings:
    filtered_findings = {}
    for sign, chunks in findings.items():
      filtered_findings[sign] = list(
          filter(
              lambda chunk: not chunk.target_file.startswith(self._prefix),
              chunks,
          )
      )
    return filtered_findings


class PackageVersionSpecificSignatureFilter(FindingsFilter):
  """Removes findings from version-specific signatures not matching given versions."""

  def __init__(self, versions: Collection[str]):
    self._package_versions = frozenset(versions)

  def filter(self, findings: Findings) -> Findings:
    filtered_findings = {}
    for sig, chunks in findings.items():
      # If the signature is not version-specific, keep.
      if not sig.match_only_versions:
        filtered_findings[sig] = chunks
        continue
      # If the signature's versions overlay with the package's versions, keep.
      if set(sig.match_only_versions) & self._package_versions:
        filtered_findings[sig] = chunks
        continue
      # If the signature has "X-next" listed and the package's version is newer
      # than X, keep. Note that this versioning scheme is currently only used by
      # Android; there are plans for a more generic approach in the future.
      next_vers = [v for v in sig.match_only_versions if v.endswith('-next')]
      # We are using string comparison for versioning; there is plan to
      # incorporate OSV's SemVer comparison library in the future.
      if (
          next_vers and
          any(ver > min(next_vers) for ver in self._package_versions)
      ):
        filtered_findings[sig] = chunks
      # Otherwise, filter out.
    return filtered_findings


@dataclasses.dataclass(frozen=True)
class ScannedFileStats:
  """Dataclass to contain statistics on files scanned by Detector.

  Attributes:
    analyzed_files: the number of files actually opened and analyzed.
    skipped_files: the number of files skipped because Vanir Detector
      heuristically concluded the files are not affected by any known
      vulnerabilities. Note that this does not include files fundamentally not
      supportted by Vanir (i.e., files with unsupported file types).
    scan_metadata: a Mapping of miscellaneous metadata that a scanner can return
      back to a Detector for logging and informational purpose.
    errors: a list of non-fatal Exceptions encountered while scanning.
  """

  analyzed_files: int
  skipped_files: int
  scan_metadata: Optional[Mapping[str, str]] = None
  errors: Optional[Sequence[Exception]] = None


def _parse_file(
    file_path, code_location
) -> Sequence[Union[signature.FunctionChunk, signature.LineChunk]]:
  """Parse the given file and return all chunks."""
  file_parser = parser.Parser(
      file_path=file_path,
      target_file=os.path.relpath(file_path, code_location))
  chunks = list(file_parser.get_function_chunks())
  chunks.append(file_parser.get_line_chunk())
  return chunks



def scan(
    code_location: str,
    signature_bundle: signature.SignatureBundle,
    strategy: target_selection_strategy.Strategy = (
        target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH
    ),
) -> Tuple[Findings, ScannedFileStats]:
  """Scans the files under the target directory against the given signatures.

  Args:
    code_location: the path to the root directory of the system to conduct
      missing patch scanning against.
    signature_bundle: the SignatureBundle containing signatures to scan against.
    strategy: the target file selection strategy.

  Returns:
    A tuple of findings and scanned file stats. In the findings is a
    dictionary, where each key is a matched signature and its value is a
    sequence of chunks that matched to the signature.
  """
  code_location = os.path.abspath(code_location)
  if not os.path.isdir(code_location):
    raise ValueError(f'Invalid directory: {code_location}')

  to_scan, total_skipped = strategy.get_target_files(
      code_location, signature_bundle
  )
  if not to_scan:
    return {}, ScannedFileStats(0, total_skipped)

  # Parsers are written in C++, which can crash unexpectedly.
  # A multiprocessing.Pool would hangs if that happens. ProcessPoolExecutor
  # can handle this more gracefully. Note that any file that's being processed
  # or not yet processed when a worker dies will also be skipped because the
  # pool is considered "broken" at that point.
  result_futures = []
  with concurrent.futures.ProcessPoolExecutor(
      max_workers=min(len(to_scan), os.cpu_count()),
      mp_context=multiprocessing.get_context('forkserver'),
  ) as executor:
    for file in to_scan:
      result_futures.append(executor.submit(_parse_file, file, code_location))

  concurrent.futures.wait(result_futures)
  findings = collections.defaultdict(list)
  broken_process_files = []
  for file, future in zip(to_scan, result_futures):
    try:
      for chunk in future.result():
        matched_signatures = signature_bundle.match(chunk)
        for matched_sign in matched_signatures:
          if (matched_sign.exact_target_file_match_only
              and chunk.target_file != matched_sign.target_file):
            continue
          findings[matched_sign].append(chunk)
          unpatched_function = getattr(chunk.base, 'name', '')
          logging.debug(
              '%s%s matches signature %s)',
              chunk.target_file,
              '::%s()' % unpatched_function if unpatched_function else '',
              matched_sign.signature_id)
    except concurrent.futures.process.BrokenProcessPool:
      logging.error('A worker died unexpectedly while processing %s', file)
      broken_process_files.append(file)

  error = RuntimeError(
      f'Failed while processing one of: {broken_process_files}. '
      'It is likely that one of the files caused the parser process to crash.'
  )
  stats = ScannedFileStats(
      analyzed_files=len(to_scan) - len(broken_process_files),
      skipped_files=total_skipped + len(broken_process_files),
      errors=[error] if broken_process_files else None,
  )
  return findings, stats


class ScannerBase(abc.ABC):
  """Base class for all Vanir detector scanners.

  Scanner implementations should define their own __init__() which takes in
  any necessary setup arguments.
  """

  @classmethod
  @property
  @abc.abstractmethod
  def name(cls) -> str:
    """Returns the name of this scanner."""

  @abc.abstractmethod
  def scan(
      self,
      strategy: target_selection_strategy.Strategy = (
          target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH
      ),
      override_vuln_manager: Optional[
          vulnerability_manager.VulnerabilityManager
      ] = None,
      extra_vulnerability_filters: Optional[
          Sequence[vulnerability_manager.VulnerabilityFilter]
      ] = None,
      vulnerability_overwrite_specs: Optional[
          Sequence[vulnerability_overwriter.OverwriteSpec]
      ] = None,
  ) -> Tuple[
      Findings, ScannedFileStats, vulnerability_manager.VulnerabilityManager
  ]:
    """Run the scan and returns findings and stats.

    Args:
      strategy: defines target selection strategy for the scanner. If
        |EXACT_PATH_MATCH|, scan only files matching the target path specified
        in the signatures. If |ALL_FILES|, scan all files found in scan
        location. If |TRUNCATED_PATH_MATCH|, scan potentially affected files
        identified by Truncated Path algorithm for signatures with known
        truncated path level; for signatures w/o known truncated path level, the
        |TRUNCATED_PATH_MATCH| uses |EXACT_PATH_MATCH| as a fallback. Please see
        truncated_path module for more details.
      override_vuln_manager: Optional |VulnerabilityManager| to be used for
        scanning. If given, this vuln manager will be used instead of any vuln
        manager created/managed by the scanner.
      extra_vulnerability_filters: Optional list of |VulnerabilityFilter| to be
        applied onto any |VulnerabilityManager| used. This is in addition to any
        filter already generated internally by the scanner or already applied to
        the given override_vuln_manager.
      vulnerability_overwrite_specs: Optional list of |OverwriteSpec| to
        be applied onto |VulnerabilityManager| created for OSV signatures if a
        manager wasn't provided in |override_vuln_manager|.

    Returns:
      A tuple of |Findings|, |ScannedFileStats|, and the |VulnerabilityManager|
        used in the scan. Note that this |VulnerabilityManager| is the final
        manager used in the scan and incorporated all the vulnerability filters
        including the extra given ones. This is returned mainly so that the
        caller can collect statistics and reports on vulnerability coverage.
    """
