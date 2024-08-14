# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Refiner module to assure no erroneous signatures are exported.

Refiner internally tests given signature candidates against the directly
patched version of the files which must not have any missing patch. If a
signature candidate reports findings from the test, the signature is regarded
as an errorneous one and filtered out.
"""

import abc
import concurrent
import concurrent.futures
import dataclasses
import multiprocessing
import os
from typing import Collection, MutableMapping, Optional, Sequence, Tuple
from absl import logging

from vanir import parser
from vanir import signature
from vanir.code_extractors import code_extractor_base
from pybind11_abseil import status


def _identity(x):
  return x


class BadSignatureAction(abc.ABC):
  """Actions to take when a signature fails refinement."""

  @abc.abstractmethod
  def act(
      self,
      candidate_signatures: Collection[signature.Signature],
      bad_signatures: Collection[signature.Signature],
  ) -> Collection[signature.Signature]:
    """Perform action on candidate signatures and return refined signatures."""


class RemoveBadSignature(BadSignatureAction):
  """Remove the bad signatures from the list of signatures."""

  def act(
      self,
      candidate_signatures: Collection[signature.Signature],
      bad_signatures: Collection[signature.Signature],
  ) -> Collection[signature.Signature]:
    if bad_signatures:
      logging.debug('Signatures removed by refinement: %s', bad_signatures)
    return {sig for sig in candidate_signatures if sig not in bad_signatures}


class MarkAsSpecificToVersions(BadSignatureAction):
  """Mark the bad signatures as specific to the given versions."""

  def __init__(self, versions: Collection[str]):
    self._versions = frozenset(versions)

  def act(
      self,
      candidate_signatures: Collection[signature.Signature],
      bad_signatures: Collection[signature.Signature],
  ) -> Collection[signature.Signature]:
    if bad_signatures:
      logging.debug(
          'Signatures marked specific to %s: %s',
          self._versions, bad_signatures,
      )
    refined_signatures = set()
    for sig in candidate_signatures:
      if sig in bad_signatures:
        refined_signatures.add(
            dataclasses.replace(sig, match_only_versions=self._versions)
        )
      else:
        refined_signatures.add(sig)
    return refined_signatures


class Refiner:
  """Refiner class to assure no erroneous signatures are exported."""

  def __init__(self):
    self._parser_cache: MutableMapping[Tuple[str, str], parser.Parser] = {}
    self._download_cache: MutableMapping[Tuple[str, str], Optional[str]] = {}

  def refine_against_patch_series(
      self,
      candidate_signatures: Collection[signature.Signature],
      commits: Sequence[code_extractor_base.Commit],
      bad_signature_action: BadSignatureAction,
  ) -> Collection[signature.Signature]:
    """Tests signatures against patched files after a series of patches.

    This function tests if each given candidate signatures in
    |candidate_signatures| matches against the "patched" version of files in a
    series of |commits|. This is commonly done so that signatures generated
    from a set of patches are tested against the "patched" version of files in
    the same set of patches, and any signature that matches against the
    "patched" version of the code will only cause false positives and should be
    dropped.

    Args:
      candidate_signatures: the sequence of candidate signatures generated for a
        patch (i.e., signatures for a single commit).
      commits: a list of |Commit| objects of the same package. The order of this
        list should be the same order where those patches are applied to the
        package. Any signature that matches against the final "patched" version
        of files in this list will be flagged.
      bad_signature_action: action to take when a signature fails refinement.

    Returns:
      list of refined signatures that did not match against the final "patched"
      versions of any file in |commits|.
    """
    sig_files = {sig.target_file for sig in candidate_signatures}

    # Get the disk location of each file touched by any commit and the commit
    # url it originated from. If more than one commit touches the same file, the
    # later commit takes precedence.
    commit_files_map = {}
    for commit in commits:
      for target_file, file_path in commit.get_patched_files().items():
        commit_files_map[target_file] = (commit.get_url(), file_path)
    groundtruth_files = {
        (target_file, url, file_path)
        for target_file, (url, file_path) in commit_files_map.items()
    }

    # For files mentioned in any signature but not touched by any commit, get
    # them at the revision of the latest commit in the series.
    last_commit = commits[-1]
    for file in sig_files - set(commit_files_map):
      url = last_commit.get_url()
      if (url, file) not in self._download_cache:
        try:
          local_file = last_commit.get_file_at_rev(file)
        except code_extractor_base.CommitDataFetchError:
          logging.info('%s does not exist at %s', file, url)
          local_file = None
        self._download_cache[(url, file)] = local_file
      if self._download_cache[(url, file)]:
        groundtruth_files.add((file, url, self._download_cache[(url, file)]))

    # See which signatures match against the "patched" version of the files.
    bad_signatures = self._match_against_files(
        candidate_signatures, groundtruth_files
    )
    return bad_signature_action.act(candidate_signatures, bad_signatures)

  def _match_against_files(
      self,
      signatures: Collection[signature.Signature],
      files: Collection[Tuple[str, str, str]],
  ) -> Collection[signature.Signature]:
    """Return signatures that match against the given files."""
    if not files:
      return set()

    # Build a signature bundle from the candidate signatures.
    signature_bundle = signature.SignatureBundle(signatures)
    collisions = signature_bundle.function_signature_hash_collisions()
    if collisions:
      logging.warning('List of signatures with the same digest: %s', collisions)

    # Parse the groundtruth files. This is done in separate subprocesses for
    # performance, and to gracefully handle native parser crashes.
    parser_futures = {}
    with concurrent.futures.ProcessPoolExecutor(
        max_workers=min(len(files), os.cpu_count()),
        mp_context=multiprocessing.get_context('forkserver'),
    ) as executor:
      for target_file, url, file_path in files:
        # Skip files that are not supported by any parser.
        if not parser.is_supported_type(file_path):
          continue
        # This no-op call returns the cached parser if it exists. This is to
        # simplify the code compared to maintaining 2 different lists of files.
        cache_key = (url, target_file)
        if cache_key in self._parser_cache:
          parser_futures[cache_key] = executor.submit(
              _identity, self._parser_cache[cache_key]
          )
        # Otherwise, parse the file.
        else:
          parser_futures[cache_key] = executor.submit(
              parser.Parser, file_path, 'groundtruth_files'
          )

    # See if any signature matched
    matched_signatures = set()
    for cache_key, future in parser_futures.items():
      try:
        file_parser = future.result()
        self._parser_cache[cache_key] = file_parser
      except concurrent.futures.process.BrokenProcessPool:
        logging.error('A worker died unexpectedly while refining %s', cache_key)
        continue
      except status.StatusNotOk as e:
        logging.exception(
            'Failed to parse %s (error: %s). Skipping. ', cache_key, e
        )
        continue
      groundtruth_patched_chunks = []
      groundtruth_patched_chunks += file_parser.get_function_chunks()
      groundtruth_patched_chunks.append(file_parser.get_line_chunk())
      for chunk in groundtruth_patched_chunks:
        matched_signatures.update(signature_bundle.match(chunk))

    return matched_signatures
