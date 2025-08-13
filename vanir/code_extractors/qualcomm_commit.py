# Copyright 2023-2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Commit class for Qualcomm Code Aurora and Code Linaro patches."""

import functools
import json
import logging
import os
import re
from typing import Any, Optional, Mapping, Union
import urllib

import requests
import unidiff
from vanir.code_extractors import code_extractor_base

HTTP_PREFIX_PATTERN = r'^https?://'


class QualcommCommit(code_extractor_base.Commit):
  """Commit Class for commit URLs pointing Qualcomm repos (Code Linaro).

  This commit class is mainly for supporting Qualcomm-specific Android patches
  available in Code Linaro. This class also supports commit URLs pointing Code
  Aurora QUIC, which is a legacy Qualcomm repo. Since repos in Code Aurora QUIC
  are deprecated and are migrated to Code Linaro, when a Code Aurora URL is
  given, this class transparently converts the URL to the corresponding Code
  Linaro URL ane pulls actual patches and files from the Code Linaro.

  This commit class can take an optional requests_session object in its
  constructor, which will be used instead of the default Session that requests
  uses, e.g. for proxying HTTP requests through firewalls, or for testing.
  """

  code_linaro_repo_prefix = 'git.codelinaro.org/clo'
  code_aurora_quic_repo_prefix = 'source.codeaurora.org/quic'

  def __init__(
      self,
      url: str,
      *,
      requests_session: Optional[requests.Session] = None,
      **kwargs
  ):
    self._session = requests_session or requests.Session()
    super().__init__(url, **kwargs)

  def _normalize_url(self) -> str:
    schemeless_url = re.sub(HTTP_PREFIX_PATTERN, '', self._original_url)
    if schemeless_url.startswith(self.code_aurora_quic_repo_prefix):
      normal_url = self._convert_aurora_to_linaro(self._original_url)
      logging.info(
          'Converted Code Aurora URL %s to Code Linaro URL %s',
          self._original_url, normal_url,
      )
      return normal_url
    elif schemeless_url.startswith(self.code_linaro_repo_prefix):
      # Linaro URL may contain redundant subdirectory expression '/-/'.
      return self._original_url.replace('/-/', '/')
    else:
      raise code_extractor_base.IncompatibleUrlError(
          f'Bad URL: {self._original_url}'
      )

  @classmethod
  def _convert_aurora_to_linaro(cls, aurora_url: str) -> str:
    """Converts Code Aurora URL to Code Linaro URL.

    The following shows the patterns of Code Aurora and Code Linaro commit URLs:
      - Code Aurora QUIC:
        https://source.codeaurora.org/quic/$REPO_NAME/commit/?id=$COMMIT_HASH
      - Code Linaro:
        https://git.codelinaro.org/clo/$REPO_NAME/commit/$COMMIT_HASH

    Args:
      aurora_url: Code Aurora commit URL.

    Returns:
      Code Linaro commit URL corresponding to the given Code Aurora commit URL.
    """
    
    # Repos in 'quic/le' are migrated to project group 'la'.
    url = aurora_url.replace(cls.code_aurora_quic_repo_prefix + '/le/',
                             cls.code_aurora_quic_repo_prefix + '/la/')
    url = url.replace(cls.code_aurora_quic_repo_prefix,
                      cls.code_linaro_repo_prefix)
    url_prefix, url_commit_suffix = url.split('/commit')
    match = re.search('id=[a-f0-9]{7,40}', url_commit_suffix)
    if match is None:
      raise code_extractor_base.IncompatibleUrlError(
          'Invalid Code Aurora commit URL: %s' % aurora_url
      )
    commit_hash = match.group().replace('id=', '')
    return '/'.join([url_prefix, 'commit', commit_hash])

  def _get_text(self, url: str) -> Union[bytes, str]:
    """Gets plain text from |url|.

    Code Linaro do not encode text pages, thus this method simply wraps
    requests.get() call.

    Args:
      url: general URL string for get request.

    Returns:
      Plain text string fetched from the |url|.
    Raises:
      CommitDataFetchError: when fails to fetch text from the |url|.
    """
    try:
      response = self._session.get(url)
      response.raise_for_status()
    except (
        requests.RequestException,
        ValueError,
    ) as e:
      raise code_extractor_base.CommitDataFetchError(
          'Failed to fetch valid commit data from %s' % url) from e
    return response.text

  @functools.cached_property
  def _commit_info(self) -> Mapping[str, Any]:
    """Retrieves commit info through Linaro REST API for commit info."""
    path_with_namespace, url_commit_suffix = re.sub(
        'http[s]*://git.codelinaro.org/', '', self.url).split('/commit/')
    path_with_namespace = urllib.parse.quote(path_with_namespace, safe='')
    match = re.search('[a-f0-9]{7,40}', url_commit_suffix)
    if match is None:
      raise ValueError('Invalid Code Linaro commit URL: %s' % self.url)
    commit_hash = match.group()
    api_format = ('https://git.codelinaro.org/api/v4/projects/%s/repository/'
                  'commits/%s')
    commit_info_api = api_format % (path_with_namespace, commit_hash)
    commit_info = json.loads(self._get_text(commit_info_api))
    if 'id' not in commit_info:
      raise code_extractor_base.CommitDataFetchError(
          'Failed to get valid commit info for URL: %s (received: %s)'
          % (self.url, commit_info))
    return commit_info

  @property
  def _parent_commit(self) -> str:
    parent_commit_hashes = self._commit_info.get('parent_ids', None)
    if not parent_commit_hashes:
      raise code_extractor_base.CommitDataFetchError(
          'Failed to find parent commit for %s' % self.url)
    if len(parent_commit_hashes) > 1:
      raise code_extractor_base.CommitDataFetchError(
          'git-merge commit: %s' % self.url)
    return parent_commit_hashes[0]

  def _extract_patch(self) -> unidiff.PatchSet:
    """Extracts the patch for the commit."""
    logging.info('Retrieving patch source: %s', self.url)
    patch_url = self.url + '.diff'
    raw_patch = self._get_text(patch_url)
    patch = unidiff.PatchSet.from_string(raw_patch)
    if not patch:
      raise code_extractor_base.CommitDataFetchError(
          'Patch for this commit is invalid. Source: %s' % patch_url)
    return patch

  def _extract_patched_files(self) -> Mapping[str, str]:
    """Extracts patched files affected by the commit.

    Returns:
      A file path map where a key is a relative path of the target file in the
      target source tree and the value is the absoulte path to the extracted
      patched version of the file.
    """
    # Removed files are not included since they do not exist in the child.
    patched_file_paths = [
        file.path
        for file in self._patch.added_files + self._patch.modified_files
    ]
    logging.info('Retrieving patched file source: %s', self.url)
    patched_files = {}
    for file_path in patched_file_paths:
      patched_file_url = ''.join(
          [self.url.replace('commit', 'raw'), '/', file_path])
      patched_files[file_path] = self._create_temp_file(
          self._get_text(patched_file_url),
          suffix=f'_{os.path.basename(file_path)}',
      )
    return patched_files

  def _extract_unpatched_files(self) -> Mapping[str, str]:
    """Extracts unpatched files affected by the commit.

    Returns:
      A file path map where a key is a relative path of the target file in the
      target source tree and the value is the absoulte path to the extracted
      unpatched version of the file.

    Raises:
      CommitDataFetchError: when failed to fetch unpatched files for the commit.
    """
    # Added files are not included since they do not exist in the parent.
    unpatched_file_paths = [
        file.path
        for file in self._patch.removed_files + self._patch.modified_files
    ]
    base_url = self.url.rstrip('/').rsplit('/', 1)[0] + '/'
    logging.info('Retrieving unpatched file source: %s', self.url)
    unpatched_files = {}
    for file_path in unpatched_file_paths:
      unpatched_file_url = ''.join([
          base_url.replace('commit', 'raw'), self._parent_commit, '/', file_path
      ])
      unpatched_files[file_path] = self._create_temp_file(
          self._get_text(unpatched_file_url),
          suffix=f'_{os.path.basename(file_path)}',
      )
    return unpatched_files

  def get_file_at_rev(self, file_path: str) -> str:
    file_url = ''.join([self.url.replace('commit', 'raw'), '/', file_path])
    tempfile = self._create_temp_file(
        self._get_text(file_url),
        suffix=f'_{os.path.basename(file_path)}',
    )
    return tempfile
