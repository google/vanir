# Copyright 2023-2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Commit class for patches on Gitiles."""

import base64
import functools
import logging
import os
import re
from typing import Optional, Mapping, Union

import requests
import unidiff
from vanir.code_extractors import code_extractor_base

COMMIT_HASH_PATTERN = r'[a-f0-9]{40}'

_ENCODINGS = ['UTF-8', 'LATIN-1']


class GitilesCommit(code_extractor_base.Commit):
  """Commit Class for Gitiles commit URLs.

  This commit class uses HTTP to download patches and files from Gitiles.

  This commit class can take an optional requests_session object in its
  constructor, which will be used instead of the default Session that requests
  uses, e.g. for proxying HTTP requests through firewalls, or for testing.
  """

  
  _KNOWN_GITILES_HOSTS = ('android.googlesource.com',)

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
    if not re.sub(r'^https?://', '', self._original_url).startswith(
        self._KNOWN_GITILES_HOSTS
    ):
      raise code_extractor_base.IncompatibleUrlError(
          f'Unknown URL: {self._original_url}'
      )
    return self._original_url

  @functools.cached_property
  def _parent_commit(self) -> str:
    commit_message = self._get_text(self.url)
    matches = re.findall(
        r'(?:\n|^)(?:parent )(' + COMMIT_HASH_PATTERN + r')(?=\n|$)',
        commit_message)
    if not matches:
      raise code_extractor_base.CommitDataFetchError(
          'Failed to find parent from the commit message for commit '
          f'{self.url}: {commit_message}')
    if len(matches) > 1:
      raise code_extractor_base.CommitDataFetchError(
          'Found more than one parent commit in the commit message for commit '
          f'{self.url}, looks like a git-merge: {commit_message}')
    return matches[0]

  def _get_text(self, url: str, raw: bool = False) -> Union[bytes, str]:
    """Gets plain text object mapped to |url|.

    Args:
      url: the URL for the commit object including patch, file and commit
        messages.
      raw: whether to return the raw text without trying to decode it.

    Returns:
      UTF-8 encoded string fetched from the |url|.
    Raises:
      CommitDataFetchError: when fails to fetch object from the |url| or the
        fails to decode fetched object to plain text.
    """
    url += '?format=TEXT'
    encoding_error_max_retrials = 2
    encoding_trial_list = []
    for encoding in _ENCODINGS:
      for _ in range(encoding_error_max_retrials):
        encoding_trial_list.append(encoding)
    for encoding in encoding_trial_list:
      try:
        response = self._session.get(url)
        response.raise_for_status()
        response_text = base64.b64decode(response.text)
        if raw:
          return response_text
        return response_text.decode(encoding)
      except (requests.RequestException, ValueError):
        continue  # Retry as long as there is next trial candidate.
    raise code_extractor_base.CommitDataFetchError(
        'Failed to fetch valid commit data from %s' % url
    )

  def _extract_patch(self) -> unidiff.PatchSet:
    """Extracts |unidiff.PatchSet| corresponding to this Gitiles commit.

    Raises:
      ValueError: when the downloaded fetch text is malformatted or empty.
      CommitDataFetchError: when fails to extract valid patch text from the web.
    Returns:
      PatchSet object wrapping the extracted patch.
    """
    logging.info('Retrieving patch source: %s', self.url)
    patch_url = self.url + '^!'
    raw_patch = self._get_text(patch_url)
    patch = unidiff.PatchSet.from_string(raw_patch)
    if not patch:
      raise code_extractor_base.CommitDataFetchError(
          'Patch for this commit is invalid. Source: %s' % patch_url)
    return patch

  def _extract_patched_files(self) -> Mapping[str, str]:
    """Extracts patched files affected by the commit.

    Raises:
      CommitDataFetchError: when fails to extract valid patched files from the
      web.
    Returns:
      A file path map where a key is a relative path of the target file in the
      target source tree and the value is the absoulte path to the extracted
      patched version of the file.
    """
    logging.info('Retrieving patched file source: %s', self.url)
    return {
        file.path: self.get_file_at_rev(file.path)
        for file in self._patch.added_files + self._patch.modified_files
        # Gitiles has a bug and cannot serve raw markdown files; exclude them
        if not file.path.endswith('.md')
    }

  def _extract_unpatched_files(self) -> Mapping[str, str]:
    """Extracts unpatched files affected by the commit.

    Raises:
      ValueError: when fails to extract parent commit of this commit.
      CommitDataFetchError: when fails to extract valid unpatched files from the
      web.
    Returns:
      A file path map where a key is a relative path of the target file in the
      target source tree and the value is the absoulte path to the extracted
      unpatched version of the file.
    """
    # Added files are not included since they do not exist in the parent.
    unpatched_file_paths = [
        file.path
        for file in self._patch.removed_files + self._patch.modified_files
        # Gitiles has a bug and cannot serve raw markdown files; exclude them
        if not file.path.endswith('.md')
    ]
    base_url = self.url.rstrip('/').rsplit('/', 1)[0] + '/'
    logging.info('Retrieving unpatched file source: %s', self.url)
    unpatched_files = {}
    for file_path in unpatched_file_paths:
      unpatched_file_url = ''.join(
          [base_url, self._parent_commit, '/', file_path])
      unpatched_files[file_path] = self._create_temp_file(
          self._get_text(unpatched_file_url, raw=True),
          suffix=f'_{os.path.basename(file_path)}',
      )
    return unpatched_files

  def get_file_at_rev(self, file_path: str) -> str:
    file_url = ''.join([self.url, '/', file_path])
    tempfile = self._create_temp_file(
        self._get_text(file_url, raw=True),
        suffix=f'_{os.path.basename(file_path)}',
    )
    return tempfile
