# Copyright 2023-2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Commit class for internal Git-on-Borg repos."""

import base64
import functools
import os
import re
from typing import Any, Mapping, Tuple
import unidiff

from vanir.code_extractors import code_extractor_base

from google3.devtools.gerritcodereview.grest_client import base_rest_client
from google3.devtools.gerritcodereview.grest_client import grest_helper
from google3.devtools.gerritcodereview.grest_client import http_provider

COMMIT_HASH_PATTERN = r'[a-f0-9]{40}'


class GobCommit(code_extractor_base.Commit):
  """Commit Class for Git-on-Borg hosted Git commit URLs.

  Internal to Google. This commit class is used to get code from Git-on-Borg
  repos via Gitiles REST APIs.
  """

  _URL_PATTERN = (
      r'https?://(?P<gob_host>[^/.]+)'
      r'(\.googlesource\.com|\.git\.corp\.google\.com)?/'
      r'(?P<project>[^+]+)/\+/'
      r'(?P<revision>[^/]+)/?'
  )

  def __init__(self, url: str, **kwargs):
    del kwargs  # unused
    self._gob_host, self._project, self._revision = self._parse_url(url)
    self._grest_client = grest_helper.GetGrestClient(
        self._gob_host,
        create_http_callable=http_provider.CreateHttpOverRpcConnection,
    )
    super().__init__(url)

  def _normalize_url(self) -> str:
    return (
        f'https://{self._gob_host}.googlesource.com/'
        f'{self._project}/+/{self._revision}'
    )

  @classmethod
  def _parse_url(cls, url) -> Tuple[str, str, str]:
    """Parses a commit URL, returns the host, project, and revision."""
    m = re.fullmatch(cls._URL_PATTERN, url)
    if not m:
      raise code_extractor_base.IncompatibleUrlError(f'Invalid URL: {url}')
    return m.group('gob_host'), m.group('project'), m.group('revision')

  @functools.cached_property
  def _commit_info(self) -> Mapping[str, Any]:
    """Gets commit log from Gerrit."""
    try:
      response = self._grest_client.GetLog(
          project_name=self._project,
          branch_name=self._revision,
          limit=1,
      )
    except (
        base_rest_client.UnexpectedHTTPReturnCode,
        base_rest_client.MalformedJSON,
    ) as e:
      raise code_extractor_base.CommitDataFetchError(
          f'Failed to fetch commit log from {self._gob_host} for project '
          f'{self._project}@{self._revision}. Grest client error: {e}'
      )
    if 'log' not in response or len(response['log']) != 1:
      raise code_extractor_base.CommitDataFetchError(
          f'Failed to fetch commit log from {self._gob_host} for project '
          f'{self._project}@{self._revision}. Invalid grest client '
          f'response": {response}'
      )
    return response['log'][0]

  def _get_commit_field(self, field: str) -> str:
    """Gets commit info from Gerrit."""
    if field not in self._commit_info:
      raise code_extractor_base.CommitDataFetchError(
          f'The log entry for URL: {self.url} does not contain the field'
          f' "{field}". Got log entry: {self._commit_info}'
      )
    return self._commit_info[field]

  @functools.cached_property
  def _parent_commit(self) -> str:
    parents = self._get_commit_field('parents')
    if len(parents) > 1:
      raise code_extractor_base.CommitDataFetchError(
          'Found more than one parent commit in '
          f'{self.url}, looks like a git-merge.'
      )
    return parents[0]

  def _extract_patch(self) -> unidiff.PatchSet:
    try:
      response = self._grest_client.GetGitilesDiff(
          project_name=self._project,
          revision=self._parent_commit,
          other_revision=self._get_commit_field('commit'),
      )
      patch_content = base64.b64decode(bytes(response)).decode('utf-8')
      return unidiff.PatchSet.from_string(patch_content)
    except (
        base_rest_client.UnexpectedHTTPReturnCode,
        base_rest_client.MalformedJSON,
    ) as e:
      raise code_extractor_base.CommitDataFetchError(
          f'Failed to fetch Gitiles diff for URL: {self.url}. Grest client'
          f' error: {e}'
      )

  def _get_file(self, revision: str, path: str) -> str:
    """Downloads content of file at the given revision:path to a temp file."""
    try:
      if re.fullmatch(COMMIT_HASH_PATTERN, revision):
        response = self._grest_client.GetFileContent(
            project_name=self._project,
            commit_id=revision,
            file_id=path,
        )
      else:
        response = self._grest_client.GetFileContent(
            project_name=self._project,
            branch_name=revision,
            file_id=path,
        )
      # Empty file content is returned as None by grest client.
      return self._create_temp_file(
          response if response else b'',
          suffix=f'_{os.path.basename(path)}'
      )
    except (
        base_rest_client.UnexpectedHTTPReturnCode,
        base_rest_client.MalformedJSON,
    ) as e:
      raise code_extractor_base.CommitDataFetchError(
          f'Failed to fetch file content for file {path} at {revision}. '
          f'Grest client error: {e}'
      )

  def _extract_patched_files(self) -> Mapping[str, str]:
    return {
        file.path: self._get_file(self._revision, file.path)
        for file in self._patch.added_files + self._patch.modified_files
    }

  def _extract_unpatched_files(self) -> Mapping[str, str]:
    return {
        file.path: self._get_file(self._parent_commit, file.path)
        for file in self._patch.removed_files + self._patch.modified_files
    }

  def get_file_at_rev(self, file_path: str) -> str:
    """Downloads a file at the commit's revision and returns the local path."""
    return self._get_file(self._revision, file_path)
