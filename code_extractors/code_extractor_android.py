# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Code extractors for Android ecosystem packages of OSV CVEs.
"""

import base64
import functools
import json
import logging
import os
import re
from typing import Any, Collection, FrozenSet, Mapping, Optional, Sequence, Tuple
import urllib

import requests
import unidiff
from vanir import vulnerability
from vanir.code_extractors import code_extractor_base

HTTP_PREFIX = 'http://'
HTTPS_PREFIX = 'https://'

AFFECTED_ECOSYSTEM_SPECIFIC = 'ecosystem_specific'
ECOSYSTEM_SPECIFIC_FIXES = 'fixes'
COMMIT_HASH_PATTERN = r'[a-f0-9]{40}'

_ENCODINGS = ['UTF-8', 'LATIN-1']


class AndroidCommit(code_extractor_base.Commit):
  """Commit Class for Android Google Git commit URLs."""

  android_repo_prefix = 'android.googlesource.com'
  android_repo_commit_patch_postfix = '^!'
  android_repo_text_postfix = '?format=TEXT'

  def _normalize_url(self, url: str) -> str:
    if not url.replace(HTTP_PREFIX, '').replace(HTTPS_PREFIX, '').startswith(
        self.android_repo_prefix):
      raise code_extractor_base.IncompatibleUrlError(
          'Not Android Google Git commit URL: %s' % url)
    return url

  def _extract_commit_hash(self) -> str:
    commit_hash = self._url.rstrip('/').split('/')[-1]
    if re.fullmatch(COMMIT_HASH_PATTERN, commit_hash) is None:
      # Some Android-specific commit URLs have short commit hashes. Extract full
      # commit hash from the html page.
      android_commit_hash_pattern = ''.join(
          [commit_hash, r'[a-f0-9]{',
           str(40 - len(commit_hash)), r'}'])
      commit_html_page = self._session.get(self._url)
      if not commit_html_page.ok:
        raise code_extractor_base.CommitDataFetchError(
            'Failed to fetch web page from URL: %s' % self._url)
      match = re.search(android_commit_hash_pattern, commit_html_page.text)
      if match is None:
        raise code_extractor_base.CommitDataFetchError(
            'Failed to extract full commit hash from URL: %s' % self._url)
      commit_hash = match.group()
    return commit_hash

  def _extract_parent_commit(self) -> str:
    commit_message = self._get_text(self._url)
    matches = re.findall(
        r'(?:\n|^)(?:parent )(' + COMMIT_HASH_PATTERN + r')(?=\n|$)',
        commit_message)
    if not matches:
      raise code_extractor_base.CommitDataFetchError(
          'Failed to find parent from the commit message for commit '
          f'{self._url}: {commit_message}')
    if len(matches) > 1:
      raise code_extractor_base.CommitDataFetchError(
          'Found more than one parent commit in the commit message for commit '
          f'{self._url}, looks like a git-merge: {commit_message}')
    return matches[0]

  def _get_text(self, url: str) -> str:
    """Gets plain text object mapped to |url|.

    Args:
      url: the URL for the commit object including patch, file and commit
        messages.

    Returns:
      UTF-8 encoded string fetched from the |url|.
    Raises:
      CommitDataFetchError: when fails to fetch object from the |url| or the
        fails to decode fetched object to plain text.
    """
    url += self.android_repo_text_postfix
    encoding_error_max_retrials = 2
    encoding_trial_list = []
    for encoding in _ENCODINGS:
      for _ in range(encoding_error_max_retrials):
        encoding_trial_list.append(encoding)
    for encoding in encoding_trial_list:
      try:
        response = self._session.get(url)
        response.raise_for_status()
        decoded_text = base64.b64decode(response.text).decode(encoding)
        return decoded_text
      except (requests.RequestException, ValueError):
        continue  # Retry as long as there is next trial candidate.
    raise code_extractor_base.CommitDataFetchError(
        'Failed to fetch valid commit data from %s' % url
    )

  def _extract_patch(self) -> unidiff.PatchSet:
    """Extracts patch for the commit from the Android Google Git.

    Raises:
      ValueError: when the downloaded fetch text is malformatted or empty.
      CommitDataFetchError: when fails to extract valid patch text from the web.
    Returns:
      PatchSet object wrapping the extracted patch.
    """
    logging.info('Retrieving patch source: %s', self._url)
    patch_url = self._url + self.android_repo_commit_patch_postfix
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
    # Removed files are not included since they do not exist in the child.
    patched_file_paths = [
        file.path
        for file in self._patch.added_files + self._patch.modified_files
        # Gitiles has a bug and cannot serve raw markdown files; exclude them
        if not file.path.endswith('.md')
    ]
    logging.info('Retrieving patched file source: %s', self._url)
    patched_files = {}
    for file_path in patched_file_paths:
      patched_file_url = ''.join([self._url, '/', file_path])
      patched_files[file_path] = self._create_temp_file(
          self._get_text(patched_file_url),
          suffix=f'_{os.path.basename(file_path)}',
      )
    return patched_files

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
    base_url = self._url.rstrip('/').rstrip(self._commit_hash)
    logging.info('Retrieving unpatched file source: %s', self._url)
    unpatched_files = {}
    for file_path in unpatched_file_paths:
      unpatched_file_url = ''.join(
          [base_url, self._parent_commit, '/', file_path])
      unpatched_files[file_path] = self._create_temp_file(
          self._get_text(unpatched_file_url),
          suffix=f'_{os.path.basename(file_path)}',
      )
    return unpatched_files

  def get_file_at_rev(self, file_path: str) -> str:
    file_url = ''.join([self._url, '/', file_path])
    tempfile = self._create_temp_file(
        self._get_text(file_url),
        suffix=f'_{os.path.basename(file_path)}',
    )
    return tempfile


class QualcommCommit(code_extractor_base.Commit):
  """Commit Class for commit URLs pointing Qualcomm repos (Code Linaro).

  This commit class is mainly for supporting Qualcomm-specific Android patches
  available in Code Linaro. This class also supports commit URLs pointing Code
  Aurora QUIC, which is a legacy Qualcomm repo. Since repos in Code Aurora QUIC
  are deprecated and are migrated to Code Linaro, when a Code Aurora URL is
  given, this class transparently converts the URL to the corresponding Code
  Linaro URL ane pulls actual patches and files from the Code Linaro.
  """

  code_linaro_repo_prefix = 'git.codelinaro.org/clo'
  code_aurora_quic_repo_prefix = 'source.codeaurora.org/quic'

  def __init__(self, url: str, session: requests.sessions.Session):
    self._commit_info = None
    super().__init__(url, session)

  def _normalize_url(self, url: str) -> str:
    schemeless_url = url.replace(HTTP_PREFIX, '').replace(HTTPS_PREFIX, '')
    if schemeless_url.startswith(self.code_aurora_quic_repo_prefix):
      normal_url = self._convert_aurora_to_linaro(url)
      logging.info('Converted Code Aurora URL %s '
                   'to Code Linaro URL %s.', url, normal_url)
      return normal_url
    elif schemeless_url.startswith(self.code_linaro_repo_prefix):
      # Linaro URL may contain redundant subdirectory expression '/-/'.
      return url.replace('/-/', '/')
    else:
      raise code_extractor_base.IncompatibleUrlError(
          'Not Qualcomm commit URL: %s' % url)

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
      raise ValueError('Invalid Code Aurora commit URL: %s' % aurora_url)
    commit_hash = match.group().replace('id=', '')
    return '/'.join([url_prefix, 'commit', commit_hash])

  def _get_text(self, url: str) -> str:
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
    except (requests.RequestException, ValueError) as e:
      raise code_extractor_base.CommitDataFetchError(
          'Failed to fetch valid commit data from %s' % url) from e
    return response.text

  def _extract_commit_hash(self) -> str:
    """Extracts the full commit hash."""
    commit_info = self._get_commit_info()
    return commit_info['id']

  def _get_commit_info(self) -> Mapping[str, Any]:
    """Retrieves commit info through Linaro REST API for commit info."""
    if not self._commit_info:
      path_with_namespace, url_commit_suffix = re.sub(
          'http[s]*://git.codelinaro.org/', '', self._url).split('/commit/')
      path_with_namespace = urllib.parse.quote(path_with_namespace, safe='')
      match = re.search('[a-f0-9]{7,40}', url_commit_suffix)
      if match is None:
        raise ValueError('Invalid Code Linaro commit URL: %s' % self._url)
      commit_hash = match.group()
      api_format = ('https://git.codelinaro.org/api/v4/projects/%s/repository/'
                    'commits/%s')
      commit_info_api = api_format % (path_with_namespace, commit_hash)
      commit_info = json.loads(self._get_text(commit_info_api))
      if 'id' not in commit_info:
        raise code_extractor_base.CommitDataFetchError(
            'Failed to get valid commit info for URL: %s (received: %s)'
            % (self._url, commit_info))
      self._commit_info = commit_info
    return self._commit_info

  def _extract_parent_commit(self) -> str:
    parent_commit_hashes = self._get_commit_info().get('parent_ids', None)
    if not parent_commit_hashes:
      raise code_extractor_base.CommitDataFetchError(
          'Failed to find parent commit for %s' % self._url)
    if len(parent_commit_hashes) > 1:
      raise code_extractor_base.CommitDataFetchError(
          'git-merge commit: %s' % self._url)
    return parent_commit_hashes[0]

  def _extract_patch(self) -> unidiff.PatchSet:
    """Extracts the patch for the commit."""
    logging.info('Retrieving patch source: %s', self._url)
    patch_url = self._url + '.diff'
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
    logging.info('Retrieving patched file source: %s', self._url)
    patched_files = {}
    for file_path in patched_file_paths:
      patched_file_url = ''.join(
          [self._url.replace('commit', 'raw'), '/', file_path])
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
    base_url = self._url.rstrip('/').rstrip(self._commit_hash)
    logging.info('Retrieving unpatched file source: %s', self._url)
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
    file_url = ''.join([self._url.replace('commit', 'raw'), '/', file_path])
    tempfile = self._create_temp_file(
        self._get_text(file_url),
        suffix=f'_{os.path.basename(file_path)}',
    )
    return tempfile


class AndroidTipOfBranchCommit(AndroidCommit):
  """Commit class that only supports getting files at tip of an AOSP branch."""

  def __init__(
      self,
      project: str,
      branch: str,
      files: Collection[str],
      session: requests.sessions.Session
  ):
    self._project = project
    self._branch = branch
    self._files = files
    self._session = session

    url = f'{HTTPS_PREFIX}{self.android_repo_prefix}/{project}/+/{branch}'
    self._extract_commit_hash = lambda: None
    self._extract_parent_commit = lambda: None
    self._extract_patch = lambda: None
    self._extract_unpatched_files = lambda: {}
    super().__init__(url, session)

  def _extract_patched_files(self) -> Mapping[str, str]:
    tip_files = {}
    for file in self._files:
      try:
        tip_files[file] = self._create_temp_file(
            self._get_text(f'{self._url}/{file}'),
            suffix=f'_{os.path.basename(file)}',
        )
      except code_extractor_base.CommitDataFetchError:
        logging.debug('File %s does not exist on tip of %s', file, self._branch)
    return tip_files

  def get_commit_hash(self, length: Optional[int] = None) -> str:
    raise NotImplementedError

  def get_patch(self) -> unidiff.PatchSet:
    raise NotImplementedError

  def get_affected_line_ranges(
      self, file_path: str,
  ) -> Sequence[Tuple[int, int]]:
    raise NotImplementedError

  def get_unpatched_files(self) -> Mapping[str, str]:
    raise NotImplementedError


@functools.cache
def _get_commit_at_tip(
    project: str,
    branch: str,
    files: FrozenSet[str],
    session: requests.sessions.Session,
) -> AndroidTipOfBranchCommit:
  """Gets AndroidTipOfBranchCommit for given files at tip of an AOSP branch."""
  return AndroidTipOfBranchCommit(project, branch, files, session)


def _get_android_fix_urls(
    affected: vulnerability.AffectedEntry
) -> Sequence[str]:
  """Extract all fix URLs for one |AffectedEntry| entry in Android ecosystem.

  Args:
    affected: an |Affected| object following OSV CVE dictionary format
  Returns:
    A list of URL strings for all fixes found
  Raises:
    ValueError: when given |Affected| OSV entry is malformed
  """
  return affected.ecosystem_specific.get(ECOSYSTEM_SPECIFIC_FIXES, [])


@functools.cache
def _generate_commit(
    url: str, session: requests.sessions.Session
) -> code_extractor_base.Commit:
  """Generates Commit object for the given URL.

  Args:
    url: a URL pointing a commit of a known source repo.
    session: requests session to use for retrieving files and patches.

  Returns:
    A commit object containing all patches and files extracted from |url|.

  Raises:
    CommitDataFetchError: when fails to extract valid commit data from |url|.
    ValueError: when the given URL is malformatted or not compatible with any
      known source repos.
  """
  known_commit_classes = [AndroidCommit, QualcommCommit]
  for commit_cls in known_commit_classes:
    try:
      return commit_cls(url, session)
    except code_extractor_base.IncompatibleUrlError:
      continue
  raise ValueError('Unknown commit URL: %s' % url)


class AndroidCodeExtractor(code_extractor_base.AbstractCodeExtractor):
  """Code extractor for Android affected packages."""
  
  KNOWN_BRANCHES = {
      '15-next': 'main',
      '15': 'android15-security-release',
      '14': 'android14-security-release',
      '13': 'android13-security-release',
      '12L': 'android12L-security-release',
      '12': 'android12-security-release',
  }

  @classmethod
  def is_supported_ecosystem(cls, ecosystem: str) -> bool:
    return ecosystem in {'Android', 'Pixel', 'Wear'}

  def extract_commits_for_affected_entry(
      self, affected: vulnerability.AffectedEntry,
  ) -> Tuple[Sequence[code_extractor_base.Commit],
             Sequence[code_extractor_base.FailedCommitUrl]]:
    commits = []
    failed_commit_urls = []
    for fix_url in _get_android_fix_urls(affected):
      logging.info('Analyzing fix: %s', fix_url)
      try:
        commit = _generate_commit(fix_url, self._session)
        commits.append(commit)
      except (ValueError, code_extractor_base.CommitDataFetchError) as e:
        failed_commit_urls.append(
            code_extractor_base.FailedCommitUrl(fix_url, e))
    return (commits, failed_commit_urls)

  def extract_files_at_tip_of_unaffected_versions(
      self,
      package_name: str,
      affected_versions: Collection[str],
      files: Collection[str],
  ) -> Tuple[
      Sequence[code_extractor_base.Commit],
      Sequence[code_extractor_base.FailedCommitUrl],
  ]:
    # we currently don't refine against tip of kernel, SoC vendor vulns,
    # or other meta packages. The reason is that even though Kernel and SoC
    # vendor fixes are included in Android bulletins, they do not follow Android
    # versioning scheme. Google's Android OSV exporter uses these special
    # version values to indicate Kernel or SoC vendor fixes.
    if {'Kernel', 'SoCVersion'} & set(affected_versions):
      return ([], [])
    if any(
        meta_package for meta_package in vulnerability.MetaPackage
        if meta_package.value == package_name
    ):
      return ([], [])

    missing_branches = {
        self.KNOWN_BRANCHES[ver] for ver in self.KNOWN_BRANCHES
        if ver not in affected_versions
    }
    tip_commits = []
    failed_commit_urls = []
    for branch in missing_branches:
      try:
        commit = _get_commit_at_tip(
            package_name, branch, frozenset(files), self._session
        )
        tip_commits.append(commit)
      except (ValueError, code_extractor_base.CommitDataFetchError) as e:
        failed_commit_urls.append(
            code_extractor_base.FailedCommitUrl(branch, e)
        )
    return (tip_commits, failed_commit_urls)
