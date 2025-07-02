# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Code extractors for Android ecosystem packages of OSV CVEs.
"""

import functools
import logging
from typing import Collection, FrozenSet, Mapping, Sequence, Tuple

from vanir import vulnerability
from vanir.code_extractors import code_extractor_base
from vanir.code_extractors import git_commit
from vanir.code_extractors import gitiles_commit
from vanir.code_extractors import qualcomm_commit



class AndroidTipOfBranchCommit(gitiles_commit.GitilesCommit):
  """Commit class that only supports getting files at tip of AOSP branch."""
  _HOST = 'android.googlesource.com'

  def __init__(
      self,
      project: str,
      branch: str,
      files: Collection[str],
      **kwargs,
  ):
    self._files = files
    self._extract_patch = lambda: []
    self._extract_unpatched_files = lambda: {}
    self._compute_affected_line_ranges = lambda: {}
    super().__init__(f'https://{self._HOST}/{project}/+/{branch}', **kwargs)

  def _extract_patched_files(self) -> Mapping[str, str]:
    tip_files = {}
    for file in self._files:
      try:
        tip_files[file] = self.get_file_at_rev(file)
      except code_extractor_base.CommitDataFetchError:
        logging.debug('File %s does not exist on %s', file, self.url)
    return tip_files


@functools.cache
def _get_commit_at_tip(
    project: str,
    branch: str,
    files: FrozenSet[str],
    **kwargs,
) -> code_extractor_base.Commit:
  """Gets Commit for given files at tip of an Android branch."""
  return AndroidTipOfBranchCommit(project, branch, files, **kwargs)


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
  return affected.ecosystem_specific.get('fixes', [])


@functools.cache
def _generate_commit(url: str, **kwargs) -> code_extractor_base.Commit:
  """Generates Commit object for the given URL.

  Args:
    url: a URL pointing a commit of a known source repo.
    **kwargs: additional arguments to pass to the constructor of each Commit.

  Returns:
    A commit object containing all patches and files extracted from |url|.

  Raises:
    CommitDataFetchError: when fails to extract valid commit data from |url|.
    ValueError: when the given URL is malformatted or not compatible with any
      known source repos.
  """
  known_commit_classes = [
      gitiles_commit.GitilesCommit,
      qualcomm_commit.QualcommCommit,
      git_commit.GitCommit,
  ]
  for commit_class in known_commit_classes:
    try:
      return commit_class(url, **kwargs)
    except (
        code_extractor_base.IncompatibleUrlError,
        code_extractor_base.CommitDataFetchError,
    ):
      continue
  raise ValueError('Unknown commit URL: %s' % url)


class AndroidCodeExtractor(code_extractor_base.AbstractCodeExtractor):
  """Code extractor for Android affected packages."""
  VERSION_BRANCH_MAP = {
      '15-next': 'main',
      '15': 'android15-security-release',
      '14': 'android14-security-release',
      '13': 'android13-security-release',
  }

  @classmethod
  def is_supported_ecosystem(cls, ecosystem: str) -> bool:
    return ecosystem in {'Android', 'Pixel', 'Wear'}

  def extract_commits_for_affected_entry(
      self, affected: vulnerability.AffectedEntry, **kwargs,
  ) -> Tuple[Sequence[code_extractor_base.Commit],
             Sequence[code_extractor_base.FailedCommitUrl]]:
    commits = []
    failed_commit_urls = []
    for fix_url in _get_android_fix_urls(affected):
      logging.info('Analyzing fix: %s', fix_url)
      try:
        commit = _generate_commit(fix_url, **kwargs)
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
      **kwargs,
  ) -> Tuple[
      Sequence[code_extractor_base.Commit],
      Sequence[code_extractor_base.FailedCommitUrl],
  ]:
    files = frozenset(files)
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
        self.VERSION_BRANCH_MAP[ver] for ver in self.VERSION_BRANCH_MAP
        if ver not in affected_versions
    }
    tip_commits = []
    failed_commit_urls = []
    for branch in missing_branches:
      try:
        commit = _get_commit_at_tip(
            package_name, branch, files, **kwargs,
        )
        tip_commits.append(commit)
      except (ValueError, code_extractor_base.CommitDataFetchError) as e:
        failed_commit_urls.append(
            code_extractor_base.FailedCommitUrl(branch, e)
        )
    return (tip_commits, failed_commit_urls)
