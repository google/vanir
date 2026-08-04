# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Code extractors for Linux ecosystem packages of OSV CVEs.
"""

import functools
import logging
from typing import Collection, Optional, Sequence, Tuple

from vanir import vulnerability
from vanir.code_extractors import code_extractor_base
from vanir.code_extractors import git_commit
from vanir.code_extractors import gitiles_commit


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
  raise ValueError(f'Unknown commit URL: {url}')


class LinuxCodeExtractor(code_extractor_base.AbstractCodeExtractor):
  """Code extractor for Linux affected packages."""

  @classmethod
  def is_supported_ecosystem(cls, ecosystem: str) -> bool:
    return 'Debian' in ecosystem or 'Linux' in ecosystem

  def extract_commits_for_affected_entry(
      self,
      affected: vulnerability.AffectedEntry,
      extractor_config: Optional[code_extractor_base.ExtractorConfig] = None,
  ) -> Tuple[
      Sequence[code_extractor_base.Commit],
      Sequence[code_extractor_base.FailedCommitUrl],
  ]:
    fix_urls = affected.ecosystem_specific.get('fixes', [])
    commits = []
    failed_commit_urls = []
    for fix_url in fix_urls:
      logging.info('Analyzing fix: %s', fix_url)
      try:
        conf = vars(extractor_config) if extractor_config else {}
        commit = _generate_commit(fix_url, **conf)
        commits.append(commit)
      except (ValueError, code_extractor_base.CommitDataFetchError) as e:
        failed_commit_urls.append(
            code_extractor_base.FailedCommitUrl(fix_url, e)
        )
    return (commits, failed_commit_urls)

  def extract_files_at_tip_of_unaffected_versions(  # pyrefly: ignore[bad-override]
      self,
      package_name: str,
      versions: Sequence[str],
      files: Collection[str],
      extractor_config: Optional[code_extractor_base.ExtractorConfig] = None,
  ) -> Tuple[
      Sequence[code_extractor_base.Commit],
      Sequence[code_extractor_base.FailedCommitUrl],
  ]:
    return ([], [])
