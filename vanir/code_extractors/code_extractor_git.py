"""Code extractor for OSV GIT ecosystem vulns."""

from typing import Collection, Sequence, Tuple

from osv import vulnerability_pb2
from vanir import vulnerability
from vanir.code_extractors import code_extractor_base
from vanir.code_extractors import git_commit


class GitCodeExtractor(code_extractor_base.AbstractCodeExtractor):
  """Code extractor for OSV GIT ecosystem vulns."""

  @classmethod
  def is_supported_ecosystem(cls, ecosystem: str) -> bool:
    # Per OSV, GIT ecosystem is identified by a lack of |package| field.
    return not ecosystem

  def extract_commits_for_affected_entry(
      self, affected: vulnerability.AffectedEntry, **kwargs,
  ) -> Tuple[Sequence[code_extractor_base.Commit],
             Sequence[code_extractor_base.FailedCommitUrl]]:
    affected_fixes: set[Tuple[str, str]] = set()
    # Per OSV, patches in GIT ecosystem are represented as |repo| and |fixed|
    # events in the affected.range.events field.
    for r in affected.to_proto().ranges:
      if r.type != vulnerability_pb2.Range.GIT:
        continue
      if not r.repo:
        raise ValueError('No affected.range.repo specified')
      range_fixes: set[Tuple[str, str]] = set()
      for event in r.events:
        if event.fixed:
          range_fixes.add((r.repo, event.fixed))
      affected_fixes.update(range_fixes)
    if not affected_fixes:
      raise ValueError('No supported affected.range found')

    commits = []
    failed_commit_urls = []
    for repo, rev in affected_fixes:
      try:
        commits.append(git_commit.GitCommit(f'{repo}@{rev}', **kwargs))
      except (
          code_extractor_base.CommitDataFetchError,
          code_extractor_base.IncompatibleUrlError
      ) as e:
        failed_commit_urls.append(
            code_extractor_base.FailedCommitUrl(f'{repo}@{rev}', e)
        )
    return commits, failed_commit_urls

  def extract_files_at_tip_of_unaffected_versions(
      self,
      package_name: str,
      versions: Sequence[str],
      files: Collection[str],
      **kwargs,
  ) -> Tuple[Sequence[code_extractor_base.Commit],
             Sequence[code_extractor_base.FailedCommitUrl]]:
    # GIT ecosystem does not support version-specific signatures.
    return ([], [])
