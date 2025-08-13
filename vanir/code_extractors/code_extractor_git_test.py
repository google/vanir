from unittest import mock

from vanir import vulnerability
from vanir.code_extractors import code_extractor_git
from vanir.code_extractors import git_commit

from absl.testing import absltest

_TEST_AFFECTED = vulnerability.AffectedEntry({
    'ranges': [
        {
            'type': 'GIT',
            'repo': 'git://typical/case',
            'events': [
                {'introduced': '0'},
                {'fixed': 'abcdef1234'},
            ],
        },
        {
            'type': 'GIT',
            'repo': 'git://multiple/fixes',
            'events': [
                {'introduced': '0'},
                {'fixed': 'abcdef1234'},
                {'fixed': 'abcdef5678'},
            ],
        },
        {
            'type': 'GIT',
            'repo': 'git://no/fix',
            'events': [
                {'introduced': '0'},
                {'last_affected': 'abcdef1234'},
            ],
        },
    ],
    'versions': ['1.0.0', '2.0.0'],
})


class CodeExtractorGitTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_git_commit_class = self.enter_context(
        mock.patch.object(git_commit, 'GitCommit', autospec=True)
    )
    self.extractor = code_extractor_git.GitCodeExtractor()

  def test_extract_files_at_tip_of_unaffected_versions_returns_nothing(self):
    self.assertEqual(
        self.extractor.extract_files_at_tip_of_unaffected_versions(
            'package_name', ['1.0'], ['file1'],
        ),
        ([], []),
    )

  def test_extract_commits_for_affected_entry(self):
    commits, failures = self.extractor.extract_commits_for_affected_entry(
        _TEST_AFFECTED,
    )
    self.assertLen(commits, 3)
    self.assertEmpty(failures)
    self.assertLen(self.mock_git_commit_class.mock_calls, 3)
    self.mock_git_commit_class.assert_has_calls(
        [
            mock.call('git://typical/case@abcdef1234'),
            mock.call('git://multiple/fixes@abcdef1234'),
            mock.call('git://multiple/fixes@abcdef5678'),
        ],
        any_order=True,
    )

  def test_extract_commits_for_affected_entry_skipping_non_git_ranges(self):
    affected_with_semver = _TEST_AFFECTED.to_osv_dict()
    affected_with_semver['ranges'].append({'type': 'SEMVER'})
    commits, failures = self.extractor.extract_commits_for_affected_entry(
        vulnerability.AffectedEntry(affected_with_semver),
    )
    self.assertLen(commits, 3)
    self.assertEmpty(failures)

  def test_extract_commits_for_affected_entry_with_only_non_git_ranges(self):
    affected = vulnerability.AffectedEntry({'ranges': [{'type': 'SEMVER'}]})
    with self.assertRaises(ValueError):
      self.extractor.extract_commits_for_affected_entry(affected)

  def test_extract_commits_for_affected_entry_with_no_repo(self):
    affected = vulnerability.AffectedEntry({'ranges': [{'type': 'GIT'}]})
    with self.assertRaises(ValueError):
      self.extractor.extract_commits_for_affected_entry(affected)


if __name__ == '__main__':
  absltest.main()
