# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

from unittest import mock

from vanir import vulnerability
from vanir.code_extractors import code_extractor_android
from vanir.code_extractors import code_extractor_base
from vanir.code_extractors import git_commit
from vanir.code_extractors import gitiles_commit
from vanir.code_extractors import qualcomm_commit

from absl.testing import absltest
from absl.testing import parameterized


class CodeExtractorAndroidTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    for cls in [
        git_commit.GitCommit,
        gitiles_commit.GitilesCommit,
        qualcomm_commit.QualcommCommit,
    ]:
      def mock_extract_patched_files(self):
        _ = self.url  # ensure URL normalization is done
        return {}
      self.enter_context(
          mock.patch.object(cls, '_extract_patched_files', autospec=True)
      ).side_effect = mock_extract_patched_files
      self.enter_context(
          mock.patch.object(cls, '_extract_unpatched_files', autospec=True)
      ).return_value = {}
      self.enter_context(
          mock.patch.object(cls, '_extract_patch', autospec=True)
      ).return_value = []
    # special mock for git operations done in GitCommit's constructor
    self.enter_context(
        mock.patch.object(git_commit.GitCommit, '_run_git', autospec=True)
    ).return_value = b''

  def test_commit_init_with_unknown_commit_url(self):
    bad_url = 'https://unsupported.kernel.patch.source.com/blah'
    affected = vulnerability.AffectedEntry({
        'package': {'ecosystem': 'Android', 'name': 'pkg'},
        'ecosystem_specific': {'fixes': [bad_url]},
    })
    extractor = code_extractor_android.AndroidCodeExtractor()
    commits, failures = extractor.extract_commits_for_affected_entry(affected)
    self.assertEmpty(commits)
    self.assertLen(failures, 1)
    self.assertEqual(failures[0].url, bad_url)
    self.assertIsInstance(failures[0].error, ValueError)

  @parameterized.named_parameters(
      (
          'qualcomm',
          'https://git.codelinaro.org/clo/quic/test_repo/commit/1234',
          qualcomm_commit.QualcommCommit,
      ),
      (
          'gitiles',
          'https://android.googlesource.com/test_repo/+/1234',
          gitiles_commit.GitilesCommit,
      ),
  )
  def test_extractor_routes_to_correct_commit_class(self, url, commit_class):
    affected = vulnerability.AffectedEntry({
        'package': {'ecosystem': 'Android', 'name': 'pkg'},
        'ecosystem_specific': {'fixes': [url]},
    })
    extractor = code_extractor_android.AndroidCodeExtractor()
    commits, failures = extractor.extract_commits_for_affected_entry(affected)
    self.assertLen(commits, 1)
    self.assertIsInstance(commits[0], commit_class)
    self.assertEmpty(failures)

  def test_extractor_with_multiple_fixes_and_failures(self):
    affected = vulnerability.AffectedEntry({
        'package': {'ecosystem': 'Android', 'name': 'pkg'},
        'ecosystem_specific': {'fixes': [
            'https://source.codeaurora.org/quic/test_repo/commit/?id=1234567',
            'https://git.codelinaro.org/clo/quic/test_repo/commit/1234567',
            'https://android.googlesource.com/test_repo/+/1234567',
            'https://unsupported.kernel.patch.source.com/blah',
        ]},
    })
    extractor = code_extractor_android.AndroidCodeExtractor()
    commits, failures = extractor.extract_commits_for_affected_entry(affected)
    self.assertLen(failures, 1)
    self.assertEqual(
        failures[0].url,
        'https://unsupported.kernel.patch.source.com/blah'
    )
    self.assertLen(commits, 3)
    self.assertIsInstance(commits[0], qualcomm_commit.QualcommCommit)
    self.assertIsInstance(commits[1], qualcomm_commit.QualcommCommit)
    self.assertIsInstance(commits[2], gitiles_commit.GitilesCommit)

  def test_extract_with_empty_patch(self):
    affected = vulnerability.AffectedEntry({
        'package': {'ecosystem': 'Android', 'name': 'pkg'},
        'ecosystem_specific': {'fixes': []},
    })

    extractor = code_extractor_android.AndroidCodeExtractor()
    commits, failures = extractor.extract_commits_for_affected_entry(affected)
    self.assertEmpty(commits)
    self.assertEmpty(failures)

  @mock.patch.object(
      code_extractor_android.AndroidCodeExtractor,
      'VERSION_BRANCH_MAP',
      new={
          '13': 'android13-security-release',
          '14': 'android14-security-release',
          '15': 'android15-security-release',
          '15-next': 'main',
      },
  )
  @mock.patch.object(
      gitiles_commit.GitilesCommit, 'get_file_at_rev', autospec=True,
  )
  def test_extract_files_at_tip_of_unaffected_versions(
      self, mock_get_file_at_rev,
  ):
    def mock_get_file_at_rev_side_effect(commit, file_path):
      del commit  # unused
      if file_path == 'file_that_does_not_exist_in_14':
        raise code_extractor_base.CommitDataFetchError()
      return file_path
    mock_get_file_at_rev.side_effect = mock_get_file_at_rev_side_effect

    extractor = code_extractor_android.AndroidCodeExtractor()
    commits, failures = extractor.extract_files_at_tip_of_unaffected_versions(
        package_name='test_repo',
        affected_versions=['12', '12L', '13', '15', '15-next'],  # all but 14
        files=['file1', 'file2', 'file_that_does_not_exist_in_14'],
    )
    self.assertEmpty(failures)
    self.assertLen(commits, 1)
    self.assertEqual(commits[0].patched_files.keys(), {'file1', 'file2'})
    self.assertContainsExactSubsequence(
        commits[0].url, 'android14-security-release',
    )

  def test_extract_files_at_tip_of_unaffected_versions_ignore_kernel(self):
    extractor = code_extractor_android.AndroidCodeExtractor()
    commits, failures = extractor.extract_files_at_tip_of_unaffected_versions(
        package_name='test_repo',
        affected_versions=['Kernel', 'something_else'],
        files=['file1'],
    )
    self.assertEmpty(commits)
    self.assertEmpty(failures)

  def test_extract_files_at_tip_of_unaffected_versions_ignore_soc_vuln(self):
    extractor = code_extractor_android.AndroidCodeExtractor()
    commits, failures = extractor.extract_files_at_tip_of_unaffected_versions(
        package_name='test_repo',
        affected_versions=['something_else', 'SoCVersion'],
        files=['file1'],
    )
    self.assertEmpty(commits)
    self.assertEmpty(failures)

  def test_extract_files_at_tip_of_unaffected_versions_ignore_metapackage(self):
    extractor = code_extractor_android.AndroidCodeExtractor()
    commits, failures = extractor.extract_files_at_tip_of_unaffected_versions(
        package_name=':modem:', affected_versions=['11'], files=['file1'],
    )
    self.assertEmpty(commits)
    self.assertEmpty(failures)


if __name__ == '__main__':
  absltest.main()
