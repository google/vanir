# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

from unittest import mock

from vanir import vulnerability
from vanir.code_extractors import code_extractor
from vanir.code_extractors import code_extractor_android
from vanir.code_extractors import code_extractor_base
from vanir.code_extractors import code_extractor_git

from absl.testing import absltest
from absl.testing import parameterized

_TEST_COMMIT = 'abcdef0000000000000000000000000000000000'
_TEST_PARENT_COMMIT = 'fedcba1111111111111111111111111111111111'

_ANDROID_PATCH_URL_BASE = 'https://android.googlesource.com/kernel/common/+/'
_TEST_ANDROID_COMMIT_URL = _ANDROID_PATCH_URL_BASE + _TEST_COMMIT


class CodeExtractorTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_extract_git = self.enter_context(
        mock.patch.object(
            code_extractor_git.GitCodeExtractor,
            'extract_commits_for_affected_entry',
            autospec=True,
        )
    )
    self.mock_extract_android = self.enter_context(
        mock.patch.object(
            code_extractor_android.AndroidCodeExtractor,
            'extract_commits_for_affected_entry',
            autospec=True,
        )
    )

  @mock.patch.object(
      code_extractor_base, 'Commit', autospec=True, instance=True
  )
  @mock.patch.object(code_extractor_base, 'AbstractCodeExtractor')
  def test_extract(self, mock_extractor_class, mock_commit):
    mock_extractor_class.__subclasses__ = lambda self: [mock_extractor_class]
    mock_extractor_class.is_supported_ecosystem.side_effect = (
        lambda s: True if s == 'test_ecosystem' else False
    )

    mock_extractor_class(
        None
    ).extract_commits_for_affected_entry.return_value = ([mock_commit], [])
    test_affected = vulnerability.AffectedEntry(
        {'package': {'ecosystem': 'test_ecosystem', 'name': 'pkg'}}
    )
    commits, failures = code_extractor.extract_for_affected_entry(test_affected)
    self.assertEmpty(failures)
    self.assertListEqual(commits, [mock_commit])

  def test_extract_with_no_package_should_use_git_extractor(self):
    code_extractor.extract_for_affected_entry(
        vulnerability.AffectedEntry({})
    )
    self.mock_extract_git.assert_called_once()
    self.mock_extract_android.assert_not_called()

  def test_extract_with_android_package_should_use_android_extractor(self):
    code_extractor.extract_for_affected_entry(
        vulnerability.AffectedEntry(
            {'package': {'ecosystem': 'Android', 'name': 'pkg'}}
        )
    )
    self.mock_extract_git.assert_not_called()
    self.mock_extract_android.assert_called_once()

  @mock.patch.object(code_extractor_base, 'AbstractCodeExtractor')
  def test_extract_with_no_patch_found(self, mock_extractor_class):
    mock_extractor_class.__subclasses__ = lambda self: [mock_extractor_class]
    mock_extractor_class.is_supported_ecosystem.side_effect = (
        lambda s: True if s == 'test_ecosystem' else False
    )
    mock_extractor_class(
        None
    ).extract_commits_for_affected_entry.return_value = ([], [])
    test_affected = vulnerability.AffectedEntry(
        {'package': {'ecosystem': 'test_ecosystem', 'name': 'pkg'}}
    )
    commits, failures = code_extractor.extract_for_affected_entry(test_affected)
    self.assertEmpty(commits)
    self.assertEmpty(failures)

  def test_extract_with_unsupported_ecosystem(self):
    test_affected = vulnerability.AffectedEntry(
        {'package': {'ecosystem': 'unknown_ecosystem', 'name': 'pkg'}}
    )
    with self.assertRaises(NotImplementedError):
      _, _ = code_extractor.extract_for_affected_entry(test_affected)

  @mock.patch.object(
      code_extractor_base, 'Commit', autospec=True, instance=True
  )
  @mock.patch.object(code_extractor_base, 'AbstractCodeExtractor')
  def test_extract_files_at_tip_of_unaffected_versions(
      self, mock_extractor_class, mock_commit,
  ):
    mock_extractor_class.__subclasses__ = lambda self: [mock_extractor_class]
    mock_extractor_class.is_supported_ecosystem.side_effect = (
        lambda s: True if s == 'test_ecosystem' else False
    )
    mock_extractor_class(
        None
    ).extract_files_at_tip_of_unaffected_versions.return_value = (
        [mock_commit], []
    )

    commits, failures = (
        code_extractor.extract_files_at_tip_of_unaffected_versions(
            'test_ecosystem', 'test_package', ['1.0.0'], ['file1'], None,
        )
    )
    self.assertEmpty(failures)
    self.assertListEqual(commits, [mock_commit])

  def test_extract_files_at_tip_of_unaffected_versions_unsupported_ecosystem(
      self
  ):
    with self.assertRaises(NotImplementedError):
      code_extractor.extract_files_at_tip_of_unaffected_versions(
          'test_ecosystem', 'test_package', ['1.0.0'], ['file1', 'file2'], None,
      )


if __name__ == '__main__':
  absltest.main()
