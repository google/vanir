# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for code_extractor."""

from vanir import vulnerability
from vanir.code_extractors import code_extractor
from vanir.code_extractors import code_extractor_base

from absl.testing import absltest
from absl.testing import parameterized

_TEST_COMMIT = 'abcdef0000000000000000000000000000000000'
_TEST_PARENT_COMMIT = 'fedcba1111111111111111111111111111111111'

_ANDROID_PATCH_URL_BASE = 'https://android.googlesource.com/kernel/common/+/'
_TEST_ANDROID_COMMIT_URL = _ANDROID_PATCH_URL_BASE + _TEST_COMMIT


class CodeExtractorTest(parameterized.TestCase):

  @absltest.mock.patch.object(
      code_extractor_base, 'Commit', autospec=True, instance=True
  )
  @absltest.mock.patch.object(code_extractor_base, 'AbstractCodeExtractor')
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

  def test_extract_with_no_package(self):
    with self.assertRaisesRegex(ValueError, 'Missing package info.*'):
      code_extractor.extract_for_affected_entry(
          vulnerability.AffectedEntry({})
      )

  @absltest.mock.patch.object(code_extractor_base, 'AbstractCodeExtractor')
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

  @absltest.mock.patch.object(
      code_extractor_base, 'Commit', autospec=True, instance=True
  )
  @absltest.mock.patch.object(code_extractor_base, 'AbstractCodeExtractor')
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
