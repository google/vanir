# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for version extractor."""

import os
from unittest import mock

from vanir import version_extractor

from absl.testing import absltest
from absl.testing import parameterized


_MAKEFILE_FULL_VERSION = """
VERSION = 10
PATCHLEVEL = 20
SUBLEVEL = 30
EXTRAVERSION = -special
"""

_MAKEFILE_PARTIAL_VERSION = """
VERSION = 10
PATCHLEVEL = 20
"""

_MAKEFILE_NO_VERSION = """
PATCHLEVEL = 20
SUBLEVEL = 30
EXTRAVERSION = -special
"""


class VersionExtractorTest(parameterized.TestCase):

  @parameterized.named_parameters(
      ('without_target_system_type', None, ['Makefile']),
      (
          'with_target_system_type',
          version_extractor.TargetSystem.KERNEL,
          ['Makefile'],
      ),
      (
          'with_useless_target_system_type',
          version_extractor.TargetSystem.UNKNOWN,
          [],
      ),
  )
  def test_get_target_version_files(self, target_system_type, expected_files):
    files = version_extractor.get_target_version_files(target_system_type)
    self.assertCountEqual(files, expected_files)

  @parameterized.named_parameters(
      (
          'no_target_system_type',
          None,
          '10.20.30-special',
      ),
      (
          'matched_target_system_type',
          version_extractor.TargetSystem.KERNEL,
          '10.20.30-special',
      ),
      (
          'unmatched_target_system_type',
          version_extractor.TargetSystem.UNKNOWN,
          None,
      ),
  )
  def test_extract_version(self, target_system_type, expected_version):
    test_root = self.create_tempdir().full_path
    self.create_tempfile(
        os.path.join(test_root, 'Makefile'), content=_MAKEFILE_FULL_VERSION
    )
    version = version_extractor.extract_version(test_root, target_system_type)
    self.assertEqual(version, expected_version)

  def test_extract_version_fails_if_multiple_versions_found(self):
    class MockVersionExtractor:
      """A mock version extractor class.

      To avoid auto-registeration of this mock class through __subclasses__() in
      other tests, this mock class intentionally does not inherit from
      VersionExtractor.
      """

      @classmethod
      def get_version_files(cls):
        return ['foo']

      @classmethod
      def get_target_system(cls):
        return version_extractor.TargetSystem.KERNEL

      @classmethod
      def extract_version(cls, _):
        return '1234.5678'

    test_root = self.create_tempdir().full_path
    self.create_tempfile(
        os.path.join(test_root, 'Makefile'), content=_MAKEFILE_FULL_VERSION
    )
    self.create_tempfile(os.path.join(test_root, 'foo'))
    with mock.patch.object(
        version_extractor.VersionExtractor,
        '__subclasses__',
        autospec=True,
        return_value=[
            version_extractor.KernelVersionExtractor,
            MockVersionExtractor,
        ],
    ):
      expected_error_msg = 'Multiple versions were found from the target root:'
      with self.assertRaisesRegex(RuntimeError, expected_error_msg):
        version_extractor.extract_version(test_root)

  @parameterized.named_parameters(
      ('full_version', _MAKEFILE_FULL_VERSION, '10.20.30-special'),
      ('partial_version', _MAKEFILE_PARTIAL_VERSION, '10.20'),
      ('no_version', _MAKEFILE_NO_VERSION, ''),
  )
  def test_kernel_version_extractor_parse_makefile(
      self, makefile_content, expected_kernelversion
  ):
    kernelversion = version_extractor.KernelVersionExtractor._parse_makefile(
        makefile_content
    )
    self.assertEqual(kernelversion, expected_kernelversion)

  def test_kernel_version_extractor_fails_if_target_root_is_invalid(self):
    with self.assertRaisesRegex(ValueError, 'Invalid directory:'):
      version_extractor.KernelVersionExtractor.extract_version(
          'nonexisting_dir'
      )

  def test_kernel_version_extractor_returns_none_if_makefile_not_exist(self):
    test_root = self.create_tempdir().full_path
    self.assertIsNone(
        version_extractor.KernelVersionExtractor.extract_version(test_root)
    )


if __name__ == '__main__':
  absltest.main()
