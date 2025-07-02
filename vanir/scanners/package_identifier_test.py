# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Test for Package Identifier module."""

from vanir import file_path_utils
from vanir import truncated_path
from vanir import vulnerability
from vanir import vulnerability_manager
from vanir.scanners import package_identifier

from absl.testing import absltest

_TEST_SIGN_FILE = file_path_utils.get_root_file_path('testdata/test_signatures.json')
_TEST_ECOSYSTEM = 'Android'


class PackageIdentifierTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self._vuln_manager = vulnerability_manager.generate_from_json_string(
        open(_TEST_SIGN_FILE, mode='rb').read()
    )

  def test_init(self):
    pkg_identifier = package_identifier.PackageIdentifier(
        self._vuln_manager, _TEST_ECOSYSTEM
    )
    self.assertCountEqual(
        pkg_identifier._signatures_per_package.keys(),
        [
            'platform/packages/apps/Bluetooth',
            'platform/frameworks/base',
            vulnerability.MetaPackage.ANDROID_KERNEL.value,
        ],
    )

  def test_get_truncated_paths(self):
    pkg_identifier = package_identifier.PackageIdentifier(
        self._vuln_manager, _TEST_ECOSYSTEM
    )

    test_regular_package = 'platform/packages/apps/Bluetooth'
    truncated_paths = pkg_identifier.get_truncated_paths(test_regular_package)
    expected_signature_target_file = 'core/java/android/widget/RemoteViews.java'
    # This signature does not have an explicit TP level, so should use default.
    expected_level = package_identifier.DEFAULT_TRUNCATED_PATH_LEVEL
    expected_tp = truncated_path.TruncatedPath(
        expected_signature_target_file,
        level=expected_level,
    )
    self.assertCountEqual(truncated_paths, [expected_tp])

    test_kernel_package = vulnerability.MetaPackage.ANDROID_KERNEL.value
    truncated_paths = pkg_identifier.get_truncated_paths(test_kernel_package)
    expected_tps = [
        truncated_path.TruncatedPath(
            'drivers/media/usb/uvc/uvc_driver.c', level=1
        ),
        truncated_path.TruncatedPath(
            'drivers/media/usb/uvc/uvc_driver.c', level=3
        ),
    ]
    self.assertCountEqual(truncated_paths, expected_tps)

  def test_is_package_mapped_to_repo(self):
    pkg_identifier = package_identifier.PackageIdentifier(
        self._vuln_manager, _TEST_ECOSYSTEM
    )

    # Case 0. no TP is included.
    self.assertFalse(
        pkg_identifier.is_package_mapped_to_repo(
            'platform/packages/apps/Bluetooth',
            ['foo/bar/baz.c', 'foo/bar/baz.java'],
            threshold=0.001,
            min_package_truncated_paths=1,
        )
    )

    # Case 1. 100% of TPs are included.
    self.assertTrue(
        pkg_identifier.is_package_mapped_to_repo(
            'platform/packages/apps/Bluetooth',
            ['foo/bar/baz/android/widget/RemoteViews.java'],
            threshold=1.0,
            min_package_truncated_paths=1,
        )
    )

    # Case 2. 50% of TPs are included: test kernel signatures will have two TPs.
    # 'uvc/uvc_driver.c' and 'media/usb/uvc/uvc_driver.c'.
    self.assertTrue(
        pkg_identifier.is_package_mapped_to_repo(
            vulnerability.MetaPackage.ANDROID_KERNEL.value,
            ['foo/bar/baz/uvc/uvc_driver.c'],
            threshold=0.5,
            min_package_truncated_paths=1,
        )
    )
    self.assertFalse(
        pkg_identifier.is_package_mapped_to_repo(
            vulnerability.MetaPackage.ANDROID_KERNEL.value,
            ['foo/bar/baz/uvc/uvc_driver.c'],
            threshold=0.51,
            min_package_truncated_paths=1,
        )
    )

  def test_is_package_mapped_to_repo_works_with_string_meta_package(self):
    pkg_identifier = package_identifier.PackageIdentifier(
        self._vuln_manager, _TEST_ECOSYSTEM
    )

    self.assertTrue(
        pkg_identifier.is_package_mapped_to_repo(
            ':linux_kernel:',
            ['foo/bar/baz/uvc/uvc_driver.c'],
            threshold=0.5,
            min_package_truncated_paths=1,
        )
    )
    self.assertFalse(
        pkg_identifier.is_package_mapped_to_repo(
            ':linux_kernel:',
            ['foo/bar/baz/uvc/uvc_driver.c'],
            threshold=0.51,
            min_package_truncated_paths=1,
        )
    )

  def test_is_package_mapped_to_repo_ignores_package_with_few_tps(self):
    pkg_identifier = package_identifier.PackageIdentifier(
        self._vuln_manager, _TEST_ECOSYSTEM
    )

    self.assertFalse(
        pkg_identifier.is_package_mapped_to_repo(
            ':linux_kernel:',
            ['foo/bar/baz/uvc/uvc_driver.c'],
            threshold=0.5,
            min_package_truncated_paths=10,
        )
    )

  def test_packages_for_repo_no_signature(self):
    pkg_identifier = package_identifier.PackageIdentifier(
        self._vuln_manager, _TEST_ECOSYSTEM
    )
    self.assertEmpty(
        pkg_identifier.packages_for_repo(
            'platform/bionic',
            ['dne.c'],
            min_package_truncated_paths=1
        )
    )

  def test_packages_for_repo_by_name_only(self):
    pkg_identifier = package_identifier.PackageIdentifier(
        self._vuln_manager, _TEST_ECOSYSTEM
    )
    self.assertEqual(
        pkg_identifier.packages_for_repo(
            'platform/frameworks/base',
            ['dne.c'],
            min_package_truncated_paths=1),
        {'platform/frameworks/base'},
    )

  def test_packages_for_repo_by_file_list_only(self):
    pkg_identifier = package_identifier.PackageIdentifier(
        self._vuln_manager, _TEST_ECOSYSTEM
    )
    self.assertEqual(
        pkg_identifier.packages_for_repo(
            'renamed/repo',
            ['core/tests/coretests/src/android/widget/RemoteViewsTest.java'],
            min_package_truncated_paths=1),
        {'platform/frameworks/base'},
    )

  def test_packages_for_repo_match_both_name_and_file_list(self):
    pkg_identifier = package_identifier.PackageIdentifier(
        self._vuln_manager, _TEST_ECOSYSTEM
    )
    self.assertEqual(
        pkg_identifier.packages_for_repo(
            'platform/frameworks/base',
            ['core/tests/coretests/src/android/widget/RemoteViewsTest.java'],
            min_package_truncated_paths=1),
        {'platform/frameworks/base'},
    )

  def test_packages_for_repo_match_file_list_multiple_packages(self):
    pkg_identifier = package_identifier.PackageIdentifier(
        self._vuln_manager, _TEST_ECOSYSTEM
    )
    self.assertEqual(
        pkg_identifier.packages_for_repo(
            'renamed/repo',
            [
                'core/tests/coretests/src/android/widget/RemoteViewsTest.java',
                'drivers/media/usb/uvc/uvc_driver.c',
            ],
            min_package_truncated_paths=1),
        {
            'platform/frameworks/base',
            vulnerability.MetaPackage.ANDROID_KERNEL.value,
        },
    )

  def test_packages_for_repo_match_file_list_and_name_multiple_packages(self):
    pkg_identifier = package_identifier.PackageIdentifier(
        self._vuln_manager, _TEST_ECOSYSTEM
    )
    self.assertEqual(
        pkg_identifier.packages_for_repo(
            'platform/packages/apps/Bluetooth',
            [
                'core/tests/coretests/src/android/widget/RemoteViewsTest.java',
                'drivers/media/usb/uvc/uvc_driver.c',
            ],
            min_package_truncated_paths=1),
        {
            'platform/packages/apps/Bluetooth',
            'platform/frameworks/base',
            vulnerability.MetaPackage.ANDROID_KERNEL.value,
        },
    )

if __name__ == '__main__':
  absltest.main()
