# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Test for Target Selection Strategy module."""

import os
from unittest import mock

from vanir import signature
from vanir.scanners import target_selection_strategy

from absl.testing import absltest


class TargetSelectionStrategyTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self._test_dir = self.create_tempdir()
    self._test_files = {
        'exact_match1.c',
        'foo/exact_match2.c',
        'prefix/on/sig/without/tp/foo/exact_match2.c',
        'foo/bar/no_match1.c',
        'baz/no_match2.c',
        'unsupported_file_type.txt',  # no count for |total_skipped|.
        'no_matching/prefix/dirs/foo/bar/truncated_path_match.c',
    }
    for file in self._test_files:
      self._test_dir.create_file(file)
    self._mock_sign_1 = mock.create_autospec(
        signature.FunctionSignature,
        instance=True,
        signature_id='sign1',
        source='https://android.googlesource.com/sign1_source',
        target_file='exact_match1.c',
        target_function='foo',
        truncated_path_level=None,
        signature_type=signature.SignatureType.FUNCTION_SIGNATURE,
        length=3,
    )
    self._mock_sign_2 = mock.create_autospec(
        signature.LineSignature,
        instance=True,
        signature_id='sign2',
        source='https://android.googlesource.com/sign2_source',
        target_file='foo/exact_match2.c',
        truncated_path_level=None,
        signature_type=signature.SignatureType.LINE_SIGNATURE,
    )
    self._mock_sign_3 = mock.create_autospec(
        signature.LineSignature,
        instance=True,
        signature_id='sign3',
        source='https://android.googlesource.com/sign3_source',
        target_file=(
            'somewhat/different/dir/prefix/foo/bar/truncated_path_match.c'
        ),
        truncated_path_level=2,
        signature_type=signature.SignatureType.LINE_SIGNATURE,
    )

    self._mock_signatures = [
        self._mock_sign_1,
        self._mock_sign_2,
        self._mock_sign_3,
    ]
    self._mock_sign_bundle = mock.create_autospec(
        signature.SignatureBundle, instance=True
    )
    type(self._mock_sign_bundle).signatures = mock.PropertyMock(
        return_value=self._mock_signatures
    )

  def test_all_files_strategy(self):
    to_scan, skipped = (
        target_selection_strategy.Strategy.ALL_FILES.get_target_files(
            self._test_dir.full_path, self._mock_sign_bundle
        )
    )
    expected_scan_targets = {
        os.path.join(self._test_dir.full_path, test_file_path)
        for test_file_path in (self._test_files - {'unsupported_file_type.txt'})
    }
    self.assertCountEqual(to_scan, expected_scan_targets)
    self.assertEqual(skipped, 0)

  def test_exact_path_match_strategy(self):
    to_scan, skipped = (
        target_selection_strategy.Strategy.EXACT_PATH_MATCH.get_target_files(
            self._test_dir.full_path, self._mock_sign_bundle
        )
    )
    expected_scan_targets = {
        os.path.join(self._test_dir.full_path, test_file_path)
        for test_file_path in [
            'exact_match1.c',
            'foo/exact_match2.c',
        ]
    }
    self.assertCountEqual(to_scan, expected_scan_targets)
    self.assertEqual(skipped, 4)

  def test_truncated_path_match_strategy(self):
    to_scan, skipped = (
        target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH.get_target_files(
            self._test_dir.full_path, self._mock_sign_bundle
        )
    )
    expected_scan_targets = {
        os.path.join(self._test_dir.full_path, test_file_path)
        for test_file_path in [
            'exact_match1.c',
            'foo/exact_match2.c',
            'prefix/on/sig/without/tp/foo/exact_match2.c',
            'no_matching/prefix/dirs/foo/bar/truncated_path_match.c',
        ]
    }
    self.assertCountEqual(to_scan, expected_scan_targets)
    self.assertEqual(skipped, 2)

  def test_truncated_path_match_raises_if_level_is_invalid(self):
    self._mock_sign_3.truncated_path_level = 100
    expected_error_message = 'The signature .* has invalid Truncated Path Level'
    with self.assertRaisesRegex(ValueError, expected_error_message):
      target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH.get_target_files(
          self._test_dir.full_path, self._mock_sign_bundle
      )


if __name__ == '__main__':
  absltest.main()
