# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for Detector Common Flags module."""

import datetime
import os
import shutil
from unittest import mock

from absl import flags
from absl.testing import flagsaver
from vanir import detector_common_flags
from vanir import file_path_utils
from vanir import vulnerability_manager
from vanir.scanners import scanner_base
from vanir.scanners import target_selection_strategy

from absl.testing import absltest
from absl.testing import parameterized


class DetectorCommonFlagsTest(parameterized.TestCase):
  """Tests common Detector flags and their validators.

  Note that the flag parsing behaviour cannot be tested with flagsaver so most
  of the testcases here explicitly use parse() to feed testing values to the
  flags. For the flags with validators, neither flagsaver nor parse() triggers
  the validator, so we expclicitly call validate_all_flags() for testing.
  """

  @flagsaver.flagsaver
  def test_vuln_id_ignore_list(self):
    flags.FLAGS['vuln_id_ignore_list'].parse('ASB-A-1111,CVE-2020-1234')
    self.assertCountEqual(['ASB-A-1111', 'CVE-2020-1234'],
                          detector_common_flags._VULN_ID_IGNORE_LIST.value)

  @flagsaver.flagsaver
  def test_vuln_id_prefix(self):
    flags.FLAGS['vuln_id_allowed_prefix'].parse('ASB-A-,WSB-A-')
    self.assertEqual(
        ['ASB-A-', 'WSB-A-'],
        detector_common_flags._VULN_ID_ALLOWED_PREFIX.value
    )

  @flagsaver.flagsaver
  def test_android_min_severity_level(self):
    test_levels = ['Low', 'moderate', 'HIGH', 'CriticaL']
    for test_level in test_levels:
      flags.FLAGS['android_min_severity_level'].parse(test_level)
      self.assertEqual(test_level.upper(),
                       detector_common_flags._ANDROID_MIN_SEVERITY_LEVEL.value)
    test_level = 'nonexisting-level'
    with self.assertRaises(flags.IllegalFlagValueError):
      flags.FLAGS['android_min_severity_level'].parse(test_level)

  @flagsaver.flagsaver
  def test_android_spl(self):
    test_spl = '2020-05-01'
    flags.FLAGS['android_spl'].parse(test_spl)
    self.assertEqual(test_spl, detector_common_flags._ANDROID_SPL.value)
    flags.FLAGS.validate_all_flags()

    test_spl = '01-05-2020'
    flags.FLAGS['android_spl'].parse(test_spl)
    with self.assertRaisesRegex(flags.IllegalFlagValueError,
                                '--android_spl format must be YYYY-MM-DD'):
      flags.FLAGS.validate_all_flags()

  @parameterized.named_parameters(
      ('none', 0, datetime.datetime(2020, 7, 30)),
      ('same_year', 2, datetime.datetime(2020, 9, 30)),
      ('next_year', 8, datetime.datetime(2021, 3, 30)),
      ('date_truncated', 7, datetime.datetime(2021, 2, 28)),
      ('negative', -1, datetime.datetime(2020, 6, 30)),
      ('last_year', -9, datetime.datetime(2019, 10, 30)),
  )
  @flagsaver.flagsaver
  def test_android_spl_offset(self, offset, expected_spl):
    # Since datetime.date is native, we can't mock datetime.date.today()
    # We can't mock datetime.date either, because some libraries use isinstance
    # which does not work if the type is a mock. We'll create a fake date class.
    class MyDate(datetime.date):
      @classmethod
      def today(cls):
        return datetime.date(2020, 7, 30)
    datetime.date = MyDate

    flags.FLAGS['android_spl_relative_months'].parse(offset)
    flags.FLAGS.validate_all_flags()
    spl_filter = [
        filter for filter in
        detector_common_flags.generate_vulnerability_filters_from_flags()
        if isinstance(filter, vulnerability_manager.AndroidSplFilter)
    ]
    self.assertLen(spl_filter, 1)
    self.assertEqual(spl_filter[0]._target_spl, expected_spl)

  @flagsaver.flagsaver
  def test_android_spl_offset_and_spl_flags_are_mutually_exclusive(self):
    flags.FLAGS['android_spl_relative_months'].parse(1)
    flags.FLAGS['android_spl'].parse('2020-05-01')
    with self.assertRaises(flags.IllegalFlagValueError):
      flags.FLAGS.validate_all_flags()

  @parameterized.named_parameters(
      ('offset_0', 0, datetime.datetime(2020, 6, 1)),
      ('offset_1', 1, datetime.datetime(2020, 6, 1)),
      ('offset_3', 3, datetime.datetime(2020, 9, 1)),
      ('offset_minus_1', -1, datetime.datetime(2020, 6, 1)),
      ('offset_minus_3', -3, datetime.datetime(2020, 3, 1)),
  )
  @flagsaver.flagsaver
  def test_android_spl_align_to_quarter(self, offset, expected_spl):
    # Since datetime.date is native, we can't mock datetime.date.today()
    # We can't mock datetime.date either, because some libraries use isinstance
    # which does not work if the type is a mock. We'll create a fake date class.
    class MyDate(datetime.date):
      @classmethod
      def today(cls):
        return datetime.date(2020, 7, 30)
    datetime.date = MyDate

    flags.FLAGS['android_spl_align_to_quarter'].parse(True)
    flags.FLAGS['android_spl_relative_months'].parse(offset)

    flags.FLAGS.validate_all_flags()
    vfilters = detector_common_flags.generate_vulnerability_filters_from_flags()

    spl_filter = [
        f
        for f in vfilters
        if isinstance(f, vulnerability_manager.AndroidSplFilter)
    ]

    self.assertLen(spl_filter, 1)
    self.assertEqual(spl_filter[0]._target_spl, expected_spl)

  @flagsaver.flagsaver
  def test_sign_target_path_filter(self):
    flags.FLAGS['sign_target_path_filter'].parse('foo/bar/.*')
    flags.FLAGS['sign_target_path_filter'].parse('foo/baz/.*')
    self.assertCountEqual(['foo/bar/.*', 'foo/baz/.*'],
                          detector_common_flags._SIGN_TARGET_PATH_FILTER.value)
    flags.FLAGS.validate_all_flags()

    flags.FLAGS['sign_target_path_filter'].parse('foo/baz/(.*')
    with self.assertRaisesRegex(
        flags.IllegalFlagValueError,
        '--sign_target_path_filter must be a valid regular expression',
    ):
      flags.FLAGS.validate_all_flags()

  @flagsaver.flagsaver
  def test_sign_target_arch(self):
    test_arches = ['x86', 'arm', 'arm64', 'riscv']
    for arch in test_arches:
      with flagsaver.flagsaver():
        flags.FLAGS['sign_target_arch'].parse(arch)
        self.assertCountEqual([arch.upper()],
                              detector_common_flags._SIGN_TARGET_ARCH.value)

    flagsaver.flagsaver()
    for arch in test_arches:
      flags.FLAGS['sign_target_arch'].parse(arch)
    self.assertCountEqual([arch.upper() for arch in test_arches],
                          detector_common_flags._SIGN_TARGET_ARCH.value)

    with self.assertRaises(flags.IllegalFlagValueError):
      flags.FLAGS['sign_target_arch'].parse('nonexisting-arch')

  @flagsaver.flagsaver
  def test_signature_ids(self):
    flags.FLAGS['signature_ids'].parse('SIG-1,SIG-2')
    self.assertCountEqual(
        ['SIG-1', 'SIG-2'], detector_common_flags._SIGNATURE_IDS.value
    )

  @flagsaver.flagsaver(signature_ids=['SIG-1', 'SIG-2'])
  def test_generate_vulnerability_filters_from_flags_with_signature_ids(self):
    vfilters = detector_common_flags.generate_vulnerability_filters_from_flags()
    self.assertNotEmpty(vfilters)
    self.assertIsInstance(vfilters[-1], vulnerability_manager.SignatureIdFilter)

  @flagsaver.flagsaver
  def test_target_selection_strategy(self):

    test_strategies = [
        'all_files',
        'eXaCt_PaTh_MaTch',
        'TRUNCATED_PATH_MATCH',
    ]
    for strategy in test_strategies:
      with flagsaver.flagsaver():
        flags.FLAGS['target_selection_strategy'].parse(strategy)
        self.assertEqual(
            target_selection_strategy.Strategy[strategy.upper()],
            detector_common_flags._TARGET_SELECTION_STRATEGY.value,
        )

  @flagsaver.flagsaver
  def test_target_selection_strategy_fails_with_undefined_strategy(self):
    test_strategy = 'undefined_strategy'
    with self.assertRaises(flags.IllegalFlagValueError):
      flags.FLAGS['target_selection_strategy'].parse(test_strategy)

  @flagsaver.flagsaver(
      vuln_id_ignore_list=['ASB-A-1111', 'CVE-2020-1234'],
      vuln_id_allowed_prefix='ASB-A-',
      android_min_severity_level='MODERATE',
      android_spl='2020-05-01',
      sign_target_path_filter=['foo/bar/.*', 'foo/bar/.*', 'foo/baz/.*'],
      sign_target_arch=['X86'],
  )
  def test_generate_vulnerability_filters_from_flags(self):
    vfilters = detector_common_flags.generate_vulnerability_filters_from_flags()
    self.assertLen(vfilters, 8)
    self.assertEqual(
        {type(vfilter) for vfilter in vfilters},
        {
            vulnerability_manager.VulnIdIgnoreFilter,
            vulnerability_manager.VulnIdAllowedPrefixFilter,
            vulnerability_manager.AndroidSeverityFilter,
            vulnerability_manager.AndroidSplFilter,
            vulnerability_manager.TargetPathFilter,
            vulnerability_manager.ArchitectureFilter,
            vulnerability_manager.DeprecatedSignatureFilter,
        },
    )

  @flagsaver.flagsaver(include_deprecated_signatures=True)
  def test_generate_vulnerability_filters_from_flags_ignores_low_severity(self):
    flags.FLAGS['android_min_severity_level'].parse('Low')
    vfilters = detector_common_flags.generate_vulnerability_filters_from_flags()
    self.assertEmpty(vfilters)

  @flagsaver.flagsaver(ignore_scan_path=['path1', 'path2/3'])
  def test_generate_scan_path_finding_filters_from_flags(self):
    filters = detector_common_flags.generate_finding_filters_from_flags()
    self.assertLen(filters, 3)
    self.assertIsInstance(filters[0], scanner_base.PathPrefixFilter)
    self.assertIsInstance(filters[1], scanner_base.PathPrefixFilter)
    self.assertIsInstance(
        filters[2], scanner_base.PackageVersionSpecificSignatureFilter
    )

  @flagsaver.flagsaver(package_version=['1', '2'])
  def test_generate_version_finding_filters_from_flags(self):
    filters = detector_common_flags.generate_finding_filters_from_flags()
    self.assertLen(filters, 1)
    self.assertIsInstance(
        filters[0], scanner_base.PackageVersionSpecificSignatureFilter
    )
    self.assertEqual(filters[0]._package_versions, {'1', '2'})

  @flagsaver.flagsaver
  def test_generate_overwrite_specs_from_flags_empty(self):
    flags.FLAGS['overwrite_specs'].parse('')
    specs = detector_common_flags.generate_overwrite_specs_from_flags()
    self.assertEmpty(specs, 'Overwrite specs should be empty')

  @flagsaver.flagsaver
  def test_generate_overwrite_specs_from_flags(self):
    flags.FLAGS['overwrite_specs'].parse(
        file_path_utils.get_root_file_path('testdata/test_overwrite_specs.json')
    )
    specs = detector_common_flags.generate_overwrite_specs_from_flags()
    self.assertNotEmpty(specs, 'Overwrite specs should not be empty')

  @flagsaver.flagsaver(vuln_ids=['ASB-A-1111', 'CVE-2020-1234'])
  def test_generate_vuln_filters_from_flags_with_vuln_ids(self):
    vfilters = detector_common_flags.generate_vulnerability_filters_from_flags()
    self.assertNotEmpty(vfilters)
    self.assertIsInstance(
        vfilters[-1], vulnerability_manager.VulnIdFilter
    )

  @flagsaver.flagsaver
  def test_generate_vuln_manager_from_flags_with_files(self):
    from_filename = os.path.join(
        absltest.TEST_SRCDIR.value,
        file_path_utils.get_root_file_path('testdata/test_vulnerabilities_platform.json'),
    )
    to_file = self.create_tempfile('test_vulnerabilities_platform.json')
    shutil.copyfile(from_filename, to_file.full_path)

    flags.FLAGS['vulnerability_file_name'].parse(to_file.full_path)

    vuln_manager = detector_common_flags.generate_vuln_manager_from_flags()
    self.assertIsNotNone(vuln_manager)

  @flagsaver.flagsaver(vulnerability_file_name=['dummy_file.json'])
  def test_generate_vuln_manager_from_flags_fails_when_all_filtered(self):
    with mock.patch('os.path.isfile', return_value=True):
      with mock.patch.object(vulnerability_manager, 'generate_from_file'):
        with mock.patch.object(
            vulnerability_manager, 'generate_from_managers'
        ) as mock_gen:
          mock_manager = mock.MagicMock()
          mock_manager.vulnerabilities = []
          mock_gen.return_value = mock_manager

          with self.assertRaisesRegex(
              ValueError, 'All vulnerabilities were filtered out'
          ):
            detector_common_flags.generate_vuln_manager_from_flags()


if __name__ == '__main__':
  absltest.main()
