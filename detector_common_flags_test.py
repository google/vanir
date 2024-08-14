# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for Detector Common Flags module."""

from absl import flags
from absl.testing import flagsaver
from vanir import detector_common_flags
from vanir import vulnerability_manager
from vanir.scanners import scanner_base
from vanir.scanners import target_selection_strategy

from absl.testing import absltest


class DetectorCommonFlagsTest(absltest.TestCase):
  """Tests common Detector flags and their validators.

  Note that the flag parsing behaviour cannot be tested with flagsaver so most
  of the testcases here explicitly use parse() to feed testing values to the
  flags. For the flags with validators, neither flagsaver nor parse() triggers
  the validator, so we expclicitly call validate_all_flags() for testing.
  """

  @flagsaver.flagsaver
  def test_osv_id_ignore_list(self):
    flags.FLAGS['osv_id_ignore_list'].parse('ASB-A-1111,ASB-A-1234')
    self.assertCountEqual(['ASB-A-1111', 'ASB-A-1234'],
                          detector_common_flags._OSV_ID_IGNORE_LIST.value)

  @flagsaver.flagsaver
  def test_cve_id_ignore_list(self):
    flags.FLAGS['cve_id_ignore_list'].parse('CVE-1234-1234,CVE-1111-1111')
    self.assertCountEqual(['CVE-1234-1234', 'CVE-1111-1111'],
                          detector_common_flags._CVE_ID_IGNORE_LIST.value)

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
      osv_id_ignore_list=['ASB-A-1111', 'ASB-A-1234'],
      cve_id_ignore_list=['CVE-1234-1234', 'CVE-1111-1111'],
      android_min_severity_level='MODERATE',
      android_spl='2020-05-01',
      sign_target_path_filter=['foo/bar/.*', 'foo/bar/.*', 'foo/baz/.*'],
      sign_target_arch=['X86'])
  def test_generate_vulnerability_filters_from_flags(self):
    vfilters = detector_common_flags.generate_vulnerability_filters_from_flags()
    self.assertLen(vfilters, 8)
    self.assertEqual(
        {type(vfilter) for vfilter in vfilters},
        {vulnerability_manager.OsvIdFilter,
         vulnerability_manager.CveIdFilter,
         vulnerability_manager.AndroidSeverityFilter,
         vulnerability_manager.AndroidSplFilter,
         vulnerability_manager.TargetPathFilter,
         vulnerability_manager.ArchitectureFilter,
         vulnerability_manager.DeprecatedSignatureFilter})

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

if __name__ == '__main__':
  absltest.main()
