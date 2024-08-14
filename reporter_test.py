# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for Reporter."""

import dataclasses
from unittest import mock

from vanir import reporter
from vanir import vulnerability_manager

from absl.testing import absltest


_TEST_SIGN_ID = 'asb-a-test-sign-1234'
_TEST_TARGET_FILE = 'foo/bar/target_file.c'
_TEST_TARGET_FUNC = 'target_func1'
_TEST_SOURCE = 'https://android.googlesource.com/some/test/source'
_TEST_UNPATCHED_FILE = 'foo/bar/unpatched_file.c'
_TEST_UNPATCHED_FUNC = 'unpatched_func1'
_TEST_IS_NON_TARGET_MATCH = True


class ReporterTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self._test_report = reporter.Report(
        _TEST_SIGN_ID,
        _TEST_TARGET_FILE,
        _TEST_TARGET_FUNC,
        _TEST_SOURCE,
        _TEST_UNPATCHED_FILE,
        _TEST_UNPATCHED_FUNC,
        _TEST_IS_NON_TARGET_MATCH,
    )

  def test_get_simple_report(self):
    expected_simple_report = 'foo/bar/unpatched_file.c::unpatched_func1()'
    self.assertEqual(
        self._test_report.get_simple_report(), expected_simple_report
    )

  def test_generate_report_book(self):
    reports = []
    for i in range(10):
      new_sign_id = _TEST_SIGN_ID + str(i)
      new_source = _TEST_SOURCE + str(i)
      report = dataclasses.replace(
          self._test_report,
          signature_id=new_sign_id,
          signature_source=new_source,
      )
      reports.append(report)
    mock_vul_manager = mock.create_autospec(
        vulnerability_manager.VulnerabilityManager, instance=True
    )
    mock_vul_manager.sign_id_to_osv_id.side_effect = (
        lambda sign_id: 'osv-id-%s' % sign_id[-1]
    )
    mock_vul_manager.osv_id_to_cve_ids.side_effect = (
        lambda osv_id: [osv_id.replace('osv', 'cve')]
    )
    test_report_book = reporter.ReportBook(reports, mock_vul_manager)
    expected_unpatched_vuls = ['osv-id-%d' % i for i in range(10)]
    self.assertEqual(
        test_report_book.unpatched_vulnerabilities, expected_unpatched_vuls
    )
    expected_unpatched_cves = ['cve-id-%d' % i for i in range(10)]
    self.assertEqual(test_report_book.unpatched_cves, expected_unpatched_cves)
    embedded_reports = []
    for osv_id in test_report_book.unpatched_vulnerabilities:
      rgroup = test_report_book.get_report_group(osv_id)
      embedded_reports += rgroup.reports
    self.assertCountEqual(embedded_reports, reports)


if __name__ == '__main__':
  absltest.main()
