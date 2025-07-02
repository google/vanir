# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

from unittest import mock

from vanir import file_path_utils
from vanir import vulnerability_manager
from vanir.scanners import offline_directory_scanner
from vanir.scanners import scanner_base

from absl.testing import absltest

_TESTDATA_DIR = file_path_utils.get_root_file_path('testdata/')
_TEST_SIGNATURES_FILE = _TESTDATA_DIR + 'test_signatures.json'


class OfflineDirectoryScannerTest(absltest.TestCase):
  def setUp(self):
    super().setUp()

    self._vul_manager = vulnerability_manager.generate_from_json_string(
        open(_TEST_SIGNATURES_FILE, mode='rb').read())
    self._code_location = self.create_tempdir().full_path

    self._mock_findings = mock.create_autospec(
        scanner_base.Findings, instance=True)
    self._mock_stats = mock.create_autospec(
        scanner_base.ScannedFileStats, instance=True)
    self._mock_scan = self.enter_context(
        mock.patch.object(
            scanner_base, 'scan', autospec=True,
            return_value=(self._mock_findings, self._mock_stats)))

  def test_scan_missing_flag(self):
    with self.assertRaisesRegex(
        ValueError,
        r'offline_directory_scanner requires at least one '
        r'--vulnerability_file_name'):
      offline_directory_scanner.OfflineDirectoryScanner(
          self._code_location).scan()

  def test_scan(self):
    scanner = offline_directory_scanner.OfflineDirectoryScanner(
        self._code_location)
    findings, stats, vul_manager = scanner.scan(
        override_vuln_manager=self._vul_manager)
    self.assertIs(findings, self._mock_findings)
    self.assertIs(stats, self._mock_stats)
    self.assertSetEqual(
        set(sig.signature_id for sig in vul_manager.signatures),
        set(['ASB-A-281018094-2d96898e', 'ASB-A-281018094-97ec235e',
             'ASB-A-111893654-8ead4b9c', 'ASB-A-111893654-2d607d27']))


if __name__ == '__main__':
  absltest.main()
