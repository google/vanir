import itertools
# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

from unittest import mock
import requests

from vanir import file_path_utils
from vanir import version_extractor
from vanir import vulnerability_manager
from vanir.scanners import android_kernel_scanner
from vanir.scanners import scanner_base

from absl.testing import absltest

_TESTDATA_DIR = file_path_utils.get_root_file_path('testdata/')
_TEST_SIGNATURES_FILE = _TESTDATA_DIR + 'test_signatures.json'


class AndroidKernelScannerTest(absltest.TestCase):
  def setUp(self):
    super().setUp()

    self._code_location = self.create_tempdir().full_path

    self._mock_findings = mock.create_autospec(
        scanner_base.Findings, instance=True)
    self._mock_version = self.enter_context(
        mock.patch.object(
            version_extractor, 'extract_version',
            autospec=True, return_value='6.5.1'))
    self._fake_base_scanner_stats = scanner_base.ScannedFileStats(1, 2, None)
    self._mock_scan = self.enter_context(
        mock.patch.object(
            scanner_base, 'scan', autospec=True,
            return_value=(self._mock_findings, self._fake_base_scanner_stats)))

  def test_scan(self):
    override_vuln_manager = vulnerability_manager.generate_from_json_string(
        open(_TEST_SIGNATURES_FILE, mode='rb').read())
    scanner = android_kernel_scanner.AndroidKernelScanner(self._code_location)
    findings, stats, output_vul_manager = scanner.scan(
        override_vuln_manager=override_vuln_manager
    )
    self.assertIs(findings, self._mock_findings)
    self.assertEqual(
        stats, scanner_base.ScannedFileStats(1, 2, {'version': '6.5.1'}))
    self.assertSameElements(
        [sig.signature_id for sig in output_vul_manager.signatures],
        ['ASB-A-111893654-8ead4b9c', 'ASB-A-111893654-2d607d27'])

  @mock.patch.object(requests.sessions, 'Session', autospec=True)
  def test_scan_osv(self, mock_session_class):
    text = b'{"vulns":' + open(_TEST_SIGNATURES_FILE, mode='rb').read() + b'}'
    mock_session_class().post.side_effect = (
        itertools.chain(
            [mock.Mock(text=text)], itertools.repeat(mock.Mock(text=b'{}'))
        )
    )
    scanner = android_kernel_scanner.AndroidKernelScanner(self._code_location)
    _, _, vul_manager = scanner.scan()
    self.assertEqual(
        {sig.signature_id for sig in vul_manager.signatures},
        {'ASB-A-111893654-8ead4b9c', 'ASB-A-111893654-2d607d27'}
    )


if __name__ == '__main__':
  absltest.main()
