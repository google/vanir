# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

from unittest import mock
import requests

from vanir import file_path_utils
from vanir import vulnerability
from vanir import vulnerability_manager
from vanir.scanners import package_scanner
from vanir.scanners import scanner_base

from absl.testing import absltest

_TESTDATA_DIR = file_path_utils.get_root_file_path('testdata/')
_TEST_SIGNATURES_FILE = _TESTDATA_DIR + 'test_signatures.json'


class PackageScannerTest(absltest.TestCase):
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

  def test_scan_frameworks_base(self):
    scanner = package_scanner.PackageScanner(
        'Android', 'platform/frameworks/base', self._code_location)
    findings, stats, vul_manager = scanner.scan(
        override_vuln_manager=self._vul_manager)
    self.assertIs(findings, self._mock_findings)
    self.assertIs(stats, self._mock_stats)
    self.assertSetEqual(
        set(sig.signature_id for sig in vul_manager.signatures),
        set(['ASB-A-281018094-2d96898e']))

  def test_scan_kernel_with_fixed_package_name(self):
    scanner = package_scanner.PackageScanner(
        'Android', ':linux_kernel:', self._code_location)
    findings, stats, vul_manager = scanner.scan(
                override_vuln_manager=self._vul_manager)
    self.assertIs(findings, self._mock_findings)
    self.assertIs(stats, self._mock_stats)
    self.assertSetEqual(
        set(sig.signature_id for sig in vul_manager.signatures),
        set(['ASB-A-111893654-8ead4b9c', 'ASB-A-111893654-2d607d27']))

  def test_scan_kernel_with_metapackage(self):
    scanner = package_scanner.PackageScanner(
        'Android',
        vulnerability.MetaPackage.ANDROID_KERNEL,
        self._code_location,
    )
    findings, stats, vul_manager = scanner.scan(
        override_vuln_manager=self._vul_manager
    )
    self.assertIs(findings, self._mock_findings)
    self.assertIs(stats, self._mock_stats)
    self.assertSetEqual(
        set(sig.signature_id for sig in vul_manager.signatures),
        set(['ASB-A-111893654-8ead4b9c', 'ASB-A-111893654-2d607d27']),
    )

  def test_scan_with_no_matching_signatures(self):
    scanner = package_scanner.PackageScanner(
        'NonExistingEcosystem', ':linux_kernel:', self._code_location
    )
    _, _, vul_manager = scanner.scan(override_vuln_manager=self._vul_manager)
    self.assertEmpty(vul_manager.signatures)

    scanner = package_scanner.PackageScanner(
        'Android', 'non/existing/package', self._code_location
    )
    _, _, vul_manager = scanner.scan(override_vuln_manager=self._vul_manager)
    self.assertEmpty(vul_manager.signatures)

  @mock.patch.object(requests.sessions, 'Session', autospec=True)
  def test_scan_frameworks_base_from_osv(self, mock_session_class):
    text = b'{"vulns":' + open(_TEST_SIGNATURES_FILE, mode='rb').read() + b'}'
    mock_session_class().post.return_value = mock.Mock(text=text)
    scanner = package_scanner.PackageScanner(
        'Android', 'platform/frameworks/base', self._code_location
    )
    findings, stats, vul_manager = scanner.scan(
        override_vuln_manager=self._vul_manager)
    self.assertIs(findings, self._mock_findings)
    self.assertIs(stats, self._mock_stats)
    self.assertSetEqual(
        set(sig.signature_id for sig in vul_manager.signatures),
        set(['ASB-A-281018094-2d96898e'])
    )


if __name__ == '__main__':
  absltest.main()
