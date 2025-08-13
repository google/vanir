# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

import multiprocessing.pool
import os
import subprocess
from unittest import mock

from google.cloud import storage
from vanir import file_path_utils
from vanir import signature
from vanir import vulnerability
from vanir import vulnerability_manager
from vanir.scanners import package_identifier
from vanir.scanners import repo_scanner
from vanir.scanners import scanner_base
from vanir.scanners import target_selection_strategy

from absl.testing import absltest

_TESTDATA_DIR = file_path_utils.get_root_file_path('testdata/')
_TEST_SIGNATURES_FILE = _TESTDATA_DIR + 'test_signatures.json'
_TEST_SIGNATURES_ZIP_FILE = _TESTDATA_DIR + 'test_signatures.zip'
_TEST_REPO_MAP = {
    'packages/apps/Bluetooth': 'platform/packages/apps/Bluetooth',
    'framework/base': 'platform/frameworks/base',
    'other': 'unaffected/proj',
}


class StrEndsWith(str):
  def __eq__(self, other):
    return other.endswith(self)


class RepoScannerTest(absltest.TestCase):
  def setUp(self):
    super().setUp()

    self._vuln_manager = vulnerability_manager.generate_from_json_string(
        open(_TEST_SIGNATURES_FILE, mode='rb').read())
    self._code_location = self.create_tempdir().full_path
    self.enter_context(
        mock.patch.object(
            os,
            'walk',
            autospec=True,
            return_value=[('foo', [], ['file1', 'file2'])],
        )
    )

    self._mock_repo_run_res = mock.create_autospec(
        subprocess.CompletedProcess,
        instance=True,
        returncode=0,
        stdout='\n'.join(
            [f'{subdir} : {proj}' for subdir, proj in _TEST_REPO_MAP.items()]
        ),
        stderr='',
    )
    self._mock_subprocess_run = self.enter_context(
        mock.patch.object(
            subprocess,
            'run',
            autospec=True,
            side_effect=[self._mock_repo_run_res],
        )
    )

    # Mock multiprocessing Pool: forkserver does not work with this test.
    self._mock_multiprocessing_pool = self.enter_context(
        mock.patch.object(multiprocessing.pool, 'Pool', autospec=True))
    self._mock_multiprocessing_pool.return_value.__enter__.return_value.starmap.side_effect = (
        lambda f, args: [f(*arg) for arg in args])

    # autospeccing dataclass doesn't work (https://bugs.python.org/issue36580)
    signatures = self._vuln_manager.signatures
    function_sig = [
        s for s in signatures if isinstance(s, signature.FunctionSignature)
    ][0]
    line_sig = [
        s for s in signatures if isinstance(s, signature.LineSignature)
    ][0]
    self._mock_findings_fwk_base = {
        function_sig: [signature.FunctionChunk(None, 'fwkbase1.java', '', 1)]}
    self._mock_stats_fwk_base = scanner_base.ScannedFileStats(1, 2)
    self._mock_findings_bt = {
        line_sig: [signature.LineChunk(None, 'bt1.java', '', [], [])]}
    self._mock_stats_bt = scanner_base.ScannedFileStats(3, 4)
    self._mock_scan = self.enter_context(
        mock.patch.object(
            scanner_base, 'scan', autospec=True,
            side_effect=[
                (self._mock_findings_bt, self._mock_stats_bt),
                (self._mock_findings_fwk_base, self._mock_stats_fwk_base)]))

  @mock.patch.object(os, 'environ', new={'PYTHONSAFEPATH': '1', 'OTHER': 'ENV'})
  def test_scan_with_python_safe_path_env(self):
    scanner = repo_scanner.RepoScanner('Android', self._code_location)
    _ = scanner.scan(override_vuln_manager=self._vuln_manager)
    self._mock_subprocess_run.assert_called_once()
    self.assertNotIn(
        'PYTHONSAFEPATH', self._mock_subprocess_run.call_args.kwargs['env'])
    self.assertIn('OTHER', self._mock_subprocess_run.call_args.kwargs['env'])

  @mock.patch.object(os, 'environ', new={'OTHER': 'ENV'})
  def test_scan_without_python_safe_path_env(self):
    scanner = repo_scanner.RepoScanner('Android', self._code_location)
    _ = scanner.scan(override_vuln_manager=self._vuln_manager)
    self._mock_subprocess_run.assert_called_once()
    self.assertIsNone(self._mock_subprocess_run.call_args.kwargs['env'])

  def test_scan(self):
    scanner = repo_scanner.RepoScanner('Android', self._code_location)
    findings, stats, vuln_manager = scanner.scan(
        override_vuln_manager=self._vuln_manager)
    self._mock_subprocess_run.assert_called_once_with(
        ['repo', 'list'], cwd=self._code_location,
        check=True, text=True, env=mock.ANY,
        stdin=None, stdout=mock.ANY, stderr=mock.ANY)
    id_to_files = {sig.signature_id: [chunk.target_file for chunk in finding]
                   for sig, finding in findings.items()}
    self._mock_scan.assert_has_calls([
        mock.call(
            StrEndsWith('packages/apps/Bluetooth'),
            mock.ANY,
            target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH,
        ),
        mock.call(
            StrEndsWith('framework/base'),
            mock.ANY,
            target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH,
        ),
    ])
    self.assertDictEqual(
        id_to_files, {
            'ASB-A-281018094-2d96898e': ['packages/apps/Bluetooth/bt1.java'],
            'ASB-A-111893654-8ead4b9c': ['framework/base/fwkbase1.java']})
    # scanned files: fwk 1, bt 3. skipped: fwk 2, bt 4, unaffected projs 2
    self.assertEqual(stats, scanner_base.ScannedFileStats(4, 8))
    self.assertSameElements(
        [sig.signature_id for sig in vuln_manager.signatures],
        ['ASB-A-281018094-2d96898e', 'ASB-A-281018094-97ec235e',
         'ASB-A-111893654-8ead4b9c', 'ASB-A-111893654-2d607d27'])

  def test_scan_with_errors(self):
    exception = Exception('scan error')
    self._mock_scan.side_effect = [
        (self._mock_findings_bt, self._mock_stats_bt),
        ({}, scanner_base.ScannedFileStats(10, 10, errors=[exception])),
    ]
    scanner = repo_scanner.RepoScanner('Android', self._code_location)
    _, stats, _ = scanner.scan(override_vuln_manager=self._vuln_manager)
    self.assertEqual(stats.errors, [exception])

  def test_scan_with_kernel_repo(self):
    test_repo_map = _TEST_REPO_MAP.copy()
    test_repo_map['kernel'] = 'kernel'
    test_repo_map['kernel_custom/drivers'] = 'kernel/custom/drivers'
    self._mock_repo_run_res.stdout = '\n'.join(
        [f'{subdir} : {proj}' for subdir, proj in test_repo_map.items()]
    )
    self._mock_scan.side_effect = [
        (self._mock_findings_bt, self._mock_stats_bt),
        (self._mock_findings_fwk_base, self._mock_stats_fwk_base),
        ({}, scanner_base.ScannedFileStats(10, 10)),
        ({}, scanner_base.ScannedFileStats(10, 10)),
        ({}, scanner_base.ScannedFileStats(10, 10)),
    ]

    scanner = repo_scanner.RepoScanner('Android', self._code_location)
    with mock.patch.object(
        package_identifier.PackageIdentifier,
        'packages_for_repo',
        side_effect=[
            {'platform/packages/apps/Bluetooth'},  # packages/apps/Bluetooth
            {'platform/frameworks/base'},  # framework/base
            set(),  # other
            {vulnerability.MetaPackage.ANDROID_KERNEL},  # kernel
            set(),  # kernel/custom/drivers
        ],
    ) as mock_packages_for_repo:
      # since there is one kernel repo, other unknown repos will be scanned
      # as kernel repos.
      _, stats, _ = scanner.scan(override_vuln_manager=self._vuln_manager)
      self.assertEqual(mock_packages_for_repo.call_count, 5)
    # scanned files: fwk 1, bt 3, unaffected/proj 10, kernel 10, drivers 10
    # skipped: fwk 2, bt 4, unaffected/proj 10, kernel 10, drivers 10
    self.assertEqual(stats, scanner_base.ScannedFileStats(34, 36))

  def test_scan_with_pkg_agnostic_analysis(self):
    self._mock_scan.side_effect = [
        (self._mock_findings_bt, self._mock_stats_bt),
        (self._mock_findings_fwk_base, self._mock_stats_fwk_base),
        ({}, scanner_base.ScannedFileStats(10, 10)),
    ]

    scanner = repo_scanner.RepoScanner(
        'Android', self._code_location, package_agnostic_analysis=True
    )
    _, stats, _ = scanner.scan(override_vuln_manager=self._vuln_manager)
    # scanned files: fwk 1, bt 3, unaffected/proj 10
    # skipped: fwk 2, bt 4, unaffected/proj 10
    self.assertEqual(stats, scanner_base.ScannedFileStats(14, 16))

  @mock.patch.object(storage, 'Client', autospec=True)
  def test_scan_osv(self, mock_storage_client):
    mock_blob = mock.MagicMock()

    def download_to_file(file_obj):
      with open(
          _TEST_SIGNATURES_ZIP_FILE, 'rb'
      ) as f:
        file_obj.write(f.read())

    mock_blob.download_to_file.side_effect = download_to_file
    mock_bucket = mock.MagicMock()
    mock_bucket.blob.return_value = mock_blob
    mock_storage_client.create_anonymous_client.return_value.bucket.return_value = (
        mock_bucket
    )

    scanner = repo_scanner.RepoScanner('Android', self._code_location)
    _, _, vuln_manager = scanner.scan()
    self.assertEqual(
        {sig.signature_id for sig in vuln_manager.signatures},
        {sig.signature_id for sig in self._vuln_manager.signatures},
    )


if __name__ == '__main__':
  absltest.main()
