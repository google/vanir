# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for detector_runner."""

import builtins
import datetime
import io
import json
import logging
import os
import re
from typing import Optional, Sequence, Tuple
from unittest import mock

from absl import app
from absl.testing import flagsaver
from vanir import detector_runner
from vanir import osv_client
from vanir import signature
from vanir import vulnerability_manager
from vanir import vulnerability_overwriter
from vanir.language_parsers import common as language_parsers_common
from vanir.scanners import scanner_base
from vanir.scanners import target_selection_strategy

from absl.testing import absltest


_TEST_TARGET_ROOT = '/foo/bar/baz/kernel'
_TEST_OSV_ID = 'ASB-A-test-1234'
_TEST_CVE_ID1 = 'CVE-1234-12345'
_TEST_CVE_ID2 = 'CVE-999-99999'
_TEST_SIGN_ID_1 = 'ASB-A-test-1234-abcdef1234'
_TEST_SIGN_ID_2 = 'ASB-A-test-1234-abcdef4321'
_TEST_TARGET_FILE = 'foo/bar/baz.c'
_TEST_NON_TARGET_FILE = 'foo/bar/baz.h'
_TEST_TARGET_FUNC = 'testfunc'
_TEST_SOURCE = 'http://android.googlesource.com/hellworld'
_TEST_ANALYZED_FILES = 20
_TEST_SKIPPED_FILES = 20
_TEST_OSV_SIGNS = [
    {
        'id': _TEST_SIGN_ID_1,
        'signature_type': 'Line',
        'signature_version': 'v1234',
        'source': _TEST_SOURCE,
        'target': {'file': _TEST_TARGET_FILE},
        'deprecated': False,
        'digest': {'line_hashes': [1, 2, 3, 4], 'threshold': 0.9},
    },
    {
        'id': _TEST_SIGN_ID_2,
        'signature_type': 'Function',
        'signature_version': 'v1234',
        'source': _TEST_SOURCE,
        'target': {'file': _TEST_TARGET_FILE, 'function': _TEST_TARGET_FUNC},
        'deprecated': False,
        'digest': {'function_hash': 1234, 'length': 50},
    },
]
_TEST_VUL = {
    'id':
        _TEST_OSV_ID,
    'modified':
        '1985-11-11T21:26:24Z',
    'aliases': [_TEST_CVE_ID1, _TEST_CVE_ID2],
    'affected': [{
        'package': {
            'ecosystem': 'Android',
            'name': 'Kernel'
        },
        'ecosystem_specific': {
            'vanir_signatures': _TEST_OSV_SIGNS
        }
    }]
}


class TestScanner(scanner_base.ScannerBase):

  def __init__(self, code_location: str, opt_arg: bool = True):
    """test_scanner init doc."""
    self._code_location = code_location
    self._opt_arg = opt_arg

  @classmethod
  def name(cls) -> str:
    return 'test_scanner'

  def scan(
      self,
      strategy: target_selection_strategy.Strategy = (
          target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH
      ),
      override_vuln_manager: Optional[
          vulnerability_manager.VulnerabilityManager
      ] = None,
      extra_vulnerability_filters: Optional[
          Sequence[vulnerability_manager.VulnerabilityFilter]
      ] = None,
      vulnerability_overwrite_specs: Optional[
          Sequence[vulnerability_overwriter.OverwriteSpec]
      ] = None
  ) -> Tuple[
      scanner_base.Findings,
      scanner_base.ScannedFileStats,
      vulnerability_manager.VulnerabilityManager,
  ]:
    findings, stats = scanner_base.scan(
        self._code_location, override_vuln_manager.signatures, strategy=strategy
    )
    return findings, stats, override_vuln_manager


class TestScanner2(scanner_base.ScannerBase):
  """TestScanner2 class doc."""

  def __init__(
      self,
      req_arg: str,
      *req_vararg: str,
      optional_kw_only: Optional[str] = None
  ):
    """TestScanner2 init doc."""
    pass

  @classmethod
  def name(cls) -> str:
    return 'test_scanner2'

  def scan(
      self,
      strategy: target_selection_strategy.Strategy = (
          target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH
      ),
      override_vuln_manager: Optional[
          vulnerability_manager.VulnerabilityManager
      ] = None,
      extra_vulnerability_filters: Optional[
          Sequence[vulnerability_manager.VulnerabilityFilter]
      ] = None,
      vulnerability_overwrite_specs: Optional[
          Sequence[vulnerability_overwriter.OverwriteSpec]
      ] = None
  ) -> Tuple[
      scanner_base.Findings,
      scanner_base.ScannedFileStats,
      vulnerability_manager.VulnerabilityManager,
  ]:
    return ({}, scanner_base.ScannedFileStats(0, 0),
            vulnerability_manager.generate_from_json_string('[]'))


class TestNonCliScanner(scanner_base.ScannerBase):

  def __init__(
      self, required_arg: str, *vararg: str, kw_only: str
  ):  # pylint: disable=super-init-not-called
    pass

  @classmethod
  def name(cls) -> str:
    return 'test_non_cli_scanner'

  def scan(
      self,
      strategy: target_selection_strategy.Strategy = (
          target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH
      ),
      override_vuln_manager: Optional[
          vulnerability_manager.VulnerabilityManager
      ] = None,
      extra_vulnerability_filters: Optional[
          Sequence[vulnerability_manager.VulnerabilityFilter]
      ] = None,
  ) -> Tuple[
      scanner_base.Findings,
      scanner_base.ScannedFileStats,
      vulnerability_manager.VulnerabilityManager,
  ]:
    pass


class TestChildScanner(TestScanner):

  @classmethod
  def name(cls) -> str:
    return 'test_child_scanner'


class DetectorRunnerTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    # detector_runner._get_all_scanners.cache_clear()
    self._report_file_prefix = '/tmp/vanir_test_report_file_prefix'
    self._json_report_file = self.create_tempfile(
        self._report_file_prefix + '.json', mode='wt'
    )
    self._html_report_file = self.create_tempfile(
        self._report_file_prefix + '.html', mode='wt'
    )
    self._test_vul_file = self.create_tempfile(content=json.dumps([_TEST_VUL]))
    mock_line_sign = mock.create_autospec(
        signature.LineSignature,
        instance=True,
        signature_id=_TEST_SIGN_ID_1,
        target_file=_TEST_TARGET_FILE,
        target_function=None,
        source=_TEST_SOURCE,
        match_only_versions=None,
    )
    mock_line_chunk_base = mock.create_autospec(
        language_parsers_common.LineChunkBase, instance=True)
    mock_line_chunk_base.name = None
    mock_line_chunk = mock.create_autospec(
        signature.LineChunk,
        instance=True,
        target_file=_TEST_TARGET_FILE,
        base=mock_line_chunk_base)
    mock_func_sign = mock.create_autospec(
        signature.FunctionSignature,
        instance=True,
        signature_id=_TEST_SIGN_ID_2,
        target_file=_TEST_TARGET_FILE,
        target_function=_TEST_TARGET_FUNC,
        source=_TEST_SOURCE,
        match_only_versions=None,
    )
    mock_func_chunk_base = mock.create_autospec(
        language_parsers_common.FunctionChunkBase, instance=True)
    mock_func_chunk_base.name = _TEST_TARGET_FUNC
    mock_func_chunk = mock.create_autospec(
        signature.FunctionChunk,
        instance=True,
        target_file=_TEST_NON_TARGET_FILE,
        base=mock_func_chunk_base)
    mock_findings = {
        mock_line_sign: [mock_line_chunk],
        mock_func_sign: [mock_func_chunk]
    }
    mock_stats = mock.create_autospec(
        scanner_base.ScannedFileStats,
        instance=True,
        analyzed_files=_TEST_ANALYZED_FILES,
        skipped_files=_TEST_SKIPPED_FILES,
        errors=[IOError('error message')],
    )
    self._mock_scan = self.enter_context(
        mock.patch.object(
            scanner_base, 'scan', autospec=True,
            return_value=(mock_findings, mock_stats)))
    self._signatures = None

    self.mock_vul = {
        'id': 'ASB-A-MOCK-VUL',
    }
    self.enter_context(
        mock.patch.object(
            osv_client.OsvClient,
            'get_vuln',
            return_value=self.mock_vul,
            autospec=True,
        )
    )

  def test_calling_bad_scanner(self):
    with flagsaver.flagsaver(
        vulnerability_file_name=[self._test_vul_file.full_path],
    ):
      with self.assertRaisesRegex(
          app.UsageError,
          r'(?s)test_non_exist_scanner is not a valid scanner.*'
          r'test_scanner2: TestScanner2 class doc.*',
      ):
        detector_runner.main(['', 'test_non_exist_scanner'])
      with self.assertRaisesRegex(
          app.UsageError,
          r'(?s)test_non_cli_scanner is not a valid scanner.*'
          r'test_scanner2: TestScanner2 class doc.*',
      ):
        detector_runner.main(['', 'test_non_cli_scanner'])

  def test_wrong_scanner_args(self):
    with flagsaver.flagsaver(
        vulnerability_file_name=[self._test_vul_file.full_path],
    ):
      scanner_msg = re.compile(
          r'.*Usage .*test_scanner code_location \[opt_arg\].*',
          re.DOTALL,
      )
      scanner2_msg = re.compile(
          r'.*Usage .*test_scanner2 req_arg req_vararg \[req_vararg\.\.\.\].*',
          re.DOTALL,
      )
      with self.assertRaisesRegex(app.UsageError, scanner_msg):
        detector_runner.main(['', 'test_scanner'])
      with self.assertRaisesRegex(app.UsageError, scanner_msg):
        detector_runner.main(['', 'test_scanner', 'codedir', 'True', 'extra'])
      with self.assertRaisesRegex(app.UsageError, scanner2_msg):
        detector_runner.main(['', 'test_scanner2', 'req'])

  def test_correct_scanner_args(self):
    with flagsaver.flagsaver(
        vulnerability_file_name=[self._test_vul_file.full_path],
    ):
      detector_runner.main(['', 'test_scanner2',
                            'req', 'vararg1', 'vararg2', 'vararg3'])

  def test_get_all_scanners(self):
    scanners = detector_runner._get_all_scanners()
    self.assertIn('test_scanner', scanners)
    self.assertIn('test_scanner2', scanners)
    self.assertIn('test_child_scanner', scanners)
    self.assertNotIn('test_non_cli_scanner', scanners)
    self.assertEqual(scanners['test_scanner'].name(), 'test_scanner')
    self.assertEqual(scanners['test_scanner2'].name(), 'test_scanner2')
    self.assertEqual(
        scanners['test_child_scanner'].name(), 'test_child_scanner'
    )

  def test_get_all_scanners_fails_with_duplicated_scanner_name(self):
    with mock.patch.object(TestChildScanner, 'name') as mock_name:
      mock_name.return_value = 'test_scanner'
      msg = 'Found more than one scanner with the same name "test_scanner"'
      with self.assertRaisesRegex(ValueError, msg):
        detector_runner._get_all_scanners()

  def test_is_valid_scanner_args(self):
    self.assertFalse(
        detector_runner._is_valid_scanner_args(TestScanner, [], {}),
        'Should fail with not enough args.',
    )
    self.assertTrue(
        detector_runner._is_valid_scanner_args(TestScanner, ['/codedir'], {}),
        'Should pass with all required args.',
    )
    self.assertTrue(
        detector_runner._is_valid_scanner_args(
            TestScanner, [], {'code_location': '/codedir'}
        ),
        'Should pass with all required args.',
    )
    self.assertTrue(
        detector_runner._is_valid_scanner_args(
            TestScanner2, ['req'], {'req_vararg': ['asdf']},
        ),
        'Should pass with required args split between positional and kwargs.',
    )
    self.assertTrue(
        detector_runner._is_valid_scanner_args(
            TestScanner, ['codedir', 'True'], {}
        ),
        'Should pass with all required args and some optional args.',
    )
    self.assertTrue(
        detector_runner._is_valid_scanner_args(
            TestScanner, ['codedir'], {'opt_arg': False},
        ),
        'Should pass with all required args and some optional args.',
    )
    self.assertFalse(
        detector_runner._is_valid_scanner_args(
            TestScanner, ['codedir', 'True', 'extra'], {},
        ),
        'Should fail with extra args.',
    )
    self.assertFalse(
        detector_runner._is_valid_scanner_args(
            TestScanner, ['codedir', 'True'], {'opt_arg': False},
        ),
        'Should fail with duplicate args.',
    )
    self.assertFalse(detector_runner._is_valid_scanner_args(
        TestScanner2, ['req'], {},
    ))
    self.assertTrue(detector_runner._is_valid_scanner_args(
        TestScanner2, ['req', 'vararg1', 'vararg2', 'vararg3'], {},
    ))

  def test_main(self):
    mock_stdout = io.StringIO()
    with flagsaver.flagsaver(
        vulnerability_file_name=[self._test_vul_file.full_path],
        report_file_name_prefix=self._report_file_prefix,
    ):
      with mock.patch('sys.stdout', mock_stdout):
        detector_runner.main(['', 'test_scanner', _TEST_TARGET_ROOT])

    self._mock_scan.assert_called_with(
        _TEST_TARGET_ROOT,
        mock.ANY,
        strategy=target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH,
    )

    used_sign_ids = [
        sign.signature_id
        for sign in self._mock_scan.call_args.args[1]
    ]
    self.assertCountEqual(used_sign_ids, [_TEST_SIGN_ID_1, _TEST_SIGN_ID_2])
    json_report = json.loads(self._json_report_file.read_text())
    self.assertIn('covered_cves', json_report)
    self.assertIn('missing_patches', json_report)

    expected_missing_patches = [{
        'ID': _TEST_OSV_ID,
        'CVE': [_TEST_CVE_ID1, _TEST_CVE_ID2],
        'OSV': f'https://osv.dev/vulnerability/{_TEST_OSV_ID}',
        'details': [
            {
                'unpatched_code': _TEST_TARGET_FILE,
                'patch': _TEST_SOURCE,
                'is_non_target_match': False,
                'matched_signature': _TEST_SIGN_ID_1,
            },
            {
                'unpatched_code': (
                    f'{_TEST_NON_TARGET_FILE}::{_TEST_TARGET_FUNC}'),
                'patch': _TEST_SOURCE,
                'is_non_target_match': True,
                'matched_signature': _TEST_SIGN_ID_2,
            },
        ],
    }]
    self.assertCountEqual(
        json_report['missing_patches'], expected_missing_patches
    )
    expected_stdout = (
        r'Found [0-9]+ potentially unpatched vulnerabilities: %s, %s'
        % (_TEST_CVE_ID1, _TEST_CVE_ID2) +
        r'\nDetailed report:\n.*'
    )
    self.assertRegex(mock_stdout.getvalue(), expected_stdout)

    html_report = self._html_report_file.read_text()
    expected_html_report = """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Vanir Detector Report /tmp/vanir_test_report_file_prefix.html</title>
    <style>
    body {
      font-family: Roboto, sans-serif;
    }
    table {
      border-collapse: collapse;
      border: 2px solid black;
    }
    th, td {
      border: 1px solid gray;
      word-break: keep-all;
      padding: 5px;
      vertical-align: top;
    }
    h3 {
      padding: 0.3em;
      background-color: lightgray;
    }
    .expand-toggle {
        cursor: pointer;
    }
    .expand-toggle.collapsed:before {
      content: "▸ ";
    }
    .expand-toggle:before {
      content: "▾ ";
    }
    .expand-toggle.collapsed + * {
        display: none;
    }
    </style>
    <script>
    function toggle(element) {
      element.classList.toggle("collapsed");
    }
    </script>
  </head>
  <body>
    <h1>Vanir Detector Report /tmp/vanir_test_report_file_prefix.html</h1>
    <h3 onclick="toggle(this);" class="expand-toggle collapsed">Options</h3>
    <pre style="white-space: pre-wrap;"></pre>
    <h3 onclick="toggle(this);" class="expand-toggle collapsed">
    Coverage (2 CVEs)</h3>
    <table>
      <tr>
        <th>Covered CVEs</th>
        <td>
        <pre><nobr>CVE-1234-12345&nbsp;</nobr>&nbsp;<wbr><nobr>CVE-999-99999&nbsp;&nbsp;</nobr>&nbsp;<wbr>
        </pre>
        </td>
      </tr>
      <tr>
        <th>Unpatched CVEs</th>
        <td>
        <pre><nobr>CVE-1234-12345&nbsp;</nobr>&nbsp;<wbr><nobr>CVE-999-99999&nbsp;&nbsp;</nobr>&nbsp;<wbr>
        </pre>
        </td>
      </tr>
    </table>
    <h3 onclick="toggle(this);" class="expand-toggle">
    Missing Patches in Target Files (in 1 vuln)</h3>
    <table>
      <tr>
        <td>ASB-A-test-1234</td>
        <td>
          foo/bar/baz.c  (<a href="http://android.googlesource.com/hellworld">patch</a>, ASB-A-test-1234-abcdef1234)<br>
          OSV: <a href="https://osv.dev/vulnerability/ASB-A-test-1234">https://osv.dev/vulnerability/ASB-A-test-1234</a><br>
          CVE: CVE-1234-12345 CVE-999-99999 <br>
        </td>
      </tr>
    </table>
    <h3 onclick="toggle(this);" class="expand-toggle">
    Missing Patches in Non-target Files (in 1 vuln)</h3>
    <table>
      <tr>
        <td>ASB-A-test-1234</td>
        <td>
          foo/bar/baz.h::testfunc()  (<a href="http://android.googlesource.com/hellworld">patch</a>, ASB-A-test-1234-abcdef4321)<br>
          OSV: <a href="https://osv.dev/vulnerability/ASB-A-test-1234">https://osv.dev/vulnerability/ASB-A-test-1234</a><br>
          CVE: CVE-1234-12345 CVE-999-99999 <br>
        </td>
      </tr>
    </table>
    <h3 onclick="toggle(this);" class="expand-toggle">Errors(1)</h3>
    <table><tr><td>error message</td></tr></table>
    <h3 onclick="toggle(this);" class="expand-toggle collapsed">Scan metadata and stats</h3>
    <table>
      <tr>
        <td>analyzed_files</td>
        <td>20</td>
      </tr>
      <tr>
        <td>skipped_files</td>
        <td>20</td>
      </tr>
    </table>
  </body>
</html>
    """
    self.assertEqual(
        ''.join(html_report.split()),
        ''.join(expected_html_report.split()),
    )

  def test_main_with_full_scan(self):
    with flagsaver.flagsaver(
        vulnerability_file_name=[self._test_vul_file.full_path],
        report_file_name_prefix=self._report_file_prefix,
        target_selection_strategy=target_selection_strategy.Strategy.ALL_FILES,
    ):
      detector_runner.main(['', 'test_scanner', _TEST_TARGET_ROOT])

    self._mock_scan.assert_called_with(
        _TEST_TARGET_ROOT,
        mock.ANY,
        strategy=target_selection_strategy.Strategy.ALL_FILES,
    )

  @mock.patch.object(os, 'makedirs', autospec=True)
  def test_main_with_default_report_file(self, _):
    class MockDatetime(datetime.datetime):
      """Direct datetime mock is prohibited; mock it using this wrapper."""

    datetime.datetime = MockDatetime
    test_datetime = datetime.datetime(2022, 10, 4, 10, 10)
    # |mock_file_open| is used for both input vuln file and output sign file.
    mock_file_open = mock.mock_open(read_data=json.dumps([_TEST_VUL]))
    with mock.patch.object(datetime.datetime, 'now') as mock_now:
      mock_now.return_value = test_datetime
      with flagsaver.flagsaver(
          vulnerability_file_name=[self._test_vul_file.full_path]):
        with mock.patch.object(os.path, 'isfile', autospec=True):
          with mock.patch.object(builtins, 'open', mock_file_open):
            detector_runner.main(['', 'test_scanner', _TEST_TARGET_ROOT])
    expected_report_file = '/tmp/vanir/report-%s.json' % test_datetime.strftime(
        '%Y%m%d%H%M%S'
    )
    mock_file_open.assert_has_calls([mock.call(expected_report_file, 'w')])

  def test_main_with_filter_flags(self):
    with flagsaver.flagsaver(
        vulnerability_file_name=[self._test_vul_file.full_path],
        report_file_name_prefix=self._report_file_prefix,
        osv_id_ignore_list=[_TEST_OSV_ID],
    ):
      detector_runner.main(['', 'test_scanner', _TEST_TARGET_ROOT])
      self._mock_scan.assert_called_with(
          _TEST_TARGET_ROOT,
          (),
          strategy=target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH,
      )

  def test_main_with_path_filter(self):
    with flagsaver.flagsaver(
        vulnerability_file_name=[self._test_vul_file.full_path],
        report_file_name_prefix=self._report_file_prefix,
        ignore_scan_path=[_TEST_TARGET_FILE],
    ):
      detector_runner.main(['', 'test_scanner', _TEST_TARGET_ROOT])

    json_report = json.loads(self._json_report_file.read_text())
    self.assertIn('covered_cves', json_report)
    self.assertIn('missing_patches', json_report)

    expected_missing_patches = [{
        'ID': _TEST_OSV_ID,
        'CVE': [_TEST_CVE_ID1, _TEST_CVE_ID2],
        'OSV': f'https://osv.dev/vulnerability/{_TEST_OSV_ID}',
        'details': [
            {
                # Note that _TEST_TARGET_FILE is not in this list
                'unpatched_code': (
                    f'{_TEST_NON_TARGET_FILE}::{_TEST_TARGET_FUNC}'),
                'patch': _TEST_SOURCE,
                'is_non_target_match': True,
                'matched_signature': _TEST_SIGN_ID_2,
            },
        ],
    }]
    self.assertEqual(
        json_report['missing_patches'], expected_missing_patches
    )

  def test_main_fails_with_invalid_report_file_name(self):
    invalid_report_file_name_prefix = '/dev/null/foo/bar/report'
    with flagsaver.flagsaver(
        vulnerability_file_name=[self._test_vul_file.full_path],
        report_file_name_prefix=invalid_report_file_name_prefix,
    ):
      with self.assertRaises(IOError):
        detector_runner.main(['', 'test_scanner', _TEST_TARGET_ROOT])

  def test_main_fails_with_nonexisting_vul_file_path(self):
    with flagsaver.flagsaver(
        vulnerability_file_name=['/never/existing/file.json'],
        report_file_name_prefix=self._report_file_prefix,
    ):
      with self.assertRaisesRegex(ValueError,
                                  'Failed to find vulnerability file at .*'):
        detector_runner.main(['', 'test_scanner', _TEST_TARGET_ROOT])

  def test_main_fails_with_non_json_vul_file(self):
    invalid_vul_file = self.create_tempfile(content='invalid sign content.')
    with flagsaver.flagsaver(
        vulnerability_file_name=[invalid_vul_file.full_path],
        report_file_name_prefix=self._report_file_prefix,
    ):
      with self.assertRaises(json.decoder.JSONDecodeError):
        detector_runner.main(['', 'test_scanner', _TEST_TARGET_ROOT])

  def test_main_fails_with_non_dict_sign(self):
    invalid_vul_file = self.create_tempfile(content=json.dumps(['invalid']))
    with flagsaver.flagsaver(
        vulnerability_file_name=[invalid_vul_file.full_path],
        report_file_name_prefix=self._report_file_prefix,
    ):
      with self.assertRaises(ValueError):
        detector_runner.main(['', 'test_scanner', _TEST_TARGET_ROOT])

  def test_main_fails_with_no_scanner_specified(self):
    with self.assertRaisesRegex(app.UsageError, '.*Scanner is not specified.*'):
      detector_runner.main([''])

  def test_main_fails_with_missing_scanner_args_positional(self):
    with self.assertRaisesRegex(app.UsageError, TestScanner.__init__.__doc__):
      detector_runner.main(['', 'test_scanner'])

  @flagsaver.flagsaver(scanner='test_scanner')
  def test_main_fails_with_missing_scanner_args_absl_flag(self):
    with self.assertRaisesRegex(app.UsageError, TestScanner.__init__.__doc__):
      detector_runner.main([''])

  def test_main_logs_error_when_target_has_too_few_supported_files(self):
    high_threshold = _TEST_ANALYZED_FILES + _TEST_SKIPPED_FILES + 1
    with self.assertLogs(level=logging.ERROR) as logs:
      with flagsaver.flagsaver(
          vulnerability_file_name=[self._test_vul_file.full_path],
          report_file_name_prefix=self._report_file_prefix,
          minimum_number_of_files=high_threshold,
      ):
        detector_runner.main(['', 'test_scanner', _TEST_TARGET_ROOT])
    self.assertIn(
        'The scanned target directory contains only %d file(s) supported by'
        ' Vanir. Please confirm that this is intended.'
        % (_TEST_ANALYZED_FILES + _TEST_SKIPPED_FILES),
        ' '.join(logs.output),
    )

  def test_main_logs_error_when_target_has_too_few_analyzed_files(self):
    medium_threshold = _TEST_ANALYZED_FILES + _TEST_SKIPPED_FILES
    with self.assertLogs(level=logging.ERROR) as logs:
      with flagsaver.flagsaver(
          vulnerability_file_name=[self._test_vul_file.full_path],
          report_file_name_prefix=self._report_file_prefix,
          minimum_number_of_files=medium_threshold,
      ):
        detector_runner.main(['', 'test_scanner', _TEST_TARGET_ROOT])
    self.assertIn(
        'The scanned target directory contains only %d file(s) analyzed by'
        ' Vanir (%d file(s) were skipped).'
        % (
            _TEST_ANALYZED_FILES,
            _TEST_SKIPPED_FILES,
        ),
        ' '.join(logs.output),
    )

  def test_main_not_log_error_when_target_has_enough_files(self):
    low_threshold = 1
    # assertNoLogs not available in Python > 3.10. Use assertLogs instead.
    with self.assertLogs(level=logging.ERROR) as logs:
      with flagsaver.flagsaver(
          vulnerability_file_name=[self._test_vul_file.full_path],
          report_file_name_prefix=self._report_file_prefix,
          minimum_number_of_files=low_threshold,
      ):
        detector_runner.main(['', 'test_scanner', _TEST_TARGET_ROOT])
        logging.error('this is just a backup log not to fail due to no log.')
    self.assertNotIn(
        'The scanned target directory contains only', ' '.join(logs.output)
    )


if __name__ == '__main__':
  absltest.main()
