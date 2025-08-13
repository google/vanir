# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

import builtins
import datetime
import json
import os
from unittest import mock

from absl import app
from absl.testing import flagsaver
from vanir import file_list_manager
from vanir import osv_client
from vanir import sign_generator_runner
from vanir import signature
from vanir import vulnerability
from vanir import vulnerability_manager

from absl.testing import absltest

_TEST_OSV_ID = 'ASB-A-1234'
_TEST_ECOSYSTEM = 'test_ecosystem'
_TEST_PKG = 'pkg'

_TEST_SIGN_HASH_1 = 'test-sign-1'
_TEST_SIGN_HASH_2 = 'test-sign-2'

_TEST_SIGN_ID_1 = 'ASB-A-1234-test-sign-1'
_TEST_SIGN_ID_2 = 'ASB-A-1234-test-sign-2'

_TEST_SIGN1 = signature.LineSignature(
    signature_id=f'{_TEST_OSV_ID}-{_TEST_SIGN_HASH_1}',
    signature_version='v0',
    source='patch1',
    target_file='f1',
    deprecated=False,
    exact_target_file_match_only=False,
    match_only_versions=None,
    truncated_path_level=None,
    line_hashes=[],
    threshold=0,
)
_TEST_SIGN2 = signature.FunctionSignature(
    signature_id=f'{_TEST_OSV_ID}-{_TEST_SIGN_HASH_2}',
    signature_version='v0',
    source='patch2',
    target_file='f2',
    deprecated=False,
    exact_target_file_match_only=False,
    match_only_versions=None,
    truncated_path_level=None,
    function_hash='func_hash',
    length=10,
    target_function='func',
)

_TEST_SIGNATURES = {
    _TEST_OSV_ID: {
        (_TEST_ECOSYSTEM, _TEST_PKG): [_TEST_SIGN1, _TEST_SIGN2],
    },
}

_TEST_DICT_SIGN_1 = {
    'id': _TEST_SIGN_ID_1,
    'signature_type': 'Line',
    'signature_version': 'v0',
    'source': 'patch1',
    'target': {'file': 'f1'},
    'deprecated': False,
    'digest': {'line_hashes': [], 'threshold': 0},
}
_TEST_DICT_SIGN_2 = {
    'id': _TEST_SIGN_ID_2,
    'signature_type': 'Function',
    'signature_version': 'v0',
    'source': 'patch2',
    'target': {'file': 'f2', 'function': 'func'},
    'deprecated': False,
    'digest': {'function_hash': 'func_hash', 'length': 10},
}

_DESIGNATED_SIGNATURE_FILE_NAME = '/tmp/test-signature.json'


class SignGeneratorRunnerTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.test_vuln = {
        'id': _TEST_OSV_ID,
        'modified': '1985-11-11T21:26:24Z',
        'affected': [
            {
                'package': {
                    'ecosystem': _TEST_ECOSYSTEM,
                    'name': _TEST_PKG,
                }
            }
        ],
    }
    self.mock_get_vulns_for_packages = self.enter_context(
        mock.patch.object(
            osv_client.OsvClient,
            'get_vulns_for_packages',
            return_value=[self.test_vuln],
            autospec=True,
        )
    )
    self.mock_generate_from_osv = self.enter_context(
        mock.patch.object(
            vulnerability_manager,
            'generate_from_osv',
            side_effect=vulnerability_manager.generate_from_osv))
    self.mock_generate_signatures = self.enter_context(
        mock.patch.object(
            vulnerability_manager.VulnerabilityManager,
            'generate_signatures',
        )
    )
    self.mock_file_list_manager = self.enter_context(
        mock.patch.object(
            file_list_manager,
            'get_file_lists',
            return_value={
                'Android': {':linux_kernel:': ['file1.c', 'file2.java']}
            },
        )
    )
    self.mock_file_open = mock.mock_open()

  def test_validate_vuln_source_flags(self):
    self.assertFalse(sign_generator_runner._validate_vuln_source_flags(
        {'vulnerability_file_name': None, 'osv_ecosystem': None,
         'osv_package': None, 'use_osv_android_kernel_vulns': False}
    ))
    self.assertTrue(sign_generator_runner._validate_vuln_source_flags(
        {'vulnerability_file_name': None, 'osv_ecosystem': 'eco',
         'osv_package': None, 'use_osv_android_kernel_vulns': False}
    ))
    self.assertFalse(sign_generator_runner._validate_vuln_source_flags(
        {'vulnerability_file_name': None, 'osv_ecosystem': None,
         'osv_package': ['pkg'], 'use_osv_android_kernel_vulns': False}
    ))
    self.assertFalse(sign_generator_runner._validate_vuln_source_flags(
        {'vulnerability_file_name': '/vul.json', 'osv_ecosystem': None,
         'osv_package': None, 'use_osv_android_kernel_vulns': True}
    ))
    self.assertFalse(sign_generator_runner._validate_vuln_source_flags(
        {'vulnerability_file_name': '/vul.json', 'osv_ecosystem': 'eco',
         'osv_package': ['pkg'], 'use_osv_android_kernel_vulns': False}
    ))
    self.assertFalse(sign_generator_runner._validate_vuln_source_flags(
        {'vulnerability_file_name': None, 'osv_ecosystem': 'eco',
         'osv_package': ['pkg'], 'use_osv_android_kernel_vulns': True}
    ))

    self.assertTrue(sign_generator_runner._validate_vuln_source_flags(
        {'vulnerability_file_name': '/vul.json', 'osv_ecosystem': None,
         'osv_package': None, 'use_osv_android_kernel_vulns': False}
    ))
    self.assertTrue(sign_generator_runner._validate_vuln_source_flags(
        {'vulnerability_file_name': None, 'osv_ecosystem': None,
         'osv_package': None, 'use_osv_android_kernel_vulns': True}
    ))
    self.assertTrue(sign_generator_runner._validate_vuln_source_flags(
        {'vulnerability_file_name': None, 'osv_ecosystem': 'eco',
         'osv_package': ['pkg'], 'use_osv_android_kernel_vulns': False}
    ))

  @flagsaver.flagsaver(use_osv_android_kernel_vulns=True)
  @mock.patch.object(os, 'makedirs', autospec=True)
  def test_main(self, _):
    test_datetime = datetime.datetime(2022, 10, 4, 10, 10)
    with mock.patch.object(
        datetime, 'datetime', wraps=datetime.datetime) as mock_datetime:
      mock_datetime.now.return_value = test_datetime
      with mock.patch.object(builtins, 'open', self.mock_file_open):
        sign_generator_runner.main([])
    self.mock_generate_from_osv.assert_called_with(
        ecosystem='Android',
        packages=vulnerability.MetaPackage.ANDROID_KERNEL,
        session=mock.ANY,
        store_signatures_in_legacy_location=False,
    )
    self.mock_get_vulns_for_packages.assert_called_once()
    self.mock_generate_signatures.assert_called_once_with(
        session=mock.ANY,
        generator=mock.ANY,
        deprecated_signatures=set(),
        deprecated_patch_urls=set(),
        deprecated_vulns=set(),
        exact_match_only_signatures=set(),
        exact_match_only_patch_urls=set(),
    )
    expected_output_file = '/tmp/vanir/signature-20221004101000.json'
    self.mock_file_open.assert_has_calls([mock.call(expected_output_file, 'w')])
    mock_file_write = self.mock_file_open().write
    mock_file_write.assert_called_once()

  @flagsaver.flagsaver(signature_file_name=_DESIGNATED_SIGNATURE_FILE_NAME)
  @flagsaver.flagsaver(use_osv_android_kernel_vulns=True)
  @flagsaver.flagsaver(store_signatures_in_legacy_location=True)
  @mock.patch.object(os, 'makedirs', autospec=True)
  def test_store_signatures_in_legacy_location(self, _):
    test_datetime = datetime.datetime(2022, 10, 4, 10, 10)
    with mock.patch.object(
        datetime, 'datetime', wraps=datetime.datetime) as mock_datetime:
      mock_datetime.now.return_value = test_datetime
      with mock.patch.object(builtins, 'open', self.mock_file_open):
        sign_generator_runner.main([])
    self.mock_generate_from_osv.assert_called_with(
        ecosystem='Android',
        packages=vulnerability.MetaPackage.ANDROID_KERNEL,
        session=mock.ANY,
        store_signatures_in_legacy_location=True,
    )

  @flagsaver.flagsaver(signature_file_name=_DESIGNATED_SIGNATURE_FILE_NAME)
  @flagsaver.flagsaver(use_osv_android_kernel_vulns=True)
  @mock.patch.object(os, 'makedirs', autospec=True)
  def test_main_with_designated_sign_file_name(self, _):
    with mock.patch.object(builtins, 'open', self.mock_file_open):
      sign_generator_runner.main([])
    self.mock_generate_from_osv.assert_called_with(
        ecosystem='Android',
        packages=vulnerability.MetaPackage.ANDROID_KERNEL,
        session=mock.ANY,
        store_signatures_in_legacy_location=False,
    )
    self.mock_get_vulns_for_packages.assert_called_once()
    self.mock_generate_signatures.assert_called_once()
    expected_output_file = _DESIGNATED_SIGNATURE_FILE_NAME
    self.mock_file_open.assert_has_calls([mock.call(expected_output_file, 'w')])
    mock_file_write = self.mock_file_open().write
    mock_file_write.assert_called_once()

  @mock.patch.object(os, 'makedirs', autospec=True)
  @mock.patch.object(os.path, 'isfile', autospec=True)
  def test_main_with_designated_vul_file(self, mock_isfile, mock_makedirs):
    test_vul_file = 'foo_bar_vuln.json'
    # |mock_file_open| is used for both input vuln file and output sign file.
    mock_file_open = mock.mock_open(read_data=json.dumps([self.test_vuln]))
    with flagsaver.flagsaver(vulnerability_file_name=test_vul_file):
      with mock.patch.object(builtins, 'open', mock_file_open):
        sign_generator_runner.main([])
    self.mock_generate_signatures.assert_called_once()
    mock_makedirs.assert_called()
    mock_isfile.assert_called()
    args, _ = mock_isfile.call_args
    self.assertEndsWith(args[0], test_vul_file)

    mock_makedirs.assert_called()
    mock_isfile.assert_called()
    args, _ = mock_isfile.call_args
    self.assertEndsWith(args[0], test_vul_file)

  @flagsaver.flagsaver(signature_file_name=_DESIGNATED_SIGNATURE_FILE_NAME)
  @flagsaver.flagsaver(use_osv_android_kernel_vulns=True)
  @flagsaver.flagsaver(deprecated_signatures=['bad_signature.json'])
  def test_main_with_deprecated_signature(self):
    bad_sig_file_mock_open = mock.mock_open(
        read_data=json.dumps(
            [
                {'reason': 'test1', 'signature_ids': [_TEST_SIGN_ID_1]},
                {'reason': 'test2', 'vuln_id': _TEST_OSV_ID},
                {'reason': 'test3', 'patch_urls': ['patch1', 'patch2']}
            ]
        )
    )
    with mock.patch.object(builtins, 'open', bad_sig_file_mock_open):
      sign_generator_runner.main([])
    self.mock_generate_signatures.assert_called_once_with(
        session=mock.ANY,
        generator=mock.ANY,
        deprecated_signatures={_TEST_SIGN_ID_1},
        deprecated_vulns={_TEST_OSV_ID},
        deprecated_patch_urls={'patch1', 'patch2'},
        exact_match_only_patch_urls=set(),
        exact_match_only_signatures=set(),
    )

  @flagsaver.flagsaver(signature_file_name=_DESIGNATED_SIGNATURE_FILE_NAME)
  @flagsaver.flagsaver(use_osv_android_kernel_vulns=True)
  @flagsaver.flagsaver(
      exact_target_file_match_only_signatures=['strict_signatures.json'])
  def test_main_with_exact_target_match_only_signature(self):
    strict_sig_file_mock_open = mock.mock_open(
        read_data=json.dumps(
            [
                {'reason': 'test', 'signature_ids': [_TEST_SIGN_ID_2]},
                {'reason': 'test2', 'patch_urls': ['patch1', 'patch2']},
            ],
        )
    )
    with mock.patch.object(builtins, 'open', strict_sig_file_mock_open):
      sign_generator_runner.main([])
    self.mock_generate_signatures.assert_called_once_with(
        session=mock.ANY,
        generator=mock.ANY,
        deprecated_signatures=set(),
        deprecated_vulns=set(),
        deprecated_patch_urls=set(),
        exact_match_only_signatures={_TEST_SIGN_ID_2},
        exact_match_only_patch_urls={'patch1', 'patch2'},
    )

  def test_main_with_designated_vul_file_fails_with_invalid_vul_file(self):
    with flagsaver.flagsaver(vulnerability_file_name='nonexisting_file.json'):
      with self.assertRaisesRegex(
          ValueError, 'Failed to find vulnerability file at.*'
      ):
        sign_generator_runner.main([])

    test_vul_file = self.create_tempfile(
        content='bad_json_file_content', mode='wt')
    with flagsaver.flagsaver(vulnerability_file_name=test_vul_file):
      with self.assertRaises(json.JSONDecodeError):
        sign_generator_runner.main([])

  def test_main_fails_with_additional_args(self):
    with self.assertRaises(app.UsageError):
      sign_generator_runner.main(['some', 'args', 'are', 'passed'])


if __name__ == '__main__':
  absltest.main()
