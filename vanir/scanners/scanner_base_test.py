# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for scanner_base and scanner_utils."""

import concurrent
import dataclasses
import os
from unittest import mock

from vanir import parser
from vanir import reporter
from vanir import signature
from vanir.language_parsers import common as language_parsers_common
from vanir.scanners import scanner_base
from vanir.scanners import target_selection_strategy

from absl.testing import absltest


class ScannerBaseTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self._test_target_root = self.create_tempdir().full_path
    test_files = ['target.c', 'target.h', 'non_target.txt', 'non_target.c']
    self._test_target_files = [
        self.create_tempfile(os.path.join(self._test_target_root, test_file))
        for test_file in test_files
    ]
    self._test_func_sign = signature.FunctionSignature(
        signature_id='ASB-A-1234-sign1',
        signature_version='v1',
        source='https://android.googlesource.com/sign1_source',
        target_file='target.c',
        target_function='foo',
        length=3,
        truncated_path_level=None,
        exact_target_file_match_only=False,
        deprecated=False,
        match_only_versions=None,
        function_hash='func_hash',
    )
    self._test_line_sign = signature.LineSignature(
        signature_id='ASB-A-1234-sign2',
        signature_version='v1',
        source='https://android.googlesource.com/sign2_source',
        target_file='target.c',
        truncated_path_level=None,
        exact_target_file_match_only=False,
        deprecated=False,
        match_only_versions=None,
        line_hashes=['line_hash'],
        threshold=0.5,
    )
    self._test_extra_sign = signature.LineSignature(
        signature_id='sign3',
        target_file='target.h',
        truncated_path_level=None,
        exact_target_file_match_only=False,
        signature_version='v1',
        source='sign3_source',
        deprecated=False,
        match_only_versions=None,
        line_hashes=['line_hash'],
        threshold=0.5,
    )
    self._test_signatures = [
        self._test_func_sign,
        self._test_line_sign,
        self._test_extra_sign,
    ]
    self._mock_sign_bundle = mock.create_autospec(
        signature.SignatureBundle, instance=True)
    type(self._mock_sign_bundle).signatures = mock.PropertyMock(
        return_value=self._test_signatures
    )
    type(self._mock_sign_bundle).target_file_paths = mock.PropertyMock(
        return_value={'target.c', 'target.h'},
    )

    # Configure the mock match to always return only sign1 for function chunks
    # and sign2 for line chunks.
    def mock_match_side_effect(chunk, *_):
      if isinstance(chunk, signature.FunctionChunk):
        return [self._test_func_sign]
      else:
        return [self._test_line_sign]

    self._mock_sign_bundle.match.side_effect = mock_match_side_effect
    self._mock_sign_bundle_class = self.enter_context(
        mock.patch.object(
            signature,
            'SignatureBundle',
            return_value=self._mock_sign_bundle,
            autospec=True))

    # By default, all files return a mock LineChunk
    self._mock_parsers = {}
    for test_file in test_files:
      mock_parser = mock.create_autospec(parser.Parser, instance=True)
      mock_parser._target_file = test_file
      mock_parser.get_function_chunks.return_value = []
      mock_parser.get_line_chunk.return_value = mock.create_autospec(
          signature.LineChunk,
          instance=True,
          target_file=test_file,
          base=mock.create_autospec(
              language_parsers_common.LineChunkBase, instance=True
          ),
      )
      # Line chunk shouldn't have a name.
      del mock_parser.get_line_chunk.return_value.base.name
      self._mock_parsers[test_file] = mock_parser

    # target.c returns an additional FunctionChunk 'foo'
    self._mock_function_chunk_foo = mock.create_autospec(
        signature.FunctionChunk,
        instance=True,
        target_file='target.c',
        base=mock.create_autospec(
            language_parsers_common.FunctionChunkBase, instance=True))
    self._mock_function_chunk_foo.base.name = 'foo'
    self._mock_parsers['target.c'].get_function_chunks.return_value = [
        self._mock_function_chunk_foo
    ]

    # non_target.c returns an additional FunctionChunk 'bar'
    self._mock_function_chunk_bar = mock.create_autospec(
        signature.FunctionChunk,
        instance=True,
        target_file='non_target.c',
        base=mock.create_autospec(
            language_parsers_common.FunctionChunkBase, instance=True))
    self._mock_function_chunk_bar.base.name = 'bar'
    self._mock_parsers['non_target.c'].get_function_chunks.return_value = [
        self._mock_function_chunk_bar
    ]

    def get_mock_parser(file_path, target_file, *_):
      del file_path  # Not needed by the mock but can be called as a keyword-arg
      return self._mock_parsers.get(target_file)
    self._mock_parser_class = self.enter_context(
        mock.patch.object(
            parser,
            'Parser',
            side_effect=get_mock_parser,
            autospec=True))

    # Mock concurrent executor: forkserver is inherently not working with mock
    def mock_apply(func, *args):
      res = mock.MagicMock()
      res.result.side_effect = lambda: func(*args)
      return res
    self._mock_executor = self.enter_context(
        mock.patch.object(
            concurrent.futures, 'ProcessPoolExecutor', autospec=True
        )
    ).return_value.__enter__
    self._mock_executor.return_value.submit.side_effect = mock_apply
    self.enter_context(mock.patch.object(concurrent.futures, 'wait'))

  def test_scanner_fails_when_target_root_is_invalid(self):
    invalid_target_root = '/foo/bar/baz'
    with self.assertRaisesRegex(ValueError, 'Invalid directory: .*'):
      scanner_base.scan(invalid_target_root, [])

  def test_scan_quick_mode(self):
    findings, stats = scanner_base.scan(
        self._test_target_root, self._mock_sign_bundle)

    # Quick scan mode should be used by default, and checks only targeted files.
    expected_scanned_files = ['target.c', 'target.h']
    expected_calls = [
        mock.call(os.path.join(self._test_target_root, test_file), test_file)
        for test_file in expected_scanned_files
    ]
    self._mock_parser_class.assert_has_calls(expected_calls, any_order=True)
    self.assertIn(self._test_func_sign, findings)
    self.assertEqual(
        [self._mock_function_chunk_foo], findings.get(self._test_func_sign)
    )
    self.assertIn(self._test_line_sign, findings)
    self.assertLen(
        findings.get(self._test_line_sign), len(expected_scanned_files)
    )
    self.assertEqual(stats.analyzed_files, 2)
    self.assertEqual(stats.skipped_files, 1)

  def test_scan_full_mode(self):
    findings, stats = scanner_base.scan(
        self._test_target_root,
        self._mock_sign_bundle,
        strategy=target_selection_strategy.Strategy.ALL_FILES,
    )

    # Full scan mode should check all files with the supported extensions.
    expected_scanned_files = ['target.c', 'target.h', 'non_target.c']
    expected_calls = [
        mock.call(os.path.join(self._test_target_root, test_file), test_file)
        for test_file in expected_scanned_files
    ]
    self._mock_parser_class.assert_has_calls(expected_calls, any_order=True)
    self.assertIn(self._test_func_sign, findings)
    self.assertSameElements(
        [self._mock_function_chunk_foo, self._mock_function_chunk_bar],
        findings.get(self._test_func_sign),
    )
    self.assertIn(self._test_line_sign, findings)
    self.assertLen(
        findings.get(self._test_line_sign), len(expected_scanned_files)
    )
    self.assertEqual(stats.analyzed_files, 3)
    self.assertEqual(stats.skipped_files, 0)

  def test_scan_with_strict_signatures(self):
    # Make function signature (for 'target.c') strict.
    self._test_func_sign = dataclasses.replace(
        self._test_func_sign, exact_target_file_match_only=True
    )

    findings, stats = scanner_base.scan(
        self._test_target_root,
        self._mock_sign_bundle,
        strategy=target_selection_strategy.Strategy.ALL_FILES,
    )

    # Full scan mode should check all files with the supported extensions.
    expected_scanned_files = ['target.c', 'target.h', 'non_target.c']
    expected_calls = [
        mock.call(os.path.join(self._test_target_root, test_file), test_file)
        for test_file in expected_scanned_files
    ]
    self._mock_parser_class.assert_has_calls(expected_calls, any_order=True)
    # function signature is strict and should only has foo matched (target.c)
    self.assertIn(self._test_func_sign, findings)
    self.assertEqual(
        [self._mock_function_chunk_foo], findings[self._test_func_sign]
    )
    self.assertIn(self._test_line_sign, findings)
    # line signature is not strict.
    self.assertLen(
        findings.get(self._test_line_sign), len(expected_scanned_files)
    )
    self.assertEqual(stats.analyzed_files, 3)
    self.assertEqual(stats.skipped_files, 0)

  def test_scan_with_version_specific_signatures_filter(self):
    # Make function signature (for 'target.c') version-specific.
    self._test_func_sign = dataclasses.replace(
        self._test_func_sign, match_only_versions=frozenset({'11', '12-next'})
    )
    findings, stats = scanner_base.scan(
        self._test_target_root,
        self._mock_sign_bundle,
        strategy=target_selection_strategy.Strategy.ALL_FILES,
    )
    self.assertIn(self._test_func_sign, findings)
    self.assertEqual(stats.analyzed_files, 3)
    self.assertEqual(stats.skipped_files, 0)

    # No version is specified, so all target.c findings should be filtered out.
    filter1 = scanner_base.PackageVersionSpecificSignatureFilter([])
    filtered_findings = filter1.filter(findings)
    self.assertNotIn(self._test_func_sign, filtered_findings)

    # Version 12 is specified but not in signature's list, so also filtered out.
    filter2 = scanner_base.PackageVersionSpecificSignatureFilter(['12'])
    filtered_findings = filter2.filter(findings)
    self.assertNotIn(self._test_func_sign, filtered_findings)

    # Version 11 is specified and in signature's list, so not filtered out.
    filter3 = scanner_base.PackageVersionSpecificSignatureFilter(['11'])
    filtered_findings = filter3.filter(findings)
    self.assertIn(self._test_func_sign, filtered_findings)

    # Version 13 is specified, not in signature's list, but is after `main`, so
    # also not filtered out.
    filter4 = scanner_base.PackageVersionSpecificSignatureFilter(['13'])
    filtered_findings = filter4.filter(findings)
    self.assertIn(self._test_func_sign, filtered_findings)

  def test_detector_filters_out_short_functions(self):
    short_function_filter = scanner_base.ShortFunctionFilter(
        function_length_threshold=10, filter_exatct_match=True)
    findings, stats = scanner_base.scan(
        self._test_target_root,
        self._mock_sign_bundle,
        strategy=target_selection_strategy.Strategy.ALL_FILES,
    )
    findings = short_function_filter.filter(findings)

    self.assertNotIn(self._test_func_sign, findings)
    self.assertEqual(stats.analyzed_files, 3)
    self.assertEqual(stats.skipped_files, 0)

  def test_detector_filters_in_long_functions(self):
    self._test_func_sign = dataclasses.replace(self._test_func_sign, length=100)
    short_function_filter = scanner_base.ShortFunctionFilter(
        function_length_threshold=10, filter_exatct_match=True)
    findings, stats = scanner_base.scan(
        self._test_target_root,
        self._mock_sign_bundle,
        strategy=target_selection_strategy.Strategy.ALL_FILES,
    )
    findings = short_function_filter.filter(findings)

    self.assertIn(self._test_func_sign, findings)
    self.assertEqual(stats.analyzed_files, 3)
    self.assertEqual(stats.skipped_files, 0)

  def test_detector_filters_in_exact_match_short_functions(self):
    short_function_filter = scanner_base.ShortFunctionFilter(
        function_length_threshold=10, filter_exatct_match=False)
    findings, stats = scanner_base.scan(
        self._test_target_root,
        self._mock_sign_bundle,
        strategy=target_selection_strategy.Strategy.ALL_FILES,
    )
    findings = short_function_filter.filter(findings)

    self.assertIn(self._test_func_sign, findings)
    self.assertEqual(
        [self._mock_function_chunk_foo], findings.get(self._test_func_sign)
    )
    self.assertEqual(stats.analyzed_files, 3)
    self.assertEqual(stats.skipped_files, 0)

  def test_report_generation(self):
    mock_line_chunk = mock.create_autospec(
        signature.LineChunk,
        instance=True,
        target_file='some_test_file',
        base=mock.create_autospec(
            language_parsers_common.LineChunkBase, instance=True
        ),
    )
    test_sign1 = self._test_func_sign
    test_sign2 = self._test_line_sign
    test_findings = {
        test_sign1: [self._mock_function_chunk_foo],
        test_sign2: [mock_line_chunk],
    }
    reports = reporter.generate_reports(test_findings)
    self.assertLen(reports, 2)
    self.assertEqual(reports[0].signature_id, test_sign1.signature_id)
    self.assertEqual(reports[0].signature_target_file, test_sign1.target_file)
    self.assertEqual(reports[0].signature_target_function,
                     test_sign1.target_function)
    self.assertEqual(reports[0].signature_source, test_sign1.source)
    self.assertEqual(reports[0].unpatched_file,
                     self._mock_function_chunk_foo.target_file)
    self.assertEqual(reports[0].unpatched_function_name,
                     self._mock_function_chunk_foo.base.name)
    self.assertEqual(reports[1].signature_id, test_sign2.signature_id)
    self.assertEqual(reports[1].signature_target_file, test_sign2.target_file)
    self.assertEqual(reports[1].signature_target_function, '')
    self.assertEqual(reports[1].signature_source, test_sign2.source)
    self.assertEqual(reports[1].unpatched_file, mock_line_chunk.target_file)
    self.assertEqual(reports[1].unpatched_function_name, '')
    self.assertEqual(
        reports[0].get_simple_report(),
        '%s::%s()'
        % (
            self._mock_function_chunk_foo.target_file,
            self._mock_function_chunk_foo.base.name,
        ),
    )
    self.assertEqual(
        reports[0].get_simple_report(include_patch_source=True),
        '%s::%s()  (patch:%s, signature:%s)'
        % (
            self._mock_function_chunk_foo.target_file,
            self._mock_function_chunk_foo.base.name,
            test_sign1.source,
            test_sign1.signature_id,
        ),
    )
    self.assertEqual(
        reports[1].get_simple_report(), mock_line_chunk.target_file
    )
    self.assertEqual(
        reports[1].get_simple_report(include_patch_source=True),
        '%s  (patch:%s, signature:%s)'
        % (
            mock_line_chunk.target_file,
            test_sign2.source,
            test_sign2.signature_id,
        ),
    )

  def test_scanner_with_unexpected_crash(self):
    # cause a crash when scanning target.h
    def mock_apply(func, *args):
      res = mock.MagicMock()
      if args[0].endswith('target.h'):
        res.result.side_effect = concurrent.futures.process.BrokenProcessPool()
      else:
        res.result.return_value = func(*args)
      return res
    self._mock_executor.return_value.submit.side_effect = mock_apply
    _, stats = scanner_base.scan(self._test_target_root, self._mock_sign_bundle)
    self.assertLen(stats.errors, 1)
    self.assertIn('target.h', str(stats.errors[0]))
    self.assertEqual(stats.analyzed_files, 1)
    self.assertEqual(stats.skipped_files, 2)  # non_target.c and failed target.h


if __name__ == '__main__':
  absltest.main()
