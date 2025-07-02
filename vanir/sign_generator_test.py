# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

import concurrent
import concurrent.futures
import re
from unittest import mock

from absl import logging
from vanir import parser
from vanir import sign_generator
from vanir import signature
from vanir.code_extractors import code_extractor_base

from absl.testing import absltest
from pybind11_abseil import status

_TEST_OSV_ID = 'ASB-A-1234'
_TEST_ECOSYSTEM = 'Android'
_TEST_PACKAGE_NAME = 'platform/foo'
_TEST_COMMIT_SOURCE = 'https://android.googlesource.com/kernel/common/+/050fad7'
_TEST_TARGET_FILE = 'foo/bar/baz.c'
_TEST_NON_TARGET_FILE = 'src/tests/foo/BarTest.java'
_TEST_PATCHED_FILES = {_TEST_TARGET_FILE: '/tmp/test/patched/baz.c'}
_TEST_PATCHED_FILES_WITH_TEST = {
    _TEST_TARGET_FILE: '/tmp/test/patched/baz.c',
    _TEST_NON_TARGET_FILE: '/tmp/test/patched/BarTest.java',
}
_TEST_UNPATCHED_FILES = {_TEST_TARGET_FILE: '/tmp/test/unpatched/baz.c'}
_TEST_UNPATCHED_FILES_WITH_TEST = {
    _TEST_TARGET_FILE: '/tmp/test/unpatched/baz.c',
    _TEST_NON_TARGET_FILE: '/tmp/test/unpatched/BarTest.java',
}


class SignGeneratorTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    # Prepare common mock objects.
    self.mock_func_chunk = mock.create_autospec(
        signature.FunctionChunk, instance=True)
    self.mock_line_chunk = mock.create_autospec(
        signature.LineChunk, instance=True)
    self.mock_line_chunk.line_hashes = ['12345']
    self.test_sign1 = signature.FunctionSignature(
        signature_id=f'{_TEST_OSV_ID}-sign1',
        source=_TEST_COMMIT_SOURCE,
        target_file=_TEST_TARGET_FILE,
        signature_version='v1',
        deprecated=False,
        exact_target_file_match_only=False,
        match_only_versions=None,
        truncated_path_level=None,
        function_hash='12345',
        length=10,
        target_function='func',
    )
    self.test_sign2 = signature.LineSignature(
        signature_id=f'{_TEST_OSV_ID}-sign2',
        source=_TEST_COMMIT_SOURCE,
        target_file=_TEST_TARGET_FILE,
        signature_version='v1',
        deprecated=False,
        exact_target_file_match_only=False,
        match_only_versions=None,
        truncated_path_level=None,
        line_hashes=['12345'],
        threshold=0.5,
    )
    self.mock_commit = mock.create_autospec(code_extractor_base.Commit,
                                            instance=True)
    self.mock_failed_commit_url = code_extractor_base.FailedCommitUrl(
        'https://bad.url.org', ValueError('bad url.'))
    self.mock_parser = mock.create_autospec(parser.Parser, instance=True)
    self.mock_parser_class = self.enter_context(
        mock.patch.object(
            parser,
            'Parser',
            return_value=self.mock_parser,
            autospec=True))
    self.mock_sign_factory = mock.create_autospec(
        signature.SignatureFactory, instance=True)
    self.mock_sign_factory.create_from_function_chunk.return_value = (
        self.test_sign1)
    self.mock_sign_factory.create_from_line_chunk.return_value = self.test_sign2
    self.mock_default_sign_factory = mock.create_autospec(
        signature.SignatureFactory, instance=True)
    self.enter_context(
        mock.patch.object(
            signature,
            'SignatureFactory',
            return_value=self.mock_default_sign_factory,
            autospec=True))

    # Configure mock objects.
    self.mock_commit.unpatched_files = _TEST_UNPATCHED_FILES
    self.mock_commit.patched_files = _TEST_PATCHED_FILES
    self.mock_parser.get_function_chunks.return_value = [self.mock_func_chunk]
    self.mock_parser.get_line_chunk.return_value = self.mock_line_chunk
    self.mock_default_sign_factory.create_from_function_chunk.return_value = (
        self.test_sign1)
    self.mock_default_sign_factory.create_from_line_chunk.return_value = (
        self.test_sign2)

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

  def test_sign_generator_init_fails_with_invalid_threshold(self):
    invalid_threshold = 1.1
    with self.assertRaisesRegex(
        ValueError, 'Line signature threshold .* is not valid. '
        'A threshold must be between 0 and 1.'):
      sign_generator.SignGenerator(invalid_threshold)

  def test_sign_generator_init_fails_with_multiple_custom_thresholds_for_same_sig(
      self,
  ):
    """There should be no more than one thresholds for a line signature."""
    custom_threshold_1 = sign_generator.CustomLineSignatureThreshold(
        _TEST_COMMIT_SOURCE, 'baz.c', 0.3
    )
    custom_threshold_2 = sign_generator.CustomLineSignatureThreshold(
        _TEST_COMMIT_SOURCE, 'baz.c', 0.4
    )
    with self.assertRaisesRegex(
        ValueError, 'Found more than one custom threshold.*'
    ):
      sign_generator.SignGenerator(
          custom_line_signature_thresholds=[
              custom_threshold_1,
              custom_threshold_2,
          ]
      )

  def test_custom_line_singature_threshold_fails_with_threshold(self):

    with self.assertRaisesRegex(
        ValueError, 'Custom line signature threshold entry .* is not valid. '
        'A threshold must be between 0 and 1.'):
      sign_generator.CustomLineSignatureThreshold(
          _TEST_COMMIT_SOURCE, 'baz.c', 1.1
      )

  def test_sign_generation(self):
    test_threshold = 0.5
    generator = sign_generator.SignGenerator(
        line_signature_threshold=test_threshold)
    signatures = generator.generate_signatures_for_commit(
        _TEST_ECOSYSTEM, _TEST_PACKAGE_NAME, self.mock_commit,
        signature_factory=self.mock_default_sign_factory,
    )
    self.mock_default_sign_factory.create_from_function_chunk.assert_called_once_with(
        self.mock_func_chunk, mock.ANY, None
    )
    self.mock_default_sign_factory.create_from_line_chunk.assert_called_once_with(
        self.mock_line_chunk, mock.ANY, test_threshold, None
    )
    self.assertEqual(signatures, [self.test_sign1, self.test_sign2])

  def test_sign_generation_with_explicit_sign_factory(self):
    test_threshold = 0.5
    generator = sign_generator.SignGenerator(
        line_signature_threshold=test_threshold
    )
    signatures = generator.generate_signatures_for_commit(
        _TEST_ECOSYSTEM, _TEST_PACKAGE_NAME, self.mock_commit,
        signature_factory=self.mock_sign_factory,
    )
    self.mock_default_sign_factory.create_from_function_chunk.assert_not_called(
    )
    self.mock_default_sign_factory.create_from_line_chunk.assert_not_called()
    self.mock_sign_factory.create_from_function_chunk.assert_called_once_with(
        self.mock_func_chunk, mock.ANY, None
    )
    self.mock_sign_factory.create_from_line_chunk.assert_called_once_with(
        self.mock_line_chunk, mock.ANY, test_threshold, None
    )
    self.assertEqual(signatures, [self.test_sign1, self.test_sign2])

  def test_sign_generation_with_custom_line_signature_thresholds(self):
    test_threshold = 0.1
    custom_line_sig_threshold = sign_generator.CustomLineSignatureThreshold(
        _TEST_COMMIT_SOURCE, _TEST_TARGET_FILE, test_threshold
    )
    self.mock_commit.url = _TEST_COMMIT_SOURCE
    generator = sign_generator.SignGenerator(
        line_signature_threshold=0.9,  # Expected to be ignored.
        custom_line_signature_thresholds=[custom_line_sig_threshold],
    )
    generator.generate_signatures_for_commit(
        _TEST_ECOSYSTEM, _TEST_PACKAGE_NAME, self.mock_commit,
        self.mock_default_sign_factory,
    )
    self.mock_default_sign_factory.create_from_line_chunk.assert_called_once_with(
        self.mock_line_chunk, mock.ANY, test_threshold, None
    )

  def test_sign_generation_ignore_test_file(self):
    self.mock_commit.unpatched_filess = (
        _TEST_UNPATCHED_FILES_WITH_TEST
    )
    self.mock_commit.patched_files = (
        _TEST_PATCHED_FILES_WITH_TEST
    )
    test_filter = sign_generator.EcosystemAndFileNameFilter(
        _TEST_ECOSYSTEM, r'(^|.*/)tests?/.*[^/]Test.java'
    )
    generator = sign_generator.SignGenerator(filters=(test_filter,))
    signatures = generator.generate_signatures_for_commit(
        _TEST_ECOSYSTEM, _TEST_PACKAGE_NAME, self.mock_commit,
        self.mock_default_sign_factory,
    )
    self.assertEqual(signatures, [self.test_sign1, self.test_sign2])

  def test_sign_generation_skips_file_when_parser_fails(self):
    self.mock_parser_class.side_effect = status.BuildStatusNotOk(
        status.StatusCode.CANCELLED, 'mock error')
    generator = sign_generator.SignGenerator()
    with self.assertLogs(level=logging.ERROR) as logs:
      sigs = generator.generate_signatures_for_commit(
          _TEST_ECOSYSTEM, _TEST_PACKAGE_NAME, self.mock_commit,
          self.mock_default_sign_factory,
      )
    self.assertRegex(''.join(logs.output), f'.*{_TEST_TARGET_FILE}.*')
    self.assertEmpty(sigs)

  def test_sign_generation_skips_file_when_worker_died_unexpectedly(self):
    self.mock_parser_class.side_effect = (
        concurrent.futures.process.BrokenProcessPool()
    )
    generator = sign_generator.SignGenerator()
    with self.assertLogs(level=logging.ERROR) as logs:
      sigs = generator.generate_signatures_for_commit(
          _TEST_ECOSYSTEM, _TEST_PACKAGE_NAME, self.mock_commit,
          self.mock_default_sign_factory,
      )
    self.assertRegex(''.join(logs.output), f'.*{_TEST_TARGET_FILE}.*')
    self.assertEmpty(sigs)

  def test_sign_generation_with_truncated_path_levels(self):
    ref_file_lists = {
        _TEST_ECOSYSTEM: {
            _TEST_PACKAGE_NAME: ['foo/bar/foo.c', 'baz.c', 'foo/bar/baz.c']
        }
    }
    conditions = {
        _TEST_ECOSYSTEM: {_TEST_PACKAGE_NAME: re.compile(_TEST_TARGET_FILE)}
    }
    tp_level_finder = sign_generator.TruncatedPathLevelFinder(
        ref_file_lists, conditions
    )
    generator = sign_generator.SignGenerator(
        truncated_path_level_finder=tp_level_finder
    )
    expected_tp_level = 1  # 'bar/baz.c'
    signatures = generator.generate_signatures_for_commit(
        _TEST_ECOSYSTEM, _TEST_PACKAGE_NAME, self.mock_commit,
        self.mock_default_sign_factory,
    )
    self.mock_default_sign_factory.create_from_function_chunk.assert_called_once_with(
        self.mock_func_chunk, mock.ANY, expected_tp_level,
    )
    self.mock_default_sign_factory.create_from_line_chunk.assert_called_once_with(
        self.mock_line_chunk, mock.ANY, mock.ANY, expected_tp_level,
    )
    self.assertEqual(signatures, [self.test_sign1, self.test_sign2])

  def test_ecosystem_and_file_filter(self):
    filt = sign_generator.EcosystemAndFileNameFilter(
        'Android', r'(^|.*/)tests?/.*[^/]Test.java')
    ignore_file = 'src/tests/foo/BarTest.java'
    keep_file = 'src/nontests/foo/BarTest.java'
    self.assertTrue(filt.should_filter_out('Android', '', [], ignore_file, ''))
    self.assertFalse(filt.should_filter_out('Wear', '', [], ignore_file, ''))
    self.assertFalse(filt.should_filter_out('Android', '', [], keep_file, ''))

  def test_truncated_path_level_finder(self):
    ref_file_list = [
        '1/2/3/4/5/6/foo.c',
        '1/2/3/4/5/foo.c',
        '1/2/3/4/foo.c',
        '2/3/4/foo.c',
        '1/2/3/4/5/6/bar.c',
        '1/2/3/baz.c',
    ]
    ref_file_lists = {'Android': {':linux_kernel:': ref_file_list}}
    conditions = {
        'Android': {':linux_kernel:': re.compile('3/4/.*')},
        'UpstreamKernel': {':linux_kernel:': re.compile('.*')},
    }
    tp_level_finder = sign_generator.TruncatedPathLevelFinder(
        ref_file_lists, conditions
    )
    self.assertEqual(
        tp_level_finder.find('3/4/5/foo.c', 'Android', ':linux_kernel:'), 1
    )  # '5/foo.c'
    with self.assertLogs(level=logging.INFO) as logs:
      self.assertEqual(
          tp_level_finder.find('3/4/foo.c', 'Android', ':linux_kernel:'), 2
      )  # '3/4/foo.c'
    self.assertIn('No unique TP found for', ''.join(logs.output))
    self.assertIsNone(
        tp_level_finder.find('a/b/c/3/4/5/foo.c', 'Android', ':linux_kernel:')
    )
    self.assertIsNone(
        tp_level_finder.find(
            '1/2/3/baz.c', 'NonExistingEcosystem', ':linux_kernel:'
        )
    )
    self.assertIsNone(
        tp_level_finder.find('mem.c', 'UpstreamKernel', ':linux_kernel:')
    )


if __name__ == '__main__':
  absltest.main()
