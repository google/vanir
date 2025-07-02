# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

import concurrent
import concurrent.futures
import dataclasses
import functools
import os
from unittest import mock

import mmh3
from vanir import parser
from vanir import refiner
from vanir import signature
from vanir.code_extractors import code_extractor_base

from absl.testing import absltest
from pybind11_abseil import status

_TEST_NORMALIZED_FUNCTION_CODE = (
    'DTYPE FUNCNAME ( const unsigned DTYPE PARAM ) { '
    'const DTYPE * VAR = ( DTYPE * ) globalvar -> data ; '
    'FUNCCALL ( PARAM , VAR ) ; '
    '0xe8 ( ) ; '
    'return 0 ; }')
_TEST_NORMALIZED_LINE_CODE = {
    1: 'struct teststruct globalvar = configvar ;',
    2: 'int test_func1 ( const unsigned int64 test_arg ) {',
    3: 'const int * testvar = ( int * ) globalvar -> data ;',
    4: 'test_func2 ( test_arg , testvar ) ;',
    5: '0xe8 ( ) ;',
    6: 'return 0 ;',
    7: '}',
}

_TEST_PATCHED_CODE = '\n'.join([
    '// Library for test functions',
    '#include "test_func_lib.h"',
    'struct teststruct globalVar = configVar;',
    'int test_func1(const unsigned int64 test_arg) { ',
    '    const int* testvar = (int *)globalVar -> data;',
    '    test_func2(test_arg , testvar);',
    '    // security patch: remove vulnerable function call',
    '    return 0;',
    '}',
])

# Signatures generated from FUNCTION_CODE will match this since it has an
# unexpected test_func3() in patched file that's similar to the unpatched func1.
# Alhough the function signature for test_func1() would match against
# test_func3(), the line signature generated from test_func1() is still valid.
_TEST_PATCHED_CODE_WITH_FALSE_FUNC_SIG_MATCH = '\n'.join([
    '// Library for test functions. This file does something awesome.',
    '#include "test_func_lib.h"',
    'struct teststruct globalVar = configVar;',
    'int test_func1(const unsigned int64 test_arg) { ',
    '    const int* testvar = (int *)globalVar -> data;',
    '    test_func2(test_arg , testvar);',
    '    // Security patch: removed vulnerable function call.',
    '    // We removed a macro function call which caused bad problems.',
    '    // Never use 0xe8() here anymore.', '    return 0;', '}', '',
    '                                                                ',
    'int test_func3(const unsigned float ratio) { ',
    '    const int* testvar = (int *)globalVar -> data;',
    '    test_func4(ratio , testvar);',
    '    0xe8();  // a black magic macro function. Safe to use here.',
    '    return 0;', '}'
])


# A patch that only adds comments so there is no meaningful difference between
# the patched file and unpatched file, which will cause false positives.
_TEST_PATCHED_CODE_WITH_FALSE_LINE_AND_FUNC_SIG_MATCHES = '\n'.join([
    '// Library for test functions', '#include "test_func_lib.h"',
    'struct teststruct globalVar = configVar;',
    'int test_func1(const unsigned int64 test_arg) { ',
    '    const int* testvar = (int *)globalVar -> data;',
    '    test_func2(test_arg , testvar);', '    0xe8();',
    '    /*                                                        ',
    '     * We have reviewed this function thoroughly for security ',
    '     * and we confirm caeven lling 0xe8() is totally fine. ',
    '     * This comment is for confirming the safety of this use.',
    '     * So, do not delete this line in any future commit.',
    '     */                                                       ',
    '    return 0;', '}'
])

_TEST_OSV_ID = 'ASB-A-123'
_TEST_LINE_SIG_HASH = 'linesighash'
_TEST_FUNC_SIG_HASH = 'functionsighash'
_TEST_TARGET_FILE = 'foo/bar/test_func_lib.c'


class RefinerTest(absltest.TestCase):

  def _create_tempfile(self, filename: str, content: str) -> str:
    tempfile = self.create_tempfile(
        file_path=os.path.join(self.create_tempdir(), filename),
        content=content,
        mode='w',
    )
    return tempfile.full_path

  def _create_groundtruth_commit_with_a_file(self, content):
    mock_commit = mock.create_autospec(
        code_extractor_base.Commit, instance=True
    )
    mock_commit.url = hash(content)
    tempfile = self._create_tempfile(_TEST_TARGET_FILE, content)
    mock_commit.patched_files = {
        _TEST_TARGET_FILE: tempfile,
        'unhandled.filetype': 'nonexistent_file',
    }
    return mock_commit

  def setUp(self):
    super().setUp()
    self._hash = functools.partial(
        mmh3.hash128, seed=0, x64arch=True, signed=False
    )
    self._test_function_sig = signature.FunctionSignature(
        signature_id=f'{_TEST_OSV_ID}-{_TEST_FUNC_SIG_HASH}',
        signature_version=signature._VANIR_SIGNATURE_VERSION,
        source=mock.Mock(),
        target_file=_TEST_TARGET_FILE,
        deprecated=mock.Mock(),
        exact_target_file_match_only=False,
        match_only_versions=None,
        truncated_path_level=None,
        function_hash=self._hash(_TEST_NORMALIZED_FUNCTION_CODE),
        length=len(_TEST_NORMALIZED_FUNCTION_CODE),
        target_function='test_func1',
    )
    test_line_hashes = []
    line_number_ngrams = [[1, 2, 3, 4], [2, 3, 4, 5], [3, 4, 5, 6],
                          [4, 5, 6, 7]]
    for line_numbers in line_number_ngrams:
      ngram = ' '.join([
          _TEST_NORMALIZED_LINE_CODE[line_number]
          for line_number in line_numbers
      ])
      test_line_hashes.append(self._hash(ngram))
    self._test_line_sig = signature.LineSignature(
        signature_id=f'{_TEST_OSV_ID}-{_TEST_LINE_SIG_HASH}',
        signature_version=signature._VANIR_SIGNATURE_VERSION,
        source=mock.Mock(),
        target_file=_TEST_TARGET_FILE,
        deprecated=mock.Mock(),
        exact_target_file_match_only=False,
        match_only_versions=None,
        truncated_path_level=None,
        line_hashes=test_line_hashes,
        threshold=0.9,
    )
    self._test_patched_commit_with_false_line_and_func_sig_matches = (
        self._create_groundtruth_commit_with_a_file(
            _TEST_PATCHED_CODE_WITH_FALSE_LINE_AND_FUNC_SIG_MATCHES
        )
    )
    self._test_patched_commit_with_false_func_sig_match_only = (
        self._create_groundtruth_commit_with_a_file(
            _TEST_PATCHED_CODE_WITH_FALSE_FUNC_SIG_MATCH
        )
    )
    self._test_patched_commit_without_false_positive = (
        self._create_groundtruth_commit_with_a_file(_TEST_PATCHED_CODE)
    )
    self._refiner = refiner.Refiner()

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

  def test_function_chunk_refinement_allows_good_sign(self):
    refined_signatures = self._refiner.refine_against_patch_series(
        [self._test_function_sig, self._test_line_sig],
        [self._test_patched_commit_without_false_positive],
        refiner.RemoveBadSignature(),
    )
    self.assertEqual(
        refined_signatures, {self._test_function_sig, self._test_line_sig},
    )

  def test_function_chunk_refinement_filters_out_bad_sign(self):
    refined_signatures = self._refiner.refine_against_patch_series(
        [self._test_function_sig, self._test_line_sig],
        [self._test_patched_commit_with_false_func_sig_match_only],
        refiner.RemoveBadSignature(),
    )
    self.assertEqual(refined_signatures, {self._test_line_sig})

    refined_signatures = self._refiner.refine_against_patch_series(
        [self._test_function_sig, self._test_line_sig],
        [self._test_patched_commit_with_false_line_and_func_sig_matches],
        refiner.RemoveBadSignature(),
    )
    self.assertEmpty(refined_signatures)

  def test_line_chunk_refinement_allows_good_sign(self):
    refined_signatures = self._refiner.refine_against_patch_series(
        [self._test_function_sig, self._test_line_sig],
        [self._test_patched_commit_without_false_positive],
        refiner.RemoveBadSignature(),
    )
    self.assertEqual(
        refined_signatures, {self._test_function_sig, self._test_line_sig},
    )

  def test_line_chunk_refinement_filters_out_bad_sign(self):
    refined_signatures = self._refiner.refine_against_patch_series(
        [self._test_function_sig, self._test_line_sig],
        [self._test_patched_commit_with_false_line_and_func_sig_matches],
        refiner.RemoveBadSignature(),
    )
    self.assertEmpty(refined_signatures)

  def test_refinement_patch_series_should_take_latest_file(self):
    # Simulate patch -> (partial) revert. Should cause signature to match.
    refined_signatures = self._refiner.refine_against_patch_series(
        [self._test_function_sig, self._test_line_sig],
        [
            self._test_patched_commit_without_false_positive,
            self._test_patched_commit_with_false_func_sig_match_only,
        ],
        refiner.RemoveBadSignature(),
    )
    self.assertEqual(refined_signatures, {self._test_line_sig})

  def test_refinement_with_patch_series_should_take_latest_file_clean(self):
    # Simulate patch -> (partial) revert -> patch. Should not cause any flag.
    refined_signatures = self._refiner.refine_against_patch_series(
        [self._test_function_sig, self._test_line_sig],
        [
            self._test_patched_commit_with_false_func_sig_match_only,
            self._test_patched_commit_without_false_positive,
        ],
        refiner.RemoveBadSignature(),
    )
    self.assertEqual(
        refined_signatures, {self._test_function_sig, self._test_line_sig},
    )

  def test_refinement_match_other_versions_mark_as_version_specific(self):
    refined_signatures = self._refiner.refine_against_patch_series(
        [self._test_function_sig, self._test_line_sig],
        [self._test_patched_commit_with_false_func_sig_match_only],
        refiner.MarkAsSpecificToVersions([10, 11]),
    )
    self.assertEqual(
        refined_signatures,
        {
            self._test_line_sig,
            dataclasses.replace(
                self._test_function_sig, match_only_versions=frozenset({10, 11})
            )
        }
    )

    refined_signatures = self._refiner.refine_against_patch_series(
        [self._test_function_sig, self._test_line_sig],
        [self._test_patched_commit_with_false_line_and_func_sig_matches],
        refiner.MarkAsSpecificToVersions([10, 11]),
    )
    self.assertEqual(
        refined_signatures,
        {
            dataclasses.replace(
                self._test_line_sig, match_only_versions=frozenset({10, 11})
            ),
            dataclasses.replace(
                self._test_function_sig, match_only_versions=frozenset({10, 11})
            )
        }
    )

  def test_refinement_match_other_files_versions_mark_as_version_specific(self):
    # Simulate a commit where the patched file is unrelated to the signatures,
    # but the signature target file at that rev matches the function signature.
    clean_file = self._create_tempfile('unrelated.c', _TEST_PATCHED_CODE)
    false_positive_file = self._create_tempfile(
        _TEST_TARGET_FILE, _TEST_PATCHED_CODE_WITH_FALSE_FUNC_SIG_MATCH
    )
    mock_commit = mock.create_autospec(
        code_extractor_base.Commit, instance=True
    )
    mock_commit.url = hash(_TEST_PATCHED_CODE)
    mock_commit.patched_files = {'unrelated.c': clean_file}
    mock_commit.get_file_at_rev.return_value = false_positive_file

    refined_signatures = self._refiner.refine_against_patch_series(
        [self._test_function_sig, self._test_line_sig],
        [mock_commit],
        refiner.MarkAsSpecificToVersions([10, 11]),
    )
    self.assertEqual(
        refined_signatures,
        {
            self._test_line_sig,
            dataclasses.replace(
                self._test_function_sig, match_only_versions=frozenset({10, 11})
            )
        }
    )

  def test_refinement_skip_when_parser_fails(self):
    with mock.patch.object(
        parser, 'Parser',
        side_effect=status.BuildStatusNotOk(
            status.StatusCode.CANCELLED, 'mock error'
        ),
    ):
      refined_signatures = self._refiner.refine_against_patch_series(
          [self._test_function_sig, self._test_line_sig],
          [self._test_patched_commit_without_false_positive],
          refiner.RemoveBadSignature(),
      )
    self.assertEqual(
        refined_signatures, {self._test_function_sig, self._test_line_sig}
    )

  def test_refinement_skip_when_parser_crashed(self):
    with mock.patch.object(
        parser, 'Parser',
        side_effect=concurrent.futures.process.BrokenProcessPool(),
    ):
      refined_signatures = self._refiner.refine_against_patch_series(
          [self._test_function_sig, self._test_line_sig],
          [self._test_patched_commit_without_false_positive],
          refiner.RemoveBadSignature(),
      )
    self.assertEqual(
        refined_signatures, {self._test_function_sig, self._test_line_sig}
    )


if __name__ == '__main__':
  absltest.main()
