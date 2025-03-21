# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for hasher."""

import functools

from absl import logging
import mmh3
from vanir import hasher

from absl.testing import absltest
from absl.testing import parameterized


_TEST_LINE_CHUNK_NORMALIZED_CODE = {
    5: 'void __init testdev_init ( void )',
    6: '{',
    7: 'memset ( cdev , 0 , sizeof * cdev ) ;',
    8: 'init_list_head ( & cdev -> list ) ;',
    9: 'kobject_init ( & cdev -> kobj , & ktype_cdev_default ) ;',
    10: 'cdev -> ops = fops ;',
    11: '}',
    19: 'cdev_map = kobj_map_init ( base_probe , & testdevs_lock ) ;',
    20: '}',
    24: 'export_symbol ( register_testdev_region ) ;',
    34: 'export_symbol ( __register_testdev ) ;',
    35: 'export_symbol ( __unregister_testdev ) ;'
}


class HasherTest(parameterized.TestCase):

  def setUp(self):
    self._hash = functools.partial(
        mmh3.hash128, seed=0, x64arch=True, signed=False)
    super().setUp()

  def test_function_chunk_hash(self):
    test_normalized_code = (
        'DTYPE FUNCNAME ( const unsigned DTYPE PARAM ) { const DTYPE '
        '* VAR = ( DTYPE * ) globalvar -> data '
        '; FUNCCALL ( PARAM , VAR ) ; 0xe8 ( ) ; return 0 ; }')

    function_hash = hasher.hash_function_chunk(test_normalized_code)

    expected_function_hash = self._hash(test_normalized_code)
    self.assertEqual(function_hash, expected_function_hash)

  @parameterized.named_parameters(
      dict(
          testcase_name='with_no_affected_ranges',
          normalized_code=_TEST_LINE_CHUNK_NORMALIZED_CODE,
          affected_ranges=[],
          expected_used_lines=[5, 6, 7, 8, 9, 10, 11, 19, 20, 24, 34, 35]),
      dict(
          testcase_name='with_affected_ranges_in_middle',
          normalized_code=_TEST_LINE_CHUNK_NORMALIZED_CODE,
          affected_ranges=[(9, 10)],
          expected_used_lines=[6, 7, 8, 9, 10, 11, 19, 20]),
      dict(
          testcase_name='with_affected_ranges_at_file_start',
          normalized_code=_TEST_LINE_CHUNK_NORMALIZED_CODE,
          affected_ranges=[(0, 0)],
          expected_used_lines=[5, 6, 7, 8]),
      dict(
          testcase_name='with_affected_ranges_at_file_end',
          normalized_code=_TEST_LINE_CHUNK_NORMALIZED_CODE,
          affected_ranges=[(50, 50)],
          expected_used_lines=[20, 24, 34, 35]),
      dict(
          testcase_name='with_short_normalized_code',
          normalized_code={
              3: '#define AUDIT_NAMES 5',
              4: '#define auditsc_get_stamp ( c , t , s ) 0'
          },
          affected_ranges=[],
          expected_used_lines=[3, 4]))
  def test_line_chunk_hash(self, normalized_code, affected_ranges,
                           expected_used_lines):
    """Tests various successful cases of line chunk hash generation.

    Args:
      normalized_code: the normalized code to test.
      affected_ranges: the affected ranges to test with for the normalized code.
      expected_used_lines: expected lines to be used for signature hash
        generation. This value varies depending on |affected_ranges| but this
        test explicitly requires this arg because we want to test the
        corresponding logic in the main code rather than to run the identical
        logic again in the test.
    """
    expected_hashes = []
    expected_line_number_ngrams = []
    index = 0
    while index + 3 < len(expected_used_lines):
      expected_line_number_ngrams.append(expected_used_lines[index:index + 4])
      index += 1
    if not expected_line_number_ngrams:
      expected_line_number_ngrams.append(normalized_code.keys())

    for line_numbers in expected_line_number_ngrams:
      ngram = ' '.join(
          [normalized_code[line_number] for line_number in line_numbers])
      expected_hashes.append(self._hash(ngram))

    line_hashes, used_lines = hasher.hash_line_chunk(normalized_code,
                                                     affected_ranges)

    self.assertCountEqual(expected_used_lines, used_lines)
    self.assertEqual(expected_hashes, line_hashes)

  def test_line_chunk_hash_with_empty_normalized_code_is_warned(self):
    test_normalized_code = {}
    with self.assertLogs(level=logging.WARNING) as logs:
      line_hashes, used_lines = hasher.hash_line_chunk(test_normalized_code, [])
    self.assertIn(
        'No valid line found from the normalized code. Returning empty lists.',
        logs.output[0])
    self.assertEmpty(line_hashes)
    self.assertEmpty(used_lines)

  def test_line_ngram_overlap_check_fails_with_reversed_line_range(self):
    # Case unable to be triggered by public class; directly test private class.
    test_ngram_line_numbers = [7, 8, 9, 10]
    test_affected_line_range = (10, 7)
    ngram = hasher._LineNgram(_TEST_LINE_CHUNK_NORMALIZED_CODE,
                              test_ngram_line_numbers)
    expected_error_msg = (
        r'line_range: start \(10\) cannot be greater than end \(7\)')
    with self.assertRaisesRegex(ValueError, expected_error_msg):
      ngram.is_overlapping(test_affected_line_range)

if __name__ == '__main__':
  absltest.main()
