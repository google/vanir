# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for the parse sweep of the language phases."""

import json
import os

from absl.testing import absltest
from vanir import parse_sweep


class ParseSweepTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.root = self.create_tempdir().full_path
    self.good = self._write('good.kt', """
      fun aFunction(value: Int): Int {
        val doubled = value * 2
        return doubled
      }
    """)
    self.broken = self._write('broken.kt', """
      fun aFunction(value: Int): Int {
        val doubled = (value *
        return doubled
      }
    """)

  def _write(self, name, content):
    path = os.path.join(self.root, name)
    with open(path, 'w', encoding='utf-8') as f:
      f.write(content)
    return path

  def test_find_source_files_finds_the_files_of_the_extension(self):
    self._write('not_kotlin.txt', 'nothing')
    found = parse_sweep.find_source_files(self.root, ['.kt'])
    self.assertCountEqual(found, [self.good, self.broken])

  def test_find_source_files_skips_the_git_directory(self):
    git_dir = os.path.join(self.root, '.git')
    os.makedirs(git_dir)
    self._write(os.path.join('.git', 'hidden.kt'), 'fun hidden() {}')
    found = parse_sweep.find_source_files(self.root, ['.kt'])
    self.assertCountEqual(found, [self.good, self.broken])

  def test_a_file_that_parses_is_counted(self):
    result = parse_sweep.sweep_file(self.good, 'good.kt')
    self.assertTrue(result.parsed)
    self.assertEqual(result.functions, 1)
    self.assertEmpty(result.errors)
    self.assertIsNone(result.exception)

  def test_a_file_with_a_syntax_error_is_counted_as_failed(self):
    result = parse_sweep.sweep_file(self.broken, 'broken.kt')
    self.assertFalse(result.parsed)
    self.assertGreater(result.error_count, 0)
    self.assertNotEmpty(result.errors)
    self.assertIsNone(result.exception)

  def test_a_parser_that_raises_does_not_stop_the_sweep(self):
    result = parse_sweep.sweep_file(
        os.path.join(self.root, 'missing.kt'), 'missing.kt')
    self.assertFalse(result.parsed)
    self.assertIsNotNone(result.exception)

  def test_the_sweep_counts_the_files_and_the_functions(self):
    result = parse_sweep.sweep(self.root, 'kotlin', '.kt')
    self.assertEqual(result.files, 2)
    self.assertEqual(result.files_parsed, 1)
    self.assertEqual(result.files_with_errors, 1)
    self.assertEqual(result.files_with_exceptions, 0)
    # The grammar is error tolerant, so the file with the syntax error still
    # yields its function, but it is not counted as a file that parsed.
    self.assertEqual(result.functions, 2)
    self.assertAlmostEqual(result.error_rate, 0.5)

  def test_the_sweep_uses_the_parser_of_the_language(self):
    results = parse_sweep.sweep_all([self.root], 'kotlin')
    self.assertLen(results, 1)
    self.assertEqual(results[0].language, 'kotlin')
    self.assertEqual(results[0].extension, '.kt')
    self.assertEqual(results[0].files, 2)

  def test_the_sweep_rejects_a_language_without_a_parser(self):
    with self.assertRaises(ValueError):
      parse_sweep.sweep_all([self.root], 'cobol')

  def test_the_summary_adds_the_checkouts_up(self):
    results = parse_sweep.sweep_all([self.root], 'kotlin')
    summary = parse_sweep.summarize(results)
    self.assertEqual(summary['files'], 2)
    self.assertEqual(summary['files_parsed'], 1)
    self.assertEqual(summary['files_failed'], 1)
    self.assertEqual(summary['functions'], 2)

  def test_the_result_is_json_serializable(self):
    results = parse_sweep.sweep_all([self.root], 'kotlin')
    document = {
        'summary': parse_sweep.summarize(results),
        'checkouts': [r.to_dict() for r in results],
    }
    text = json.dumps(document, indent=2, sort_keys=True)
    self.assertIn('"summary"', text)


if __name__ == '__main__':
  absltest.main()
