# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Golden file test of the Vanir Kotlin parser.

The test parses the Kotlin files of three real Android fixes, i.e. the
Device Controls of SystemUI (CVE-2023-40124), the PermissionController
(CVE-2022-20218) and the PackageInstaller (CVE-2020-0418), and asserts

* that the parser reads them without an error,
* that the digests of their functions and of their lines are the ones that
  are frozen in the corpus, so that a change of the parser or of the
  grammar is caught, and
* that the two sides of every pair differ, i.e. that the parser tells the
  unpatched and the patched revision of a file apart.

The corpus holds the pairs of three real Android fixes, and its manifest
records the source commit of every pair.
"""

import json
import os
from typing import Any, Dict, Mapping

from absl.testing import absltest
from vanir import file_path_utils
from vanir import parser
from vanir.language_parsers import language_parsers

# The directory of the golden corpus, relative to the `vanir` package.
_CORPUS_DIR = file_path_utils.get_root_file_path(
    os.path.join('testdata', 'kotlin_golden'))

# The manifest and the digest document of the corpus.
_MANIFEST_PATH = os.path.join(_CORPUS_DIR, 'manifest.json')
_DIGESTS_PATH = os.path.join(_CORPUS_DIR, 'digests.json')


def _load_json(path: str) -> Dict[str, Any]:
  """Loads the JSON document of the given path."""
  with open(path, 'r', encoding='utf-8') as f:
    return json.load(f)


def _get_digests(
    path: str, relative_path: str
) -> Mapping[str, Any]:
  """Returns the digests of the given file, computed the production way.

  The file is parsed with the production parser and the digests are computed
  with the production normalizer and hasher, i.e. the very same values that
  Vanir stores in its signatures.

  Args:
    path: the absolute path of the file to parse.
    relative_path: the path of the file relative to the corpus root. It is
      used as the target file label of the generated chunks.

  Returns:
    A dict holding the file path, the function digests and the line digests.
  """
  file_parser = parser.Parser(path, relative_path)
  functions = []
  for chunk in file_parser.get_function_chunks():
    functions.append({
        'name': chunk.base.name,
        'function_hash': str(chunk.function_hash),
        'length': len(chunk.normalized_code),
    })
  # Functions are sorted by name. Functions sharing a name (e.g. C++
  # overloads) are sorted by their digest to keep the output byte stable.
  functions.sort(key=lambda f: (f['name'], f['function_hash'], f['length']))

  # The line hashes are emitted in ascending line number order, which is the
  # order in which the hasher generates the n-grams of a file.
  line_hashes = [str(h) for h in file_parser.get_line_chunk().line_hashes]

  return {
      'path': relative_path,
      'functions': functions,
      'line_hashes': line_hashes,
  }


class KotlinGoldenTest(absltest.TestCase):
  """Golden file test of the Kotlin parser."""

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    cls.manifest = _load_json(_MANIFEST_PATH)
    cls.digests = _load_json(_DIGESTS_PATH)
    cls.digests_by_path = {
        entry['path']: entry for entry in cls.digests.get('files', [])
    }

  def test_the_corpus_holds_the_three_fixes(self):
    pairs = self.manifest.get('pairs', [])
    self.assertLen(pairs, 6)
    cve_ids = set()
    for pair in pairs:
      cve_ids.update(pair.get('cve_ids', []))
    self.assertEqual(
        cve_ids,
        {'CVE-2023-40124', 'CVE-2022-20218', 'CVE-2020-0418'},
        'The corpus does not hold the three fixes of the spec.')
    for pair in pairs:
      self.assertTrue(pair.get('fix_commit_sha'))
      self.assertTrue(pair.get('parent_commit_sha'))
      self.assertNotEqual(pair.get('fix_commit_sha'),
                          pair.get('parent_commit_sha'))

  def test_the_files_are_parsed_without_an_error(self):
    for pair in self.manifest.get('pairs', []):
      for side in ('unpatched_file', 'patched_file'):
        path = os.path.join(_CORPUS_DIR, pair[side])
        results = language_parsers.parse_file(path)
        self.assertEmpty(
            results.parse_errors,
            f'{pair["id"]} ({side}) does not parse without an error.')

  def test_the_digests_of_the_files_are_frozen(self):
    for path, expected in self.digests_by_path.items():
      absolute_path = os.path.join(_CORPUS_DIR, path)
      self.assertTrue(os.path.exists(absolute_path), f'{path} is missing.')
      digests = _get_digests(absolute_path, path)
      self.assertEqual(
          digests['functions'], expected['functions'],
          f'The function digests of {path} changed.')
      self.assertEqual(
          digests['line_hashes'], expected['line_hashes'],
          f'The line digests of {path} changed.')

  def test_the_two_sides_of_a_pair_differ(self):
    for pair in self.manifest.get('pairs', []):
      unpatched = self.digests_by_path[pair['unpatched_file']]
      patched = self.digests_by_path[pair['patched_file']]
      # The fix changed the file, so the digests of its lines differ.
      self.assertNotEqual(
          unpatched['line_hashes'], patched['line_hashes'],
          f'The two sides of {pair["id"]} have the same line digests.')
      # The functions the fix touched have different digests.
      unpatched_functions = {
          function['name']: function['function_hash']
          for function in unpatched['functions']
      }
      patched_functions = {
          function['name']: function['function_hash']
          for function in patched['functions']
      }
      differing = sorted(
          name for name in unpatched_functions
          if name in patched_functions
          and unpatched_functions[name] != patched_functions[name])
      self.assertEqual(
          differing, pair.get('differing_functions', []),
          f'The functions that differ in {pair["id"]} are not the ones the '
          'manifest records.')

  def test_the_manifest_matches_the_digest_document(self):
    for pair in self.manifest.get('pairs', []):
      for side in ('unpatched_file', 'patched_file'):
        self.assertIn(pair[side], self.digests_by_path)


if __name__ == '__main__':
  absltest.main()
