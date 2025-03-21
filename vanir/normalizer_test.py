# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for normalizer."""

import json

from vanir import normalizer
from vanir.language_parsers import common

from absl.testing import absltest


class NormalizerTest(absltest.TestCase):

  def test_token_trie_insert_entry(self):
    token_trie = normalizer._TokenTrie()
    token_trie.insert_entry(['a', 'b', 'c', 'd', 'e'], 'V1')
    token_trie.insert_entry(['a', 'b'], 'V2')
    token_trie.insert_entry(['c', 'd', '', 'e'], 'V3')
    token_trie.insert_entry(['c', 'd'], 'V4')
    token_trie.insert_entry(['c', 'd'], 'V5')
    token_trie.insert_entry(['', '', ''], 'invalid entry')
    token_trie.insert_entry([], 'invalid entry')

    # Strip off defaultdict wraps using json.
    internal_trie_dict = json.loads(json.dumps(token_trie._trie))
    expected_dict = {'a': {'b': {'c': {'d': {'e': {'0': 'V1'}}}, '0': 'V2'}},
                     'c': {'d': {'e': {'0': 'V3'}, '0': 'V5'}}}

    self.assertEqual(internal_trie_dict, expected_dict)

  def test_token_trie_normalized_tokens(self):
    token_trie = normalizer._TokenTrie()
    token_trie.insert_entry(['a', 'b', 'c', 'd', 'e'], 'V1')
    token_trie.insert_entry(['a', 'b'], 'V2')
    token_trie.insert_entry(['c', 'd', 'e'], 'V3')
    token_trie.insert_entry(['c', 'd'], 'V4')

    test_token_stream = 'a b c d e a b c d e a b c a b c d x y z'.split()
    test_token_stream.insert(5, '')
    normalized_tokens = ' '.join(
        token_trie.generate_normalized_tokens(test_token_stream))
    expected_normalized_tokens = 'V1 V1 V2 c V2 V4 x y z'
    self.assertEqual(normalized_tokens, expected_normalized_tokens)

  def test_token_trie_get_next_normalized_token_makes_boundary_error(self):
    # The exception in _get_next_normalized_token() is not reachable with
    # public methods, so we directly run the function for this exception test.
    token_trie = normalizer._TokenTrie()
    with self.assertRaisesRegex(
        IndexError, r'Index:3 is out of boundary of tokens \(max:2\)'):
      token_trie._get_next_normalized_token(['a', 'b', 'c'], index=3)

  def test_function_chunk_normalization(self):
    test_chunk_base = common.FunctionChunkBase(
        name='test_func1',
        return_types=[['int']],
        parameters=['test_arg'],
        used_data_types=[['const', 'unsigned', '', 'int64'],
                         ['const', 'struct', 'teststruct'],
                         ['struct', 'teststruct']],
        local_variables=['testvar'],
        called_functions=['test_func2'],
        tokens=(
            'int test_func1 ( const unsigned int64 test_arg ) { const struct '
            'teststruct * testvar = ( struct teststruct * ) globalVar -> data '
            '; test_func2 ( test_arg , testvar ) ; 0xe8 ( ) ; return 0 ; }'
        ).split(),
    )

    normalized_code = normalizer.normalize_function_chunk(test_chunk_base)

    expected_normalized_code = (
        'DTYPE FUNCNAME ( const unsigned DTYPE PARAM ) { const DTYPE '
        '* VAR = ( DTYPE * ) globalvar -> data '
        '; FUNCCALL ( PARAM , VAR ) ; 0xe8 ( ) ; return 0 ; }')
    self.assertEqual(normalized_code, expected_normalized_code)

  def test_line_chunk_normalization(self):
    test_chunk_base = common.LineChunkBase(
        tokens={
            3: ['void', 'testFUNC', '(', 'int64', 'test_arg', ')', '{'],
            4: [
                'printk', '(', 'KERN_INFO', '"', '%d', '"', ',', 'test_arg',
                ')', ';', '}'
            ],
        },
    )

    normalized_code = normalizer.normalize_line_chunk(test_chunk_base)

    expected_normalized_code = {
        3: 'void testfunc ( int64 test_arg ) {',
        4: 'printk ( kern_info " %d " , test_arg ) ; }',
    }
    self.assertEqual(normalized_code, expected_normalized_code)


if __name__ == '__main__':
  absltest.main()
