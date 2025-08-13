# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

import dataclasses
from typing import Union
from unittest import mock

from absl import logging
from vanir import signature

from absl.testing import absltest
from absl.testing import parameterized

_TEST_NORMALIZED_FUNCTION_CODE = 'norm_code'
_TEST_NORMALIZED_LINE_CODE = {10: 'hello world'}
_TEST_FUNCTION_HASH = 1234
_TEST_LINE_HASHES = [5678, 6789]


class SignatureTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.addCleanup(mock.patch.stopall)
    self.test_line_signature = signature.LineSignature(
        signature_id='line-sig-id',
        signature_version=signature._VANIR_SIGNATURE_VERSION,
        source='patch_url',
        target_file='file1',
        deprecated=False,
        exact_target_file_match_only=False,
        match_only_versions=None,
        truncated_path_level=None,
        line_hashes=[123, 456],
        threshold=0.9,
    )
    self.test_function_signature = signature.FunctionSignature(
        signature_id='func-sig-id',
        signature_version=signature._VANIR_SIGNATURE_VERSION,
        source='patch_url',
        target_file='file1',
        deprecated=False,
        exact_target_file_match_only=False,
        match_only_versions=None,
        truncated_path_level=None,
        function_hash=11111,
        length=5,
        target_function='',
    )

  @mock.patch(
      'vanir.normalizer.normalize_function_chunk',
      return_value=_TEST_NORMALIZED_FUNCTION_CODE,
  )
  @mock.patch(
      'vanir.hasher.hash_function_chunk', return_value=_TEST_FUNCTION_HASH
  )
  def test_function_chunk_creation(self, hash_function_chunk,
                                   normalize_function_chunk):
    test_chunk_base = mock.Mock()
    test_target_file = 'foo/bar/test_lib.c'

    chunk = signature.create_function_chunk(test_chunk_base, test_target_file)

    normalize_function_chunk.assert_called_once_with(test_chunk_base)
    hash_function_chunk.assert_called_once_with(_TEST_NORMALIZED_FUNCTION_CODE)
    self.assertEqual(chunk.base, test_chunk_base)
    self.assertEqual(chunk.target_file, test_target_file)
    self.assertEqual(chunk.normalized_code, _TEST_NORMALIZED_FUNCTION_CODE)
    self.assertEqual(chunk.function_hash, _TEST_FUNCTION_HASH)

  @mock.patch(
      'vanir.normalizer.normalize_line_chunk',
      return_value=_TEST_NORMALIZED_LINE_CODE,
  )
  @mock.patch(
      'vanir.hasher.hash_line_chunk',
      return_value=(_TEST_LINE_HASHES, [10, 11, 12, 13]),
  )
  def test_line_chunk_creation(self, hash_line_chunk, normalize_line_chunk):
    test_chunk_base = mock.Mock()
    test_affected_file_ranges = [range(10, 20), range(40, 50)]
    test_target_file = 'foo/bar/test_lib.c'

    chunk = signature.create_line_chunk(test_chunk_base,
                                        test_affected_file_ranges,
                                        test_target_file)

    normalize_line_chunk.assert_called_once_with(test_chunk_base)
    hash_line_chunk.assert_called_once_with(_TEST_NORMALIZED_LINE_CODE,
                                            test_affected_file_ranges)
    self.assertEqual(chunk.base, test_chunk_base)
    self.assertEqual(chunk.target_file, test_target_file)
    self.assertEqual(chunk.normalized_code, _TEST_NORMALIZED_LINE_CODE)
    self.assertEqual(chunk.line_hashes, _TEST_LINE_HASHES)
    self.assertEqual(chunk.used_lines, [10, 11, 12, 13])

  @mock.patch('vanir.normalizer.normalize_line_chunk', return_value={})
  @mock.patch('vanir.hasher.hash_line_chunk', return_value=([], []))
  def test_line_chunk_creation_with_empty_valid_lines_is_warned(
      self, hash_line_chunk, normalize_line_chunk):
    """Tests if the line sign creation warns if the hash list is empty.

    This test is to make sure that we get a proper warning when a line signature
    has no hashes inside. A signature with no hash never get flagged during
    the detection phase, but human operators should investigate this case and
    make a decision to either drop the signature or customize it. The warning
    log is necessary for this investigation process.

    Args:
      hash_line_chunk: mock hash_line_chunk function.
      normalize_line_chunk: mock normalize_line_chunk function.
    """
    test_target_file = 'foo/bar/test_lib.c'

    with self.assertLogs(level=logging.WARNING) as logs:
      chunk = signature.create_line_chunk(mock.Mock(), mock.Mock(),
                                          test_target_file)

    normalize_line_chunk.assert_called_once()
    hash_line_chunk.assert_called_once()
    self.assertEqual(chunk.line_hashes, [])
    self.assertEqual(chunk.used_lines, [])
    self.assertIn('The line chunk of %s has no hash.' % test_target_file,
                  logs.output[0])

  def test_function_signature_creation_from_function_chunk(self):
    test_function_chunk_base = mock.Mock()
    test_function_name = 'test_func1'
    test_function_chunk_base.name = test_function_name
    test_target_file = 'foo/bar/test_lib.c'
    test_normalized_code = _TEST_NORMALIZED_FUNCTION_CODE
    test_function_hash = _TEST_FUNCTION_HASH
    test_source = 'http://android.googlesource.com/test_source'
    test_truncated_path_level = 10

    test_function_chunk = signature.FunctionChunk(test_function_chunk_base,
                                                  test_target_file,
                                                  test_normalized_code,
                                                  test_function_hash)

    signature_factory = signature.SignatureFactory('TESTPREFIX')
    func_sign = signature_factory.create_from_function_chunk(
        test_function_chunk,
        test_source,
        test_truncated_path_level,
    )

    expected_siganture_id_pattern = 'TESTPREFIX-[0-9a-f]{8}$'
    self.assertRegex(func_sign.signature_id, expected_siganture_id_pattern)
    self.assertEqual(func_sign.signature_version,
                     signature._VANIR_SIGNATURE_VERSION)
    self.assertEqual(func_sign.source, test_source)
    self.assertEqual(func_sign.target_file, test_target_file)
    self.assertFalse(func_sign.deprecated)
    self.assertEqual(func_sign.function_hash, test_function_hash)
    expected_length = len(test_normalized_code)
    self.assertEqual(func_sign.length, expected_length)
    self.assertEqual(func_sign.target_function, test_function_name)
    self.assertEqual(func_sign.signature_type,
                     signature.SignatureType.FUNCTION_SIGNATURE)
    self.assertEqual(func_sign.truncated_path_level, test_truncated_path_level)

  def test_line_signature_creation_from_line_chunk(self):
    test_target_file = 'foo/bar/test_lib.c'
    test_line_hashes = _TEST_LINE_HASHES
    test_line_chunk = signature.LineChunk(mock.Mock(), test_target_file,
                                          mock.Mock(), test_line_hashes,
                                          mock.Mock())
    test_source = 'http://android.googlesource.com/test_source'
    test_threshold = 0.456
    test_truncated_path_level = 2

    signature_factory = signature.SignatureFactory('TESTPREFIX')
    line_sign = signature_factory.create_from_line_chunk(
        test_line_chunk,
        test_source,
        test_threshold,
        test_truncated_path_level,
    )

    expected_siganture_id_pattern = 'TESTPREFIX-[0-9a-f]{8}$'
    self.assertRegex(line_sign.signature_id, expected_siganture_id_pattern)
    self.assertEqual(line_sign.signature_version,
                     signature._VANIR_SIGNATURE_VERSION)
    self.assertEqual(line_sign.source, test_source)
    self.assertEqual(line_sign.target_file, test_target_file)
    self.assertFalse(line_sign.deprecated)
    self.assertEqual(line_sign.line_hashes, test_line_hashes)
    self.assertEqual(line_sign.threshold, test_threshold)
    self.assertEqual(line_sign.signature_type,
                     signature.SignatureType.LINE_SIGNATURE)
    self.assertEqual(line_sign.truncated_path_level, test_truncated_path_level)

  @mock.patch(
      'vanir.signature.SignatureFactory._generate_signature_id',
      return_value='ASB-A-SIGNATURE-ID',
  )
  def test_line_signature_creation_fails_with_invalid_threshold(
      self, gen_sig_hash):
    test_threshold = 5000

    signature_factory = signature.SignatureFactory('TESTPREFIX')
    with self.assertRaisesRegex(
        ValueError, 'Invalid line signature threshold: (-)*[0-9]*[.][0-9]*[.]'
        ' Line signature threshold must be between 0 and 1.'):
      signature_factory.create_from_line_chunk(
          mock.Mock(), mock.Mock(), test_threshold
      )
    gen_sig_hash.assert_called_once()

  def test_signature_id_generation_adds_salt_if_id_already_exits(self):
    test_function_chunk_base = mock.Mock()
    test_function_name = 'test_func1'
    test_function_chunk_base.name = test_function_name
    test_target_file = 'foo/bar/test_lib.c'
    test_normalized_code = _TEST_NORMALIZED_FUNCTION_CODE
    test_function_hash = _TEST_FUNCTION_HASH
    test_source = 'http://android.googlesource.com/test_source'

    test_function_chunk = signature.FunctionChunk(test_function_chunk_base,
                                                  test_target_file,
                                                  test_normalized_code,
                                                  test_function_hash)

    signature_factory = signature.SignatureFactory('TESTPREFIX')
    func_sign1 = signature_factory.create_from_function_chunk(
        test_function_chunk, test_source)
    func_sign2 = signature_factory.create_from_function_chunk(
        test_function_chunk, test_source)
    self.assertStartsWith(func_sign1.signature_id, 'TESTPREFIX')
    self.assertStartsWith(func_sign2.signature_id, 'TESTPREFIX')
    self.assertNotEqual(func_sign1.signature_id, func_sign2.signature_id)

  @parameterized.named_parameters(
      ('with_int_hash', _TEST_FUNCTION_HASH, False),
      ('with_string_hash', str(_TEST_FUNCTION_HASH), True),
  )
  def test_function_signature_creation_from_osv_sign(
      self, test_function_hash: Union[int, str], use_string_hashes: bool
  ):
    test_signature_id = 'ASB-A-12345-TEST-SIGN-ID-12345678'
    test_signature_version = 'v1234'
    test_source = 'http://android.googlesource.com/test_source'
    test_target_file = 'foo/bar/test_lib.c'
    test_function_name = 'test_func1'
    test_deprecated = True
    test_match_only_versions = ['11', '12L']
    test_exact_target_file_match_only = True
    test_length = 100
    test_osv_sign = {
        'id': test_signature_id,
        'signature_type': 'Function',
        'signature_version': test_signature_version,
        'source': test_source,
        'target': {
            'file': test_target_file,
            'function': test_function_name,
        },
        'deprecated': test_deprecated,
        'match_only_versions': test_match_only_versions,
        'exact_target_file_match_only': test_exact_target_file_match_only,
        'digest': {
            'function_hash': test_function_hash,
            'length': test_length,
        },
    }

    func_sign = signature.Signature.from_osv_dict(test_osv_sign)

    self.assertEqual(func_sign.signature_id, test_signature_id)
    self.assertEqual(func_sign.signature_version, test_signature_version)
    self.assertEqual(func_sign.source, test_source)
    self.assertEqual(func_sign.target_file, test_target_file)
    self.assertEqual(func_sign.deprecated, test_deprecated)
    self.assertEqual(
        func_sign.match_only_versions,
        set(test_match_only_versions),
    )
    self.assertEqual(
        func_sign.exact_target_file_match_only,
        test_exact_target_file_match_only,
    )
    self.assertEqual(func_sign.function_hash, int(test_function_hash))
    self.assertEqual(func_sign.length, test_length)
    self.assertEqual(func_sign.target_function, test_function_name)
    self.assertIsNone(func_sign.truncated_path_level)

    self.assertEqual(func_sign.to_osv_dict(use_string_hashes), test_osv_sign)

  @parameterized.named_parameters(
      ('with_int_hashes', _TEST_LINE_HASHES, False),
      ('with_string_hashes', [str(h) for h in _TEST_LINE_HASHES], True),
  )
  def test_line_signature_creation_from_osv_sign(
      self, test_line_hashes: list[Union[str, int]], use_string_hashes: bool
  ):
    test_signature_id = 'ASB-A-12345-TEST-SIGN-ID-12345678-1'
    test_signature_version = 'v1234'
    test_source = 'http://android.googlesource.com/test_source'
    test_target_file = 'foo/bar/test_lib.c'
    test_deprecated = True
    test_threshold = 0.789
    test_tp_level = 1
    test_osv_sign = {
        'id': test_signature_id,
        'signature_type': 'Line',
        'signature_version': test_signature_version,
        'source': test_source,
        'target': {
            'file': test_target_file,
            'truncated_path_level': test_tp_level,
        },
        'deprecated': test_deprecated,
        'digest': {
            'line_hashes': test_line_hashes,
            'threshold': test_threshold,
        },
    }

    line_sign = signature.Signature.from_osv_dict(test_osv_sign)

    self.assertEqual(line_sign.signature_id, test_signature_id)
    self.assertEqual(line_sign.signature_version, test_signature_version)
    self.assertEqual(line_sign.source, test_source)
    self.assertEqual(line_sign.target_file, test_target_file)
    self.assertEqual(line_sign.deprecated, test_deprecated)
    self.assertEqual(line_sign.exact_target_file_match_only, False)
    self.assertIsNone(line_sign.match_only_versions)
    self.assertEqual(line_sign.line_hashes, [int(h) for h in test_line_hashes])
    self.assertEqual(line_sign.threshold, test_threshold)
    self.assertEqual(line_sign.truncated_path_level, test_tp_level)

    self.assertEqual(line_sign.to_osv_dict(use_string_hashes), test_osv_sign)

  @parameterized.named_parameters(
      ('with_int_hashes', _TEST_LINE_HASHES, False),
      ('with_string_hashes', [str(h) for h in _TEST_LINE_HASHES], True),
  )
  def test_line_signature_creation_from_osv_sign_with_floats(
      self, test_line_hashes: list[Union[str, int]], use_string_hashes: bool
  ):
    test_signature_id = 'ASB-A-12345-TEST-SIGN-ID-12345678-1-1'
    test_tp_level = 1.0
    test_osv_sign = {
        'id': test_signature_id,
        'signature_type': 'Line',
        'signature_version': 'v1234',
        'source': 'http://android.googlesource.com/test_source',
        'target': {
            'file': 'foo/bar/test_lib.c',
            'truncated_path_level': test_tp_level,
        },
        'deprecated': False,
        'digest': {
            'line_hashes': test_line_hashes,
            'threshold': 0.789,
        },
    }
    line_sign = signature.Signature.from_osv_dict(test_osv_sign)

    self.assertEqual(line_sign.signature_id, test_signature_id)
    self.assertEqual(line_sign.truncated_path_level, 1)
    self.assertEqual(line_sign.to_osv_dict(use_string_hashes), test_osv_sign)

  @parameterized.named_parameters(
      ('with_int_hash', _TEST_FUNCTION_HASH, False),
      ('with_string_hash', str(_TEST_FUNCTION_HASH), True),
  )
  def test_function_signature_creation_from_osv_sign_with_floats(
      self, test_function_hash: Union[int, str], use_string_hashes: bool
  ):
    test_signature_id = 'ASB-A-12345-TEST-SIGN-ID-12345678-1-2'
    test_length = 100.0
    test_osv_sign = {
        'id': test_signature_id,
        'signature_type': 'Function',
        'signature_version': 'v1234',
        'source': 'http://android.googlesource.com/test_source',
        'target': {
            'file': 'foo/bar/test_lib.c',
            'function': 'test_func1',
        },
        'deprecated': False,
        'digest': {
            'function_hash': test_function_hash,
            'length': test_length,
        },
    }
    line_sign = signature.Signature.from_osv_dict(test_osv_sign)

    self.assertEqual(line_sign.signature_id, test_signature_id)
    self.assertEqual(line_sign.length, 100)
    self.assertEqual(line_sign.to_osv_dict(use_string_hashes), test_osv_sign)

  def test_signature_creation_from_osv_sign_fails_with_unknown_sign_type(self):
    test_signature_id = 'ASB-A-12345-TEST-SIGN-ID-12345678-2'
    test_osv_sign = {
        'signature_type': 'some_unknown_type',
        'id': test_signature_id
    }

    # Unknown signature type will be caught by SignatureType enum.
    with self.assertRaises(ValueError):
      signature.Signature.from_osv_dict(test_osv_sign)

    # Even if new signature type is added to SignatureType, the type must be
    # also handled in from_osv_dict().
    with mock.patch('vanir.signature.SignatureType'):
      with self.assertRaisesRegex(ValueError, 'Signature type .* is unknown'):
        signature.Signature.from_osv_dict(test_osv_sign)

  def test_signature_bundle_match_for_function_chunks(self):
    # Prepare a test function chunk.
    test_function_chunk_base = mock.Mock()
    test_chunk_target_file = '/my/test/kernel/foo/bar/test_lib.c'
    test_normalized_code = _TEST_NORMALIZED_FUNCTION_CODE
    test_function_hash = _TEST_FUNCTION_HASH
    test_function_chunk = signature.FunctionChunk(test_function_chunk_base,
                                                  test_chunk_target_file,
                                                  test_normalized_code,
                                                  test_function_hash)

    # Prepare a test function signature.
    test_signature_id = 'ASB-A-12345-TEST-OSV-SIGN-ID-1'
    test_source = 'http://android.googlesource.com/test_source'
    test_target_file = 'foo/bar/test_lib.c'
    test_osv_sign = {
        'id': test_signature_id,
        'signature_type': 'Function',
        'signature_version': signature._VANIR_SIGNATURE_VERSION,
        'source': test_source,
        'target': {
            'file': test_target_file,
            'function': 'foo'
        },
        'deprecated': False,
        'digest': {
            'function_hash': test_function_hash,
            'length': len(test_normalized_code)
        }
    }
    test_signature = signature.Signature.from_osv_dict(test_osv_sign)

    # Test signature bundle match for function chunks.
    sign_bundle = signature.SignatureBundle([test_signature])
    matched_signs = sign_bundle.match(test_function_chunk)
    self.assertEqual(matched_signs, [test_signature])
    self.assertEqual(sign_bundle.signatures, [test_signature])

  def test_signature_bundle_match_for_line_chunks(self):
    # Prepare a test line chunk.
    test_target_file = 'foo/bar/test_lib.c'
    test_line_hashes = [1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888]
    test_line_chunk = signature.LineChunk(mock.Mock(), test_target_file,
                                          mock.Mock(), test_line_hashes,
                                          mock.Mock())
    # Prepare a test line signature.
    test_signature_id = 'ASB-A-12345-TEST-SIGN-ID-12345678-4'
    test_source = 'http://android.googlesource.com/test_source'
    test_signature_line_hashes = [2222, 3333, 4444, 1234]  # 75% inclusion.
    test_threshold = 0.75
    test_osv_sign = {
        'id': test_signature_id,
        'signature_type': 'Line',
        'signature_version': signature._VANIR_SIGNATURE_VERSION,
        'source': test_source,
        'target': {
            'file': test_target_file,
        },
        'deprecated': False,
        'digest': {
            'line_hashes': test_signature_line_hashes,
            'threshold': test_threshold
        }
    }
    test_signature = signature.Signature.from_osv_dict(test_osv_sign)

    # Test signature bundle match for line chunks.
    sign_bundle = signature.SignatureBundle([test_signature])
    matched_signs = sign_bundle.match(test_line_chunk)
    self.assertEqual(matched_signs, [test_signature])

    # Increase the threshold to 76%; now the sign should not match.
    new_test_signature_id = 'ASB-A-12345-TEST-SIGN-ID-12345678-5'
    test_osv_sign['id'] = new_test_signature_id
    test_osv_sign['digest']['threshold'] = 0.76

    test_signature = signature.Signature.from_osv_dict(test_osv_sign)
    sign_bundle = signature.SignatureBundle([test_signature])
    matched_signs = sign_bundle.match(test_line_chunk)
    self.assertEmpty(matched_signs)

  def test_signature_bundle_match_fails_with_unknown_chunk_type(self):
    sign_bundle = signature.SignatureBundle([self.test_line_signature])
    with self.assertRaisesRegex(TypeError,
                                'The type of given chunk .* is unknown.'):
      sign_bundle.match(chunk=mock.Mock())

  def test_signature_bundle_filters_out_uncompatible_signatures(self):
    test_signature = dataclasses.replace(
        self.test_line_signature,
        signature_version='v1234',
    )
    with self.assertLogs(level=logging.WARNING) as logs:
      sign_bundle = signature.SignatureBundle([test_signature])
    self.assertIn(
        'Signature %s is disregarded due to version mismatch: (current ver: '
        '%s, the signature ver: %s)' %
        (test_signature.signature_id, signature._VANIR_SIGNATURE_VERSION,
         test_signature.signature_version), logs.output[0])
    self.assertEmpty(sign_bundle.signatures)

  def test_signature_bundle_filters_out_unrecognized_signatures(self):
    test_signature = mock.create_autospec(
        signature.Signature, instance=True,
        signature_version=signature._VANIR_SIGNATURE_VERSION,
        signature_type='some_unknown_type',
        signature_id='ASB-A-12345-TEST-SIGN-ID-12345678',
    )
    with self.assertLogs(level=logging.ERROR) as logs:
      sign_bundle = signature.SignatureBundle([test_signature])
    self.assertIn(
        'Signature %s is disregarded due to its unrecognized type: %s' %
        (test_signature.signature_id, test_signature.signature_type),
        logs.output[0])
    self.assertEmpty(sign_bundle.signatures)

  def test_signature_bundle_function_signature_hash_collisions(self):
    test_signature1 = dataclasses.replace(
        self.test_function_signature,
        signature_id='test-sig-id-1',
    )
    test_signature2 = dataclasses.replace(
        self.test_function_signature,
        signature_id='test-sig-id-2',
    )
    sign_bundle = signature.SignatureBundle(
        [test_signature1, test_signature2])
    self.assertEqual(
        sign_bundle.function_signature_hash_collisions(),
        [['test-sig-id-1', 'test-sig-id-2']])
    self.assertEqual(sign_bundle.signatures, [test_signature1, test_signature2])

  def test_signature_bundle_get_target_file_paths(self):
    sign_bundle = signature.SignatureBundle([
        self.test_line_signature,
        self.test_function_signature,
    ])
    self.assertEqual(sign_bundle.target_file_paths, {'file1'})

  def test_signature_bundle_from_bundles(self):
    test_line_signature_2 = dataclasses.replace(
        self.test_line_signature,
        signature_id='line-sig-id-2',
    )
    bundle1 = signature.SignatureBundle(
        [self.test_line_signature, self.test_function_signature]
    )
    bundle2 = signature.SignatureBundle([test_line_signature_2])
    combined_bundle = signature.SignatureBundle.from_bundles([bundle1, bundle2])
    self.assertCountEqual(
        combined_bundle.signatures,
        [
            self.test_line_signature,
            self.test_function_signature,
            test_line_signature_2,
        ],
    )

  def test_signature_bundle_from_bundles_single_bundle(self):
    bundle = signature.SignatureBundle(
        [self.test_line_signature, self.test_function_signature]
    )
    combined_bundle_single = signature.SignatureBundle.from_bundles([bundle])
    self.assertIs(combined_bundle_single, bundle)

  def test_signature_bundle_truthiness(self):
    self.assertFalse(signature.SignatureBundle([]))
    self.assertTrue(signature.SignatureBundle([self.test_line_signature]))

if __name__ == '__main__':
  absltest.main()
