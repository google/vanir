# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for signature."""

from unittest import mock

from absl import logging
from vanir import signature

from absl.testing import absltest

_TEST_NORMALIZED_FUNCTION_CODE = 'norm_code'
_TEST_NORMALIZED_LINE_CODE = {10: 'hello world'}
_TEST_FUNCTION_HASH = 1234
_TEST_LINE_HASHES = [5678, 6789]


class SignatureTest(absltest.TestCase):

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

    signature_factory = signature.SignatureFactory()
    func_sign = signature_factory.create_from_function_chunk(
        test_function_chunk,
        test_source,
        test_truncated_path_level,
    )

    expected_siganture_hash_pattern = '[0-9a-f]{8}$'
    self.assertRegex(func_sign.signature_hash, expected_siganture_hash_pattern)
    with self.assertRaises(ValueError):
      _ = func_sign.signature_id
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

    signature_factory = signature.SignatureFactory()
    line_sign = signature_factory.create_from_line_chunk(
        test_line_chunk,
        test_source,
        test_threshold,
        test_truncated_path_level,
    )

    expected_siganture_hash_pattern = '[0-9a-f]{8}$'
    self.assertRegex(line_sign.signature_hash, expected_siganture_hash_pattern)
    with self.assertRaises(ValueError):
      _ = line_sign.signature_id
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
      'vanir.signature.SignatureFactory._generate_signature_hash',
      return_value='ASB-A-SIGNATURE-ID',
  )
  def test_line_signature_creation_fails_with_invalid_threshold(
      self, gen_sig_hash):
    test_threshold = 5000

    signature_factory = signature.SignatureFactory()
    with self.assertRaisesRegex(
        ValueError, 'Invalid line signature threshold: (-)*[0-9]*[.][0-9]*[.]'
        ' Line signature threshold must be between 0 and 1.'):
      signature_factory.create_from_line_chunk(
          mock.Mock(), mock.Mock(), test_threshold
      )
    gen_sig_hash.assert_called_once()

  def test_signature_hash_generation_adds_salt_if_hash_already_exits(self):
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

    signature_factory = signature.SignatureFactory()
    func_sign1 = signature_factory.create_from_function_chunk(
        test_function_chunk, test_source)
    func_sign2 = signature_factory.create_from_function_chunk(
        test_function_chunk, test_source)
    self.assertNotEqual(func_sign1.signature_hash, func_sign2.signature_hash)

  def test_function_signature_creation_from_osv_sign(self):
    test_signature_id = 'ASB-A-12345-TEST-SIGN-ID-12345678'
    test_signature_version = 'v1234'
    test_source = 'http://android.googlesource.com/test_source'
    test_target_file = 'foo/bar/test_lib.c'
    test_function_name = 'test_func1'
    test_deprecated = True
    test_match_only_versions = ['11', '12L']
    test_exact_target_file_match_only = True
    test_function_hash = _TEST_FUNCTION_HASH
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
        'digest': {'function_hash': test_function_hash, 'length': test_length},
    }

    signature_factory = signature.SignatureFactory()
    func_sign = signature_factory.create_from_osv_sign(test_osv_sign)

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
    self.assertEqual(func_sign.function_hash, test_function_hash)
    self.assertEqual(func_sign.length, test_length)
    self.assertEqual(func_sign.target_function, test_function_name)
    self.assertIsNone(func_sign.truncated_path_level)

    self.assertEqual(func_sign.to_osv_dict(), test_osv_sign)

  def test_line_signature_creation_from_osv_sign(self):
    test_signature_id = 'ASB-A-12345-TEST-SIGN-ID-12345678-1'
    test_signature_version = 'v1234'
    test_source = 'http://android.googlesource.com/test_source'
    test_target_file = 'foo/bar/test_lib.c'
    test_deprecated = True
    test_line_hashes = _TEST_LINE_HASHES
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

    signature_factory = signature.SignatureFactory()
    line_sign = signature_factory.create_from_osv_sign(test_osv_sign)

    self.assertEqual(line_sign.signature_id, test_signature_id)
    self.assertEqual(line_sign.signature_version, test_signature_version)
    self.assertEqual(line_sign.source, test_source)
    self.assertEqual(line_sign.target_file, test_target_file)
    self.assertEqual(line_sign.deprecated, test_deprecated)
    self.assertEqual(line_sign.exact_target_file_match_only, False)
    self.assertIsNone(line_sign.match_only_versions)
    self.assertEqual(line_sign.line_hashes, test_line_hashes)
    self.assertEqual(line_sign.threshold, test_threshold)
    self.assertEqual(line_sign.truncated_path_level, test_tp_level)

    self.assertEqual(line_sign.to_osv_dict(), test_osv_sign)

  def test_line_signature_creation_from_osv_sign_with_floats(self):
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
            'line_hashes': _TEST_LINE_HASHES,
            'threshold': 0.789,
        },
    }
    signature_factory = signature.SignatureFactory()
    line_sign = signature_factory.create_from_osv_sign(test_osv_sign)

    self.assertEqual(line_sign.signature_id, test_signature_id)
    self.assertEqual(line_sign.truncated_path_level, 1)
    self.assertEqual(line_sign.to_osv_dict(), test_osv_sign)

  def test_function_signature_creation_from_osv_sign_with_floats(self):
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
            'function_hash': _TEST_FUNCTION_HASH,
            'length': test_length,
        },
    }
    signature_factory = signature.SignatureFactory()
    line_sign = signature_factory.create_from_osv_sign(test_osv_sign)

    self.assertEqual(line_sign.signature_id, test_signature_id)
    self.assertEqual(line_sign.length, 100)
    self.assertEqual(line_sign.to_osv_dict(), test_osv_sign)

  def test_signature_creation_from_osv_sign_fails_with_unknown_sign_type(self):
    test_signature_id = 'ASB-A-12345-TEST-SIGN-ID-12345678-2'
    test_osv_sign = {
        'signature_type': 'some_unknown_type',
        'id': test_signature_id
    }

    signature_factory = signature.SignatureFactory()
    # Unknown signature type will be caught by SignatureType enum.
    with self.assertRaises(ValueError):
      signature_factory.create_from_osv_sign(test_osv_sign)

    # Even if new signature type is added to SignatureType, the type must be
    # also handled in create_from_osv_sign().
    with mock.patch('vanir.signature.SignatureType'):
      with self.assertRaisesRegex(ValueError, 'Signature type .* is unknown'):
        signature_factory.create_from_osv_sign(test_osv_sign)

  def test_signature_creation_from_osv_sign_fails_with_duplicate_sign_id(self):
    test_signature_id = 'ASB-A-12345-TEST-SIGN-ID-12345678-3'
    test_osv_sign = {
        'id': test_signature_id,
        'signature_type': 'Function',
        'signature_version': 'v1',
        'source': 'foo',
        'target': {
            'file': 'foo',
            'function': 'foo'
        },
        'deprecated': False,
        'digest': {
            'function_hash': 1234,
            'length': 5
        }
    }

    signature_factory = signature.SignatureFactory([test_signature_id])
    with self.assertRaisesRegex(
        ValueError, 'The signature ID %s is already assigned to another '
        'signature.' % test_signature_id):
      signature_factory.create_from_osv_sign(test_osv_sign)

    signature_factory = signature.SignatureFactory()
    signature_factory.add_used_signature_id(test_signature_id)
    with self.assertRaisesRegex(
        ValueError, 'The signature ID %s is already assigned to another '
        'signature.' % test_signature_id):
      signature_factory.create_from_osv_sign(test_osv_sign)

    # Should pass after removal of the duplicated signature ID.
    signature_factory.remove_used_signature_id(test_signature_id)
    signature_factory.create_from_osv_sign(test_osv_sign)

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
    test_signature = signature.SignatureFactory().create_from_osv_sign(
        test_osv_sign)

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
    test_signature = signature.SignatureFactory().create_from_osv_sign(
        test_osv_sign)

    # Test signature bundle match for line chunks.
    sign_bundle = signature.SignatureBundle([test_signature])
    matched_signs = sign_bundle.match(test_line_chunk)
    self.assertEqual(matched_signs, [test_signature])

    # Increase the threshold to 76%; now the sign should not match.
    new_test_signature_id = 'ASB-A-12345-TEST-SIGN-ID-12345678-5'
    test_osv_sign['id'] = new_test_signature_id
    test_osv_sign['digest']['threshold'] = 0.76

    test_signature = signature.SignatureFactory().create_from_osv_sign(
        test_osv_sign)
    sign_bundle = signature.SignatureBundle([test_signature])
    matched_signs = sign_bundle.match(test_line_chunk)
    self.assertEmpty(matched_signs)

  def test_signature_bundle_match_fails_with_unknown_chunk_type(self):
    test_signature = mock.Mock(
        signature_version=signature._VANIR_SIGNATURE_VERSION,
        signature_type=signature.SignatureType.LINE_SIGNATURE)

    sign_bundle = signature.SignatureBundle([test_signature])
    with self.assertRaisesRegex(TypeError,
                                'The type of given chunk .* is unknown.'):
      sign_bundle.match(chunk=mock.Mock())

  def test_signature_bundle_filters_out_uncompatible_signatures(self):
    test_signature = mock.Mock(
        signature_version='v1234',
        signature_type=signature.SignatureType.LINE_SIGNATURE,
        signature_id='ASB-A-12345-TEST-SIGN-ID-12345678')

    with self.assertLogs(level=logging.WARNING) as logs:
      sign_bundle = signature.SignatureBundle([test_signature])
    self.assertIn(
        'Signature %s is disregarded due to version mismatch: (current ver: '
        '%s, the signature ver: %s)' %
        (test_signature.signature_id, signature._VANIR_SIGNATURE_VERSION,
         test_signature.signature_version), logs.output[0])
    self.assertEmpty(sign_bundle.signatures)

  def test_signature_bundle_filters_out_unrecognized_signatures(self):
    test_signature = mock.Mock(
        signature_version=signature._VANIR_SIGNATURE_VERSION,
        signature_type='some_unknown_type',
        signature_id='ASB-A-12345-TEST-SIGN-ID-12345678')

    with self.assertLogs(level=logging.ERROR) as logs:
      sign_bundle = signature.SignatureBundle([test_signature])
    self.assertIn(
        'Signature %s is disregarded due to its unrecognized type: %s' %
        (test_signature.signature_id, test_signature.signature_type),
        logs.output[0])
    self.assertEmpty(sign_bundle.signatures)

  def test_signature_bundle_function_signature_hash_collisions(self):
    test_digest = {'function_hash': 11111, 'length': 500}
    test_signature_hash1 = 'TEST-SIGN-ID-12345678'
    test_signature1 = mock.Mock(
        signature_version=signature._VANIR_SIGNATURE_VERSION,
        signature_type='Function',
        signature_hash=test_signature_hash1,
        digest=test_digest)
    test_signature_hash2 = 'TEST-SIGN-ID-87654321'
    test_signature2 = mock.Mock(
        signature_version=signature._VANIR_SIGNATURE_VERSION,
        signature_type='Function',
        signature_hash=test_signature_hash2,
        digest=test_digest)

    sign_bundle = signature.SignatureBundle(
        [test_signature1, test_signature2])
    self.assertEqual(
        sign_bundle.function_signature_hash_collisions(),
        [[test_signature_hash1, test_signature_hash2]])
    self.assertEqual(sign_bundle.signatures, [test_signature1, test_signature2])


if __name__ == '__main__':
  absltest.main()
