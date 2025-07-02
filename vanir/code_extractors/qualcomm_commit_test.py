import json
from unittest import mock

import requests
from vanir import file_path_utils
from vanir.code_extractors import code_extractor_base
from vanir.code_extractors import qualcomm_commit

from absl.testing import absltest
from absl.testing import parameterized


_TEST_COMMIT = 'abcdef0000000000000000000000000000000000'
_TEST_PARENT_COMMIT = 'fedcba1111111111111111111111111111111111'

# patch file containing modified /modified.txt text file & added /added.bin file
_TEST_PATCH_FILE_PATH = file_path_utils.get_root_file_path('testdata/test_patch_file')
_TEST_PATCH_AFFECTED_RANGES = [
    (1, 1), (17, 17), (40, 44), (114, 116), (138, 138), (155, 155),
]
_TEST_PATCHED_FILE_PATH = file_path_utils.get_root_file_path('testdata/test_patched_file')
_TEST_PATCHED_BINARY_FILE_PATH = file_path_utils.get_root_file_path('testdata/test_patched_binary_file.png')
_TEST_UNPATCHED_FILE_PATH = file_path_utils.get_root_file_path('testdata/test_unpatched_file')
_TEST_UNRELATED_FILE_PATH = file_path_utils.get_root_file_path('testdata/test_unrelated_file')
_QUALCOMM_LINARO_PATCH_URL_BASE = 'https://git.codelinaro.org/clo/test_repo'


def _linaro_url(*args: str) -> str:
  return '/'.join((_QUALCOMM_LINARO_PATCH_URL_BASE,) + args)


_TEST_COMMIT_URL = _linaro_url('commit', _TEST_COMMIT)
_TEST_QUALCOMM_COMMIT_API_URL = ''.join([
    r'https://git.codelinaro.org/api/v4/projects/clo%2Ftest_repo/repository/commits/',
    _TEST_COMMIT
])
_TEST_QUALCOMM_AURORA_COMMIT_URL = ''.join(
    ['https://source.codeaurora.org/quic/test_repo/commit/?id=', _TEST_COMMIT])


class QualcommCommitTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self._test_patch_file = open(_TEST_PATCH_FILE_PATH, mode='rb').read()
    self._test_patched_file = open(_TEST_PATCHED_FILE_PATH, mode='rb').read()
    self._test_patched_binary_file = open(
        _TEST_PATCHED_BINARY_FILE_PATH
    , mode='rb').read()
    self._test_unpatched_file = open(_TEST_UNPATCHED_FILE_PATH, mode='rb').read()
    self._test_unrelated_file = open(_TEST_UNRELATED_FILE_PATH, mode='rb').read()

    self._mock_get_returnval_map = {
        _TEST_QUALCOMM_COMMIT_API_URL:
            json.dumps(
                {'id': _TEST_COMMIT, 'parent_ids': [_TEST_PARENT_COMMIT]}
            ),
        _linaro_url('commit', _TEST_COMMIT + '.diff'):
            self._test_patch_file.decode('UTF-8'),
        _linaro_url('raw', _TEST_COMMIT, 'modified.txt'):
            self._test_patched_file.decode('UTF-8'),
        _linaro_url('raw', _TEST_COMMIT, 'added.bin'):
            self._test_patched_binary_file,
        _linaro_url('raw', _TEST_PARENT_COMMIT, 'modified.txt'):
            self._test_unpatched_file.decode('UTF-8'),
        _linaro_url('raw', _TEST_COMMIT, 'unrelated.txt'):
            self._test_unrelated_file.decode('UTF-8'),
    }
    mock_session_class = self.enter_context(
        mock.patch.object(requests.sessions, 'Session', autospec=True))
    self._mock_session = mock_session_class()
    def mock_get_side_effect(url: str):
      if url in self._mock_get_returnval_map:
        return mock.Mock(text=self._mock_get_returnval_map[url])
      else:
        msg = f'Not found: {url}'
        response = absltest.mock.MagicMock(text=msg, ok=False, status=404)
        response.raise_for_status.side_effect = requests.RequestException(msg)
        return response
    self._mock_session.get.side_effect = mock_get_side_effect

  @parameterized.named_parameters(
      ('CodeLinaro', _TEST_COMMIT_URL),
      ('CodeAurora_converted_to_CodeLinaro', _TEST_QUALCOMM_AURORA_COMMIT_URL),
  )
  def test_commit_init(self, commit_url):
    commit = qualcomm_commit.QualcommCommit(
        commit_url, requests_session=self._mock_session,
    )
    self.assertEqual(commit.url, _TEST_COMMIT_URL)
    self.assertEqual(
        commit.get_affected_line_ranges('modified.txt'),
        _TEST_PATCH_AFFECTED_RANGES,
    )

    self.assertEqual(commit.patched_files.keys(), {'modified.txt', 'added.bin'})
    patched_text_file_path = commit.patched_files['modified.txt']
    with open(patched_text_file_path, 'r') as f:
      self.assertEqual(f.read(), self._test_patched_file.decode('UTF-8'))
    patched_binary_file_path = commit.patched_files['added.bin']
    with open(patched_binary_file_path, 'rb') as f:
      self.assertEqual(f.read(), self._test_patched_binary_file)

    self.assertEqual(commit.unpatched_files.keys(), {'modified.txt'})
    unpatched_text_file_path = commit.unpatched_files['modified.txt']
    with open(unpatched_text_file_path, 'r') as f:
      self.assertEqual(f.read(), self._test_unpatched_file.decode('UTF-8'))

  @parameterized.named_parameters(
      (
          'CodeLinaro',
          'https://git.codelinaro.org/clo/test_repo/commit/bad_commit',
      ),
      (
          'CodeAurora',
          'https://source.codeaurora.org/quic/test_repo/commit/bad_commit',
      ),
      (
          'Not_Qualcomm',
          'https://android.googlesource.com/test_repo/+/12345',
      )
  )
  def test_commit_init_with_bad_urls(self, url):
    with self.assertRaises(
        (
            code_extractor_base.CommitDataFetchError,
            code_extractor_base.IncompatibleUrlError,
        )
    ):
      qualcomm_commit.QualcommCommit(url, requests_session=self._mock_session)

  @parameterized.named_parameters(
      ('CodeLinaro', _TEST_COMMIT_URL),
      ('CodeAurora_converted_to_CodeLinaro', _TEST_QUALCOMM_AURORA_COMMIT_URL),
  )
  def test_commit_init_under_network_failure(self, commit_url):
    def mock_raise_for_status():
      raise requests.RequestException('bad network')
    side_effect = lambda _: mock.Mock(raise_for_status=mock_raise_for_status)
    self._mock_session.get.side_effect = side_effect
    with self.assertRaisesRegex(
        code_extractor_base.CommitDataFetchError,
        'Failed to fetch valid commit data from.*',
    ):
      qualcomm_commit.QualcommCommit(
          commit_url, requests_session=self._mock_session,
      )

  def test_commit_init_with_bad_commit_info(self):
    bad_test_commit_info_text = json.dumps({'message': 'nothing found'})
    self._mock_get_returnval_map[_TEST_QUALCOMM_COMMIT_API_URL] = (
        bad_test_commit_info_text
    )
    with self.assertRaisesRegex(
        code_extractor_base.CommitDataFetchError,
        'Failed to get valid commit info for URL:.*',
    ):
      qualcomm_commit.QualcommCommit(
          _TEST_COMMIT_URL, requests_session=self._mock_session,
      )

  def test_commit_init_with_bad_patch(self):
    patch_url = _linaro_url('commit', _TEST_COMMIT + '.diff')
    self._mock_get_returnval_map[patch_url] = 'a meaningless patch file'
    with self.assertRaisesRegex(
        code_extractor_base.CommitDataFetchError,
        'Patch for this commit is invalid. Source:.*',
    ):
      qualcomm_commit.QualcommCommit(
          _TEST_COMMIT_URL, requests_session=self._mock_session,
      )

  def test_commit_init_missing_parent_info(self):
    self._mock_get_returnval_map[_TEST_QUALCOMM_COMMIT_API_URL] = (
        json.dumps({'id': _TEST_COMMIT, 'parent_ids': []})
    )
    with self.assertRaisesRegex(
        code_extractor_base.CommitDataFetchError, 'Failed to find parent.*',
    ):
      qualcomm_commit.QualcommCommit(
          _TEST_COMMIT_URL, requests_session=self._mock_session
      )

  def test_commit_init_with_git_merge_commit(self):
    self._mock_get_returnval_map[_TEST_QUALCOMM_COMMIT_API_URL] = (
        json.dumps({
            'id': _TEST_COMMIT,
            'parent_ids': [
                '2d73c5c3470933184df35ca4d93ec5f62f0d8fa4',
                '245f15a48cdc4d5a90902e140392dc151e528ab8',
            ]
        })
    )
    with self.assertRaisesRegex(
        code_extractor_base.CommitDataFetchError, '.*git-merge.*'
    ):
      qualcomm_commit.QualcommCommit(
          _TEST_COMMIT_URL, requests_session=self._mock_session
      )

  def test_android_get_file_at_rev(self):
    commit = qualcomm_commit.QualcommCommit(
        _TEST_COMMIT_URL, requests_session=self._mock_session,
    )
    file_tmp_path = commit.get_file_at_rev('unrelated.txt')
    self.assertIsNotNone(file_tmp_path)
    with open(file_tmp_path, 'r') as f:
      self.assertEqual(f.read(), self._test_unrelated_file.decode('UTF-8'))
    del commit
    with self.assertRaises(FileNotFoundError):
      open(file_tmp_path, 'r')


if __name__ == '__main__':
  absltest.main()
