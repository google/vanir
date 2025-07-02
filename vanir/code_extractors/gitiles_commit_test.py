
import base64
from unittest import mock
import requests

from vanir import file_path_utils
from vanir.code_extractors import code_extractor_base
from vanir.code_extractors import gitiles_commit

from absl.testing import absltest
from absl.testing import parameterized


_TEST_COMMIT = 'abcdef0000000000000000000000000000000000'
_TEST_PARENT_COMMIT = 'fedcba1111111111111111111111111111111111'
_TEST_PROJECT = 'platform/frameworks/base'

# patch file containing modified /modified.txt text file & added /added.bin file
_TEST_PATCH_FILE_PATH = file_path_utils.get_root_file_path('testdata/test_patch_file')
_TEST_PATCH_AFFECTED_RANGES = [
    (1, 1), (17, 17), (40, 44), (114, 116), (138, 138), (155, 155),
]
_TEST_PATCHED_FILE_PATH = file_path_utils.get_root_file_path('testdata/test_patched_file')
_TEST_PATCHED_BINARY_FILE_PATH = file_path_utils.get_root_file_path('testdata/test_patched_binary_file.png')
_TEST_UNPATCHED_FILE_PATH = file_path_utils.get_root_file_path('testdata/test_unpatched_file')
_TEST_UNRELATED_FILE_PATH = file_path_utils.get_root_file_path('testdata/test_unrelated_file')
_URL_BASE = 'https://android.googlesource.com'


def _url(proj: str, rev: str, other_part: str = '') -> str:
  return f'{_URL_BASE}/{proj}/+/{rev}{other_part}?format=TEXT'


_TEST_COMMIT_URL = f'{_URL_BASE}/{_TEST_PROJECT}/+/{_TEST_COMMIT}'
_TEST_PARENT_COMMIT_URL = f'{_URL_BASE}/{_TEST_PROJECT}/+/{_TEST_PARENT_COMMIT}'
_TEST_COMMIT_MSG_URL = _url(_TEST_PROJECT, _TEST_COMMIT)
_TEST_PATCH_DOWNLOAD_URL = _url(_TEST_PROJECT, _TEST_COMMIT, '^!')


class GitilesCommitTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self._test_patch_file = open(_TEST_PATCH_FILE_PATH, mode='rb').read()
    self._test_patched_file = open(_TEST_PATCHED_FILE_PATH, mode='rb').read()
    self._test_patched_binary_file = open(
        _TEST_PATCHED_BINARY_FILE_PATH
    , mode='rb').read()
    self._test_unpatched_file = open(_TEST_UNPATCHED_FILE_PATH, mode='rb').read()
    self._test_unrelated_file = open(_TEST_UNRELATED_FILE_PATH, mode='rb').read()
    self._test_commit_message = 'parent %s' % _TEST_PARENT_COMMIT

    self._mock_get_returnval_map = {
        # Android Commit URL requests.
        _TEST_COMMIT_URL:
            f'commit html page mentioning {_TEST_COMMIT}',
        _TEST_COMMIT_MSG_URL:
            base64.b64encode(self._test_commit_message.encode('UTF-8')),
        _TEST_PATCH_DOWNLOAD_URL:
            base64.b64encode(self._test_patch_file),
        _url(_TEST_PROJECT, _TEST_COMMIT, '/modified.txt'):
            base64.b64encode(self._test_patched_file),
        _url(_TEST_PROJECT, _TEST_COMMIT, '/added.bin'):
            base64.b64encode(self._test_patched_binary_file),
        _url(_TEST_PROJECT, _TEST_PARENT_COMMIT, '/modified.txt'):
            base64.b64encode(self._test_unpatched_file),
        _url(_TEST_PROJECT, _TEST_COMMIT, '/unrelated.txt'):
            base64.b64encode(self._test_unrelated_file),
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

  def test_commit_init(self):
    commit = gitiles_commit.GitilesCommit(
        _TEST_COMMIT_URL, requests_session=self._mock_session,
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

  def test_commit_init_with_bad_urls(self):
    with self.assertRaises(code_extractor_base.IncompatibleUrlError):
      gitiles_commit.GitilesCommit(
          'https://not-android.googlesource.com/test_repo/+/12345',
          requests_session=self._mock_session,
      )

  @parameterized.named_parameters(
      ('full_commit', _TEST_COMMIT_URL),
      ('short_commit', _TEST_COMMIT_URL[:-30]),
  )
  def test_commit_init_under_network_failure(self, url):
    def mock_raise_for_status():
      raise requests.RequestException('bad network')
    side_effect = lambda _: mock.Mock(raise_for_status=mock_raise_for_status)
    self._mock_session.get.side_effect = side_effect
    with self.assertRaisesRegex(
        code_extractor_base.CommitDataFetchError,
        'Failed to fetch valid commit data from.*',
    ):
      gitiles_commit.GitilesCommit(url, requests_session=self._mock_session)

  def test_commit_init_with_malformatted_commit_message(self):
    bad_msg = 'this text is not base 64 encoded.'
    self._mock_get_returnval_map[_TEST_COMMIT_MSG_URL] = bad_msg
    with self.assertRaisesRegex(
        code_extractor_base.CommitDataFetchError,
        'Failed to fetch valid commit data from.*',
    ):
      gitiles_commit.GitilesCommit(
          _TEST_COMMIT_URL, requests_session=self._mock_session,
      )

  def test_commit_init_with_flaky_android_commit_message(self):
    def flaky_session_side_effect(url):
      # Returns malformatted data for trials in |self._bad_return_trials|.
      if (url == _TEST_COMMIT_MSG_URL and
          self._trial in self._bad_return_trials):
        self._trial += 1
        return mock.Mock(text='this text is not base 64 encoded.')
      return mock.Mock(text=self._mock_get_returnval_map[url])

    self._trial = 1
    self._bad_return_trials = [1, 2]
    self._mock_session.get.side_effect = flaky_session_side_effect
    commit = gitiles_commit.GitilesCommit(
        _TEST_COMMIT_URL, requests_session=self._mock_session
    )
    self.assertEqual(self._trial, 3)
    self.assertEqual(commit.url, _TEST_COMMIT_URL)

    # Should fail if bad data returned for three consecutive trials.
    self._trial = 1
    self._bad_return_trials = [1, 2, 3, 4, 5]
    with self.assertRaisesRegex(
        code_extractor_base.CommitDataFetchError,
        'Failed to fetch valid commit data from.*',
    ):
      gitiles_commit.GitilesCommit(
          _TEST_COMMIT_URL, requests_session=self._mock_session,
      )

  def test_commit_init_with_bad_patch(self):
    patch = base64.b64encode('a meaningless patch file'.encode('UTF-8'))
    self._mock_get_returnval_map[_TEST_PATCH_DOWNLOAD_URL] = patch

    with self.assertRaisesRegex(
        code_extractor_base.CommitDataFetchError,
        'Patch for this commit is invalid. Source:.*',
    ):
      gitiles_commit.GitilesCommit(
          _TEST_COMMIT_URL, requests_session=self._mock_session,
      )

  def test_commit_init_with_missing_parent_info(self):
    msg = 'a commit message with no parent commit info'.encode('UTF-8')
    self._mock_get_returnval_map[_TEST_COMMIT_MSG_URL] = base64.b64encode(msg)
    with self.assertRaisesRegex(
        code_extractor_base.CommitDataFetchError, 'Failed to find parent.*'
    ):
      gitiles_commit.GitilesCommit(
          _TEST_COMMIT_URL, requests_session=self._mock_session,
      )

  def test_commit_init_with_git_merge_commit(self):
    msg = (
        'tree d61db019f523ed0554241c502d3702a31a7eb945\n'
        'parent 2d73c5c3470933184df35ca4d93ec5f62f0d8fa4\n'
        'parent 245f15a48cdc4d5a90902e140392dc151e528ab8\n'
        'author Greg Kroah-Hartman <gregkh@google.com> 1631707320 +0200\n'
    ).encode('UTF-8')
    self._mock_get_returnval_map[_TEST_COMMIT_MSG_URL] = base64.b64encode(msg)
    with self.assertRaisesRegex(
        code_extractor_base.CommitDataFetchError, '.*git-merge.*'
    ):
      gitiles_commit.GitilesCommit(
          _TEST_COMMIT_URL, requests_session=self._mock_session,
      )

  def test_android_get_file_at_rev(self):
    commit = gitiles_commit.GitilesCommit(
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
