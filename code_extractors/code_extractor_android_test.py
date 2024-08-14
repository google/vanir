# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

import base64
import json
import subprocess
from unittest import mock

import requests
from vanir import vulnerability
from vanir.code_extractors import code_extractor_android
from vanir.code_extractors import code_extractor_base

from absl.testing import absltest
from absl.testing import parameterized


_TEST_COMMIT = 'abcdef0000000000000000000000000000000000'
_TEST_PARENT_COMMIT = 'fedcba1111111111111111111111111111111111'

_TEST_PATCH_FILE_PATH = (
    'testdata/test_patch_file'
)
_TEST_PATCHED_FILE_PATH = (
    'testdata/test_patched_file'
)
_TEST_UNPATCHED_FILE_PATH = (
    'testdata/test_unpatched_file'
)
_TEST_UNRELATED_FILE_PATH = (
    'testdata/test_unrelated_file'
)

_TEST_FILE_RELATIVE_PATH = 'ipsum'
_TEST_UNRELATED_FILE_RELATIVE_PATH = 'lorem'

# Android Commit Test URLs
_ANDROID_PATCH_URL_BASE = 'https://android.googlesource.com/kernel/common/+/'
_ANDROID_TEST_USERSPACE_PROJECT = 'platform/frameworks/base'
_ANDROID14_SECURITY_BRANCH = 'android14-security-release'

_TEST_ANDROID_COMMIT_URL = _ANDROID_PATCH_URL_BASE + _TEST_COMMIT
_TEST_ANDROID_PARENT_COMMIT_URL = _ANDROID_PATCH_URL_BASE + _TEST_PARENT_COMMIT

_TEST_ANDROID_COMMIT_MESSAGE_URL = ''.join([
    _TEST_ANDROID_COMMIT_URL,
    code_extractor_android.AndroidCommit.android_repo_text_postfix
])
_TEST_ANDROID_PATCH_DOWNLOAD_URL = ''.join([
    _TEST_ANDROID_COMMIT_URL,
    code_extractor_android.AndroidCommit.android_repo_commit_patch_postfix,
    code_extractor_android.AndroidCommit.android_repo_text_postfix
])
_TEST_ANDROID_PATCHED_FILE_DOWNLOAD_URL = ''.join([
    _TEST_ANDROID_COMMIT_URL, '/', _TEST_FILE_RELATIVE_PATH,
    code_extractor_android.AndroidCommit.android_repo_text_postfix
])
_TEST_ANDROID_UNPATCHED_FILE_DOWNLOAD_URL = ''.join([
    _TEST_ANDROID_PARENT_COMMIT_URL, '/', _TEST_FILE_RELATIVE_PATH,
    code_extractor_android.AndroidCommit.android_repo_text_postfix
])
_TEST_ANDROID_UNRELATED_FILE_DOWNLOAD_URL = ''.join([
    _TEST_ANDROID_COMMIT_URL, '/', _TEST_UNRELATED_FILE_RELATIVE_PATH,
    code_extractor_android.AndroidCommit.android_repo_text_postfix
])
_TEST_ANDROID_COMMIT_INIT_URLS = [
    _TEST_ANDROID_COMMIT_MESSAGE_URL, _TEST_ANDROID_PATCH_DOWNLOAD_URL,
    _TEST_ANDROID_PATCHED_FILE_DOWNLOAD_URL,
    _TEST_ANDROID_UNPATCHED_FILE_DOWNLOAD_URL
]
_TEST_ANDROID_FILE_AT_TIP_OF_14_BRANCH = (
    f'https://android.googlesource.com/{_ANDROID_TEST_USERSPACE_PROJECT}/+/'
    f'{_ANDROID14_SECURITY_BRANCH}/{_TEST_FILE_RELATIVE_PATH}'
    f'{code_extractor_android.AndroidCommit.android_repo_text_postfix}'
)

# Qualcomm Commit Test URLs
_QUALCOMM_LINARO_PATCH_URL_BASE = 'https://git.codelinaro.org/clo/test_repo/'
_TEST_QUALCOMM_COMMIT_URL = ''.join(
    [_QUALCOMM_LINARO_PATCH_URL_BASE, 'commit/', _TEST_COMMIT])
_TEST_QUALCOMM_COMMIT_API_URL = ''.join([
    r'https://git.codelinaro.org/api/v4/projects/clo%2Ftest_repo/repository/commits/',
    _TEST_COMMIT
])
_TEST_QUALCOMM_PATCH_DOWNLOAD_URL = ''.join(
    [_TEST_QUALCOMM_COMMIT_URL, '.diff'])
_TEST_QUALCOMM_PATCHED_FILE_DOWNLOAD_URL = ''.join([
    _QUALCOMM_LINARO_PATCH_URL_BASE, 'raw/', _TEST_COMMIT, '/',
    _TEST_FILE_RELATIVE_PATH
])
_TEST_QUALCOMM_UNPATCHED_FILE_DOWNLOAD_URL = ''.join([
    _QUALCOMM_LINARO_PATCH_URL_BASE, 'raw/', _TEST_PARENT_COMMIT, '/',
    _TEST_FILE_RELATIVE_PATH
])
_TEST_QUALCOMM_UNRELATED_FILE_DOWNLOAD_URL = ''.join([
    _QUALCOMM_LINARO_PATCH_URL_BASE, 'raw/', _TEST_COMMIT, '/',
    _TEST_UNRELATED_FILE_RELATIVE_PATH,
])
_TEST_QUALCOMM_COMMIT_INIT_URLS = [
    _TEST_QUALCOMM_COMMIT_API_URL, _TEST_QUALCOMM_PATCH_DOWNLOAD_URL,
    _TEST_QUALCOMM_PATCHED_FILE_DOWNLOAD_URL,
    _TEST_QUALCOMM_UNPATCHED_FILE_DOWNLOAD_URL
]

_TEST_QUALCOMM_AURORA_COMMIT_URL = ''.join(
    ['https://source.codeaurora.org/quic/test_repo/commit/?id=', _TEST_COMMIT])


class CodeExtractorAndroidTest(parameterized.TestCase):
  def setUp(self):
    super().setUp()
    self._test_patch_file = open(_TEST_PATCH_FILE_PATH, mode='rb').read()
    self._test_patched_file = open(_TEST_PATCHED_FILE_PATH, mode='rb').read()
    self._test_unpatched_file = open(_TEST_UNPATCHED_FILE_PATH, mode='rb').read()
    self._test_unrelated_file = open(_TEST_UNRELATED_FILE_PATH, mode='rb').read()
    self._test_commit_message = 'parent %s' % _TEST_PARENT_COMMIT

    self._mock_get_returnval_map = {
        # Android Commit URL requests.
        _TEST_ANDROID_COMMIT_URL:
            mock.Mock(text='commit html page mentioning %s' % _TEST_COMMIT),
        _TEST_ANDROID_COMMIT_MESSAGE_URL:
            mock.Mock(
                text=base64.b64encode(
                    self._test_commit_message.encode('UTF-8'))),
        _TEST_ANDROID_PATCH_DOWNLOAD_URL:
            mock.Mock(text=base64.b64encode(self._test_patch_file)),
        _TEST_ANDROID_PATCHED_FILE_DOWNLOAD_URL:
            mock.Mock(text=base64.b64encode(self._test_patched_file)),
        _TEST_ANDROID_UNPATCHED_FILE_DOWNLOAD_URL:
            mock.Mock(text=base64.b64encode(self._test_unpatched_file)),
        _TEST_ANDROID_UNRELATED_FILE_DOWNLOAD_URL:
            mock.Mock(text=base64.b64encode(self._test_unrelated_file)),
        _TEST_ANDROID_FILE_AT_TIP_OF_14_BRANCH:
            mock.Mock(text=base64.b64encode(self._test_patched_file)),
        # Qualcomm Commit URL requests.
        _TEST_QUALCOMM_COMMIT_API_URL:
            mock.Mock(
                text=json.dumps({
                    'id': _TEST_COMMIT,
                    'parent_ids': [_TEST_PARENT_COMMIT]
                })),
        _TEST_QUALCOMM_PATCH_DOWNLOAD_URL:
            mock.Mock(text=self._test_patch_file.decode('UTF-8')),
        _TEST_QUALCOMM_PATCHED_FILE_DOWNLOAD_URL:
            mock.Mock(text=self._test_patch_file.decode('UTF-8')),
        _TEST_QUALCOMM_UNPATCHED_FILE_DOWNLOAD_URL:
            mock.Mock(text=self._test_patch_file.decode('UTF-8')),
        _TEST_QUALCOMM_UNRELATED_FILE_DOWNLOAD_URL:
            mock.Mock(text=self._test_unrelated_file.decode('UTF-8')),
    }

    mock_session_class = self.enter_context(
        mock.patch.object(requests.sessions, 'Session', autospec=True))
    self._mock_session = mock_session_class()
    def mock_get_side_effect(url: str):
      if url in self._mock_get_returnval_map:
        return self._mock_get_returnval_map[url]
      else:
        msg = f'Not found: {url}'
        response = absltest.mock.MagicMock(text=msg, ok=False, status=404)
        response.raise_for_status.side_effect = requests.RequestException(msg)
        return response
    self._mock_session.get.side_effect = mock_get_side_effect

  @parameterized.named_parameters(
      ('Android', _TEST_ANDROID_COMMIT_URL, _TEST_ANDROID_COMMIT_INIT_URLS),
      ('Qualcomm', _TEST_QUALCOMM_COMMIT_URL, _TEST_QUALCOMM_COMMIT_INIT_URLS),
      ('Qualcomm_Aurora', _TEST_QUALCOMM_AURORA_COMMIT_URL,
       _TEST_QUALCOMM_COMMIT_INIT_URLS),
  )
  def test_commit_init(self, commit_url, retrieved_urls):
    code_extractor_android._generate_commit(commit_url, self._mock_session)
    self._mock_session.get.assert_has_calls(
        calls=[mock.call(url) for url in retrieved_urls],
        any_order=True,
    )

  def test_commit_init_with_unknown_commit_url(self):
    test_url = 'https://unsupported.kernel.patch.source.com/blah'
    with self.assertRaisesRegex(ValueError, 'Unknown commit URL:.*'):
      code_extractor_android._generate_commit(test_url, self._mock_session)
    self._mock_session.get.assert_not_called()

  @parameterized.named_parameters(
      ('android', _TEST_ANDROID_COMMIT_URL,
       [_TEST_ANDROID_COMMIT_URL] + _TEST_ANDROID_COMMIT_INIT_URLS),
      ('qualcomm', _TEST_QUALCOMM_COMMIT_URL, _TEST_QUALCOMM_COMMIT_INIT_URLS),
      ('qualcomm_aurora', _TEST_QUALCOMM_AURORA_COMMIT_URL,
       _TEST_QUALCOMM_COMMIT_INIT_URLS),
  )
  def test_commit_init_with_partial_commit_url(self, commit_url,
                                               retrieved_urls):
    partial_commit = _TEST_COMMIT[:-30]
    to_partial_commit = lambda url: url.replace(_TEST_COMMIT, partial_commit)
    partial_commit_url = to_partial_commit(commit_url)
    self._mock_get_returnval_map.update({
        to_partial_commit(k): v
        for k, v in self._mock_get_returnval_map.items()
    })
    code_extractor_android._generate_commit(
        partial_commit_url, self._mock_session)
    self._mock_session.get.assert_has_calls(
        calls=[mock.call(to_partial_commit(url)) for url in retrieved_urls],
        any_order=True,
    )

  def test_commit_init_with_bad_android_commit_page(self):
    bad_test_commit_page_text = 'commit html page containing no commit hash'
    # When partial commit URL is given, its full commit is extracted from the
    # commit page, so bad commit page would cause exception.
    partial_commit_url = _TEST_ANDROID_COMMIT_URL[:-30]
    self._mock_get_returnval_map[partial_commit_url] = mock.Mock(
        text=bad_test_commit_page_text)
    with self.assertRaisesRegex(
        code_extractor_base.CommitDataFetchError,
        'Failed to extract full commit hash from URL:.*'):
      code_extractor_android._generate_commit(
          partial_commit_url, self._mock_session)

    # When full commit URL is given, bad commit page does not cause exception.
    self._mock_get_returnval_map[_TEST_ANDROID_COMMIT_URL] = mock.Mock(
        text=bad_test_commit_page_text)
    code_extractor_android._generate_commit(
        _TEST_ANDROID_COMMIT_URL, self._mock_session)

  def test_commit_init_with_bad_qualcomm_commit_info(self):
    bad_test_commit_info_text = json.dumps({'message': 'nothing found'})
    self._mock_get_returnval_map[_TEST_QUALCOMM_COMMIT_API_URL] = mock.Mock(
        text=bad_test_commit_info_text)
    with self.assertRaisesRegex(code_extractor_base.CommitDataFetchError,
                                'Failed to get valid commit info for URL:.*'):
      code_extractor_android._generate_commit(
          _TEST_QUALCOMM_COMMIT_URL, self._mock_session)

  @parameterized.named_parameters(
      ('linaro', ('https://git.codelinaro.org/clo/test_repo/commit/'
                  'invalid_commit_number')),
      ('aurora', ('https://source.codeaurora.org/quic/test_repo/commit/'
                  'invalid_commit_number')))
  def test_commit_init_with_bad_qualcomm_urls(self, bad_url):
    with self.assertRaisesRegex(ValueError, 'Invalid .* commit URL.*'):
      code_extractor_android._generate_commit(bad_url, self._mock_session)

  def test_commit_init_with_partial_commit_url_under_network_failure(self):
    partial_commit_url = _TEST_ANDROID_COMMIT_URL[:-30]
    self._mock_get_returnval_map[partial_commit_url] = mock.Mock(ok=False)
    with self.assertRaisesRegex(code_extractor_base.CommitDataFetchError,
                                'Failed to fetch web page from URL:.*'):
      code_extractor_android._generate_commit(
          partial_commit_url, self._mock_session)

  @parameterized.named_parameters(
      ('android', _TEST_ANDROID_COMMIT_URL),
      ('qualcomm', _TEST_QUALCOMM_COMMIT_URL),
      ('qualcomm_aurora', _TEST_QUALCOMM_AURORA_COMMIT_URL),
  )
  def test_commit_init_under_network_failure(self, commit_url):

    def mock_raise_for_status():
      raise requests.RequestException('bad network')

    side_effect = lambda _: mock.Mock(raise_for_status=mock_raise_for_status)
    self._mock_session.get.side_effect = side_effect
    with self.assertRaisesRegex(code_extractor_base.CommitDataFetchError,
                                'Failed to fetch valid commit data from.*'):
      code_extractor_android._generate_commit(commit_url, self._mock_session)

  def test_commit_init_with_malformatted_android_commit_message(self):
    self._mock_get_returnval_map[_TEST_ANDROID_COMMIT_MESSAGE_URL] = mock.Mock(
        text='this text is not base 64 encoded.')
    with self.assertRaisesRegex(code_extractor_base.CommitDataFetchError,
                                'Failed to fetch valid commit data from.*'):
      code_extractor_android._generate_commit(
          _TEST_ANDROID_COMMIT_URL, self._mock_session)

  def test_commit_init_with_flaky_android_commit_message(self):

    def flaky_session_side_effect(url):
      # Returns malformatted data for trials in |self._bad_return_trials|.
      if (url == _TEST_ANDROID_COMMIT_MESSAGE_URL and
          self._trial in self._bad_return_trials):
        self._trial += 1
        return mock.Mock(text='this text is not base 64 encoded.')
      return self._mock_get_returnval_map[url]

    self._trial = 1
    self._bad_return_trials = [1, 2]
    self._mock_session.get.side_effect = flaky_session_side_effect
    code_extractor_android._generate_commit(
        _TEST_ANDROID_COMMIT_URL, self._mock_session)
    self.assertEqual(self._trial, 3)

    # Should fail if bad data returned for three consecutive trials.
    code_extractor_android._generate_commit.cache_clear()
    self._trial = 1
    self._bad_return_trials = [1, 2, 3, 4, 5]
    with self.assertRaisesRegex(code_extractor_base.CommitDataFetchError,
                                'Failed to fetch valid commit data from.*'):
      code_extractor_android._generate_commit(
          _TEST_ANDROID_COMMIT_URL, self._mock_session)

  @parameterized.named_parameters(
      ('android', _TEST_ANDROID_COMMIT_URL),
      ('qualcomm', _TEST_QUALCOMM_COMMIT_URL),
      ('qualcomm_aurora', _TEST_QUALCOMM_AURORA_COMMIT_URL),
  )
  def test_commit_init_with_bad_patch(self, commit_url):
    self._mock_get_returnval_map[_TEST_ANDROID_PATCH_DOWNLOAD_URL] = mock.Mock(
        text=base64.b64encode('a meaningless patch file'.encode('UTF-8')))
    self._mock_get_returnval_map[_TEST_QUALCOMM_PATCH_DOWNLOAD_URL] = mock.Mock(
        text='a meaningless patch file')
    with self.assertRaisesRegex(code_extractor_base.CommitDataFetchError,
                                'Patch for this commit is invalid. Source:.*'):
      code_extractor_android._generate_commit(commit_url, self._mock_session)

  @parameterized.named_parameters(
      ('android', _TEST_ANDROID_COMMIT_URL),
      ('qualcomm', _TEST_QUALCOMM_COMMIT_URL),
      ('qualcomm_aurora', _TEST_QUALCOMM_AURORA_COMMIT_URL),
  )
  def test_commit_init_with_android_commit_message_missing_parent_info(
      self, commit_url):
    bad_commit_message = 'a commit message with no parent commit info'
    self._mock_get_returnval_map[_TEST_ANDROID_COMMIT_MESSAGE_URL] = mock.Mock(
        text=base64.b64encode(bad_commit_message.encode('UTF-8')))
    self._mock_get_returnval_map[_TEST_QUALCOMM_COMMIT_API_URL] = mock.Mock(
        text=json.dumps({
            'id': _TEST_COMMIT,
            'parent_ids': []
        }))
    with self.assertRaisesRegex(code_extractor_base.CommitDataFetchError,
                                'Failed to find parent.*'):
      code_extractor_android._generate_commit(commit_url, self._mock_session)

  @parameterized.named_parameters(
      ('android', _TEST_ANDROID_COMMIT_URL),
      ('qualcomm', _TEST_QUALCOMM_COMMIT_URL),
      ('qualcomm_aurora', _TEST_QUALCOMM_AURORA_COMMIT_URL),
  )
  def test_commit_init_with_git_merge_commit(self, commit_url):
    merge_commit_message = (
        'tree d61db019f523ed0554241c502d3702a31a7eb945\n'
        'parent 2d73c5c3470933184df35ca4d93ec5f62f0d8fa4\n'
        'parent 245f15a48cdc4d5a90902e140392dc151e528ab8\n'
        'author Greg Kroah-Hartman <gregkh@google.com> 1631707320 +0200\n')
    self._mock_get_returnval_map[_TEST_ANDROID_COMMIT_MESSAGE_URL] = mock.Mock(
        text=base64.b64encode(merge_commit_message.encode('UTF-8')))
    self._mock_get_returnval_map[_TEST_QUALCOMM_COMMIT_API_URL] = mock.Mock(
        text=json.dumps({
            'id': _TEST_COMMIT,
            'parent_ids': [
                '2d73c5c3470933184df35ca4d93ec5f62f0d8fa4',
                '245f15a48cdc4d5a90902e140392dc151e528ab8',
            ]
        }))
    with self.assertRaisesRegex(
        code_extractor_base.CommitDataFetchError, '.*git-merge.*'):
      code_extractor_android._generate_commit(commit_url, self._mock_session)

  def test_get_url(self):
    commit = code_extractor_android._generate_commit(
        _TEST_ANDROID_COMMIT_URL, self._mock_session)
    url = commit.get_url()
    self.assertEqual(url, _TEST_ANDROID_COMMIT_URL)

  def test_get_commit_hash(self):
    commit = code_extractor_android._generate_commit(
        _TEST_ANDROID_COMMIT_URL, self._mock_session)
    full_commit_hash = commit.get_commit_hash()
    self.assertEqual(full_commit_hash, _TEST_COMMIT)
    test_length = 10
    partial_commit_hash = commit.get_commit_hash(test_length)
    self.assertEqual(partial_commit_hash, _TEST_COMMIT[:test_length])
    test_length = -10
    partial_commit_hash = commit.get_commit_hash(test_length)
    self.assertEqual(partial_commit_hash, _TEST_COMMIT)

  def test_get_patch(self):
    commit = code_extractor_android._generate_commit(
        _TEST_ANDROID_COMMIT_URL, self._mock_session)
    patch = commit.get_patch()
    expected_lines = [
        'diff --git a/ipsum b/ipsum',
        'index dcf24e1..8b16546 100644',
        '+an added line and there is no context line before',
        '-40  Fusce efficitur fermentum mi,',
    ]
    self.assertContainsSubset(expected_lines, str(patch).split('\n'))

  def test_get_affected_line_ranges(self):
    commit = code_extractor_android._generate_commit(
        _TEST_ANDROID_COMMIT_URL, self._mock_session)
    affected_ranges = commit.get_affected_line_ranges(_TEST_FILE_RELATIVE_PATH)
    # The following ranges map to the hunks in test_patch_file.
    expected_affected_ranges = [
        (1, 1),
        (17, 17),
        (40, 44),
        (114, 116),
        (138, 138),
        (155, 155),
    ]
    self.assertListEqual(expected_affected_ranges, affected_ranges)

  def test_get_patched_files(self):
    commit = code_extractor_android._generate_commit(
        _TEST_ANDROID_COMMIT_URL, self._mock_session)
    patched_files = commit.get_patched_files()
    patched_file_tmp_path = patched_files.get(_TEST_FILE_RELATIVE_PATH)
    self.assertIsNotNone(patched_file_tmp_path)
    with open(patched_file_tmp_path, 'r') as downloaded_file:
      self.assertEqual(downloaded_file.read(),
                       self._test_patched_file.decode('UTF-8'))
    del commit
    code_extractor_android._generate_commit.cache_clear()
    with self.assertRaises(FileNotFoundError):
      open(patched_file_tmp_path, 'r')

  def test_get_unpatched_files(self):
    commit = code_extractor_android._generate_commit(
        _TEST_ANDROID_COMMIT_URL, self._mock_session)
    unpatched_files = commit.get_unpatched_files()
    unpatched_file_tmp_path = unpatched_files.get(_TEST_FILE_RELATIVE_PATH)
    self.assertIsNotNone(unpatched_file_tmp_path)
    with open(unpatched_file_tmp_path, 'r') as downloaded_file:
      self.assertEqual(downloaded_file.read(),
                       self._test_unpatched_file.decode('UTF-8'))
    del commit
    code_extractor_android._generate_commit.cache_clear()
    with self.assertRaises(FileNotFoundError):
      open(unpatched_file_tmp_path, 'r')

  def test_extract(self):
    affected = vulnerability.AffectedEntry({
        'package': {'ecosystem': 'Android', 'name': 'pkg'},
        'ecosystem_specific': {'fixes': [_TEST_ANDROID_COMMIT_URL]},
    })

    commits, failures = code_extractor_android.AndroidCodeExtractor(
        self._mock_session).extract_commits_for_affected_entry(affected)
    self.assertEmpty(failures)
    self.assertLen(commits, 1, 'Unexpected number of patches returned')

  def test_extract_with_commit_init_failure(self):
    test_url = 'https://unsupported.patch.url.com/mypatch'
    affected = vulnerability.AffectedEntry({
        'package': {'ecosystem': 'Android', 'name': 'pkg'},
        'ecosystem_specific': {'fixes': [test_url]},
    })

    _, failed_urls = code_extractor_android.AndroidCodeExtractor(
        self._mock_session).extract_commits_for_affected_entry(affected)
    self.assertLen(failed_urls, 1)
    self.assertEqual(failed_urls[0].url, test_url)

  def test_extract_with_empty_patch(self):
    affected = vulnerability.AffectedEntry({
        'package': {'ecosystem': 'Android', 'name': 'pkg'},
        'ecosystem_specific': {'fixes': []},
    })

    commits, failed_urls = code_extractor_android.AndroidCodeExtractor(
        self._mock_session).extract_commits_for_affected_entry(affected)
    self.assertEmpty(commits)
    self.assertEmpty(failed_urls)

  def test_extract_files_at_tip_of_unaffected_versions(self):
    extractor = code_extractor_android.AndroidCodeExtractor(self._mock_session)
    commits, failed_urls = (
        extractor.extract_files_at_tip_of_unaffected_versions(
            _ANDROID_TEST_USERSPACE_PROJECT,
            ['10', '11', '12', '12L', '13', '14-next'],  # all but 14
            [_TEST_FILE_RELATIVE_PATH],
        )
    )
    self._mock_session.get.assert_called_once_with(
        _TEST_ANDROID_FILE_AT_TIP_OF_14_BRANCH,
    )
    self.assertLen(commits, 1)
    self.assertEqual(
        commits[0].get_patched_files().keys(), {_TEST_FILE_RELATIVE_PATH},
    )
    self.assertEmpty(failed_urls)

  def test_extract_files_at_tip_of_unaffected_versions_ignore_kernel(self):
    extractor = code_extractor_android.AndroidCodeExtractor(self._mock_session)
    commits, failed_urls = (
        extractor.extract_files_at_tip_of_unaffected_versions(
            _ANDROID_TEST_USERSPACE_PROJECT,
            ['Kernel', 'something_else'],
            [_TEST_FILE_RELATIVE_PATH],
        )
    )
    self.assertEmpty(commits)
    self.assertEmpty(failed_urls)

  def test_extract_files_at_tip_of_unaffected_versions_ignore_soc_vuln(self):
    extractor = code_extractor_android.AndroidCodeExtractor(self._mock_session)
    commits, failed_urls = (
        extractor.extract_files_at_tip_of_unaffected_versions(
            _ANDROID_TEST_USERSPACE_PROJECT,
            ['something_else', 'SoCVersion'],
            [_TEST_FILE_RELATIVE_PATH],
        )
    )
    self.assertEmpty(commits)
    self.assertEmpty(failed_urls)

  def test_extract_files_at_tip_of_unaffected_versions_ignore_metapackage(self):
    extractor = code_extractor_android.AndroidCodeExtractor(self._mock_session)
    commits, failed_urls = (
        extractor.extract_files_at_tip_of_unaffected_versions(
            ':modem:', ['11'], [_TEST_FILE_RELATIVE_PATH],
        )
    )
    self.assertEmpty(commits)
    self.assertEmpty(failed_urls)

  @parameterized.named_parameters(
      ('android', _TEST_ANDROID_COMMIT_URL),
      ('qualcomm', _TEST_QUALCOMM_COMMIT_URL),
      ('qualcomm_aurora', _TEST_QUALCOMM_AURORA_COMMIT_URL),
  )
  def test_android_get_file_at_rev(self, commit_url):
    commit = code_extractor_android._generate_commit(
        commit_url, self._mock_session
    )
    file_tmp_path = commit.get_file_at_rev(_TEST_UNRELATED_FILE_RELATIVE_PATH)
    self.assertIsNotNone(file_tmp_path)
    with open(file_tmp_path, 'r') as downloaded_file:
      self.assertEqual(
          downloaded_file.read(),
          self._test_unrelated_file.decode('UTF-8')
      )
    del commit
    code_extractor_android._generate_commit.cache_clear()
    with self.assertRaises(FileNotFoundError):
      open(file_tmp_path, 'r')


if __name__ == '__main__':
  absltest.main()
