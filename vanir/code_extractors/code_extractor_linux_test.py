# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

from unittest import mock
import urllib.request

from vanir import vulnerability
from vanir.code_extractors import code_extractor_linux
from vanir.code_extractors import git_commit

from absl.testing import absltest
from absl.testing import parameterized

_SHORT_HASH = '1234567'
_EXPANDED_HASH = '1234567000000000000000000000000000000000'


class CodeExtractorLinuxTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    cls = git_commit.GitCommit
    # Added mocks added to bypass strict empty-patch validation (cl/881440128)
    # triggered by dummy data, which otherwise raises an AssertionError.
    # See b/504918028 for full details.
    def mock_extract_patched_files(self):
      _ = self.url  # ensure URL normalization is done
      return {}
    self.enter_context(
        mock.patch.object(cls, '_extract_patched_files', autospec=True)
    ).side_effect = mock_extract_patched_files
    self.enter_context(
        mock.patch.object(cls, '_extract_unpatched_files', autospec=True)
    ).return_value = {}
    self.enter_context(
        mock.patch.object(cls, '_extract_patch', autospec=True)
    ).return_value = []
    self.enter_context(
        mock.patch.object(cls, '_fetch_raw_patch', autospec=True)
    ).return_value = ''
    # special mock for git operations done in GitCommit's constructor
    # return value must not be empty
    self.enter_context(
        mock.patch.object(git_commit.GitCommit, '_run_git', autospec=True)
    ).return_value = b'mock-result'

    def mock_urlopen(req, *args, **kwargs):
      del args, kwargs  # Unused.
      url = getattr(req, 'full_url', req)
      mock_response = mock.MagicMock()

      # Simulate returning a patch header from the /patch/ endpoint to test
      # short-hash expansion logic.
      if '/patch/?id=' in url:
        mock_response.__enter__.return_value.readline.return_value = (
            f'From {_EXPANDED_HASH} Mon Sep 17 00:00:00 2001\n'.encode('utf-8')
        )
        return mock_response

      # Simulate HTTP redirects for git.kernel.org shortlinks.
      # This is required because tests run in a hermetic environment.
      match = git_commit._GIT_KERNEL_SHORT_PATTERN.fullmatch(url)
      if match:
        path = match.group('path')
        rev = match.group('rev')
        if path == 'linus':
          target_path = 'torvalds/linux'
        elif path == 'stable':
          target_path = 'stable/linux'
        elif path == 'torvalds':
          target_path = 'torvalds/linux'
        else:
          target_path = path
        mock_response.__enter__.return_value.url = (
            f'https://git.kernel.org/pub/scm/linux/kernel/git/{target_path}.git/commit/?id={rev}'
        )
      else:
        mock_response.__enter__.return_value.url = url
      return mock_response
    self.enter_context(
        mock.patch.object(urllib.request, 'urlopen', autospec=True)
    ).side_effect = mock_urlopen

  def test_commit_init_with_unknown_commit_url(self):
    bad_url = 'https://unsupported.kernel.patch.source.com/blah'
    affected = vulnerability.AffectedEntry({
        'package': {'ecosystem': 'Linux', 'name': 'Kernel'},
        'ecosystem_specific': {'fixes': [bad_url]},
    })
    extractor = code_extractor_linux.LinuxCodeExtractor()
    commits, failures = extractor.extract_commits_for_affected_entry(affected)
    self.assertEmpty(commits)
    self.assertLen(failures, 1)
    self.assertEqual(failures[0].url, bad_url)
    self.assertIsInstance(failures[0].error, ValueError)

  def test_different_packages(self):
    packages = (
        {'ecosystem': 'Linux', 'name': 'Kernel'},
        {'ecosystem': 'Debian:11', 'name': 'linux'}
    )
    for package in packages:
      affected = vulnerability.AffectedEntry({
          'package': package,
          'ecosystem_specific': {'fixes': [
              'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1234567',
          ]},
      })
      extractor = code_extractor_linux.LinuxCodeExtractor()
      commits, failures = extractor.extract_commits_for_affected_entry(affected)
      self.assertEmpty(failures)
      self.assertIsInstance(commits[0], git_commit.GitCommit)

  def test_extractor_with_multiple_fixes_and_failures(self):
    affected = vulnerability.AffectedEntry({
        'package': {'ecosystem': 'Linux', 'name': 'Kernel'},
        'ecosystem_specific': {
            'fixes': [
                'https://git.kernel.org/linus/1234567',
                'https://git.kernel.org/stable/c/1234567',
                'https://git.kernel.org/torvalds/c/1234567',
                'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1234567',
                'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git@1234567',
                'https://github.com/torvalds/linux/commit/1234567',
                'https://unsupported.kernel.patch.source.com/blah',
            ]
        },
    })
    extractor = code_extractor_linux.LinuxCodeExtractor()
    commits, failures = extractor.extract_commits_for_affected_entry(affected)
    self.assertLen(failures, 1)
    self.assertEqual(
        failures[0].url,
        'https://unsupported.kernel.patch.source.com/blah'
    )
    self.assertLen(commits, 6)
    for commit in commits:
      self.assertIsInstance(commit, git_commit.GitCommit)

    # Commits 0-3 are CGit URLs and should be expanded
    for i in range(4):
      self.assertEqual(commits[i]._rev, _EXPANDED_HASH)

    # Commits 4-5 are Normalized/GitHub and should NOT be expanded
    for i in range(4, 6):
      self.assertEqual(commits[i]._rev, _SHORT_HASH)

    self.assertEqual(
        commits[0]._remote,
        'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git'
    )
    self.assertEqual(
        commits[1]._remote,
        'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git'
    )
    self.assertEqual(
        commits[2]._remote,
        'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git'
    )
    self.assertEqual(
        commits[3]._remote,
        'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git',
    )
    self.assertEqual(
        commits[4]._remote,
        'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git',
    )
    self.assertEqual(commits[5]._remote, 'https://github.com/torvalds/linux')

  def test_extract_with_empty_patch(self):
    affected = vulnerability.AffectedEntry({
        'package': {'ecosystem': 'Linux', 'name': 'Kernel'},
        'ecosystem_specific': {'fixes': []},
    })

    extractor = code_extractor_linux.LinuxCodeExtractor()
    commits, failures = extractor.extract_commits_for_affected_entry(affected)
    self.assertEmpty(commits)
    self.assertEmpty(failures)

if __name__ == '__main__':
  absltest.main()
