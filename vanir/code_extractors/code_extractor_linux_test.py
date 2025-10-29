# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

from unittest import mock

from vanir import vulnerability
from vanir.code_extractors import code_extractor_linux
from vanir.code_extractors import code_extractor_base
from vanir.code_extractors import git_commit

from absl.testing import absltest
from absl.testing import parameterized

class CodeExtractorLinuxTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    # special mock for git operations done in GitCommit's constructor
    # return value must not be empty
    self.enter_context(
        mock.patch.object(git_commit.GitCommit, '_run_git', autospec=True)
    ).return_value = b"mock-result"

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
      self.assertLen(failures, 0)

  def test_extractor_with_multiple_fixes_and_failures(self):
    affected = vulnerability.AffectedEntry({
        'package': {'ecosystem': 'Linux', 'name': 'Kernel'},
        'ecosystem_specific': {'fixes': [
            'https://git.kernel.org/linus/1234567',
            'https://git.kernel.org/stable/c/1234567',
            'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1234567',
            'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git@1234567',
            'https://github.com/torvalds/linux/commit/1234567',
            'https://unsupported.kernel.patch.source.com/blah',
        ]},
    })
    extractor = code_extractor_linux.LinuxCodeExtractor()
    commits, failures = extractor.extract_commits_for_affected_entry(affected)
    self.assertLen(failures, 1)
    self.assertEqual(
        failures[0].url,
        'https://unsupported.kernel.patch.source.com/blah'
    )
    self.assertLen(commits, 5)
    for commit in commits:
        self.assertIsInstance(commit, git_commit.GitCommit)
        self.assertEqual(commit._rev, "1234567")

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
        'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git'
    )
    self.assertEqual(
        commits[4]._remote,
        'https://github.com/torvalds/linux'
    )

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
