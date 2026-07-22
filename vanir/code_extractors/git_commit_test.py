# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

# Disabling protected-access to allow unit testing of internal variables and
# methods.
# pylint: disable=protected-access

"""Tests for git_commit module."""

import os
import subprocess
from typing import Mapping, Optional, Sequence
from unittest import mock
import tenacity

from vanir.code_extractors import code_extractor_base
from vanir.code_extractors import git_commit

from absl.testing import absltest
from absl.testing import parameterized


def _run(cmd: Sequence[str], cwd: Optional[str] = None) -> bytes:
  p = subprocess.run(list(cmd), capture_output=True, check=True, cwd=cwd)
  return p.stdout


class GitCommitTest(parameterized.TestCase):

  def _run_git(self, repo_dir: str, cmd: Sequence[str]) -> bytes:
    return _run(self.git_cmd + list(cmd), cwd=repo_dir)

  def _create_test_repo(
      self, repo_dir: str, revs: Sequence[Mapping[str, bytes]]
  ) -> Sequence[str]:
    """Each rev is a mapping of file name to content)."""
    self._run_git(self.git_repo_root, ['init', repo_dir])
    self._run_git(repo_dir, ['config', 'user.name', 'test'])
    self._run_git(repo_dir, ['config', 'user.email', 'a@b.c'])
    commits = []
    for i, files in enumerate(revs):
      self._run_git(repo_dir, ['rm', '--ignore-unmatch', '*'])
      for file_name, content in files.items():
        with open(os.path.join(repo_dir, file_name), 'wb') as f:
          f.write(content)
      self._run_git(repo_dir, ['add', '-A'])
      self._run_git(repo_dir, ['commit', '-m', f'commit {i}', '--allow-empty'])
      commit_id = self._run_git(repo_dir, ['rev-parse', 'HEAD'])
      commits.append(commit_id.decode('utf-8').strip())
    return commits

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    cls.enter_context(mock.patch.object(
        git_commit.GitCommit._run_git_with_retry.retry, 'wait',
        tenacity.wait_none(),
    ))
    cls.git_bin = 'git'
    cls.git_cmd = [cls.git_bin]
    cls.exec_path = None

  def setUp(self):
    super().setUp()
    self.git_repo_root = self.create_tempdir().full_path

    self.git_repo_dir = os.path.join(self.git_repo_root, 'test_repo')
    revs = [
        {'unrelated.txt': b'unchanged'},
        {
            'unrelated.txt': b'unchanged',
            'modified.txt': b'unmodified',
            'deleted': b'to be deleted',
        },
        {
            'unrelated.txt': b'unchanged',
            'modified.txt': b'modified',
            'added.bin': b'\x00\x01',
        },
        {},
    ]
    self.test_commit_id = self._create_test_repo(self.git_repo_dir, revs)[2]

  def test_init_with_file_url(self):
    url = f'file://{self.git_repo_dir}@{self.test_commit_id}'
    commit = git_commit.GitCommit(
        url,
        git_path=self.git_bin,
        git_exec_path=self.exec_path,
        git_working_dir=self.create_tempdir().full_path,
    )
    self.assertEqual(commit.url, url)
    self.assertEqual(commit.patched_files.keys(), {'modified.txt', 'added.bin'})
    self.assertEqual(commit.unpatched_files.keys(), {'modified.txt', 'deleted'})
    modified_tmp_file = commit.get_file_at_rev('modified.txt')
    with open(modified_tmp_file, 'rt', encoding='utf-8') as f:
      self.assertEqual(f.read(), 'modified')
    added_tmp_file = commit.get_file_at_rev('added.bin')
    with open(added_tmp_file, 'rb') as f:
      self.assertEqual(f.read(), b'\x00\x01')
    # The commit.patch is a copy, so its mutation shouldn't affect the original.
    self.assertNotEqual(commit.patch.clear(), commit._patch)

  def test_init_with_instead_of(self):
    commit = git_commit.GitCommit(
        f'https://android.com/test_repo/+/{self.test_commit_id}',
        git_path=self.git_bin,
        git_exec_path=self.exec_path,
        git_working_dir=self.create_tempdir().full_path,
        git_instead_ofs=[
            ('https://android.com', f'file://{self.git_repo_root}'),
        ],
    )
    self.assertEqual(
        commit.url, f'https://android.com/test_repo/+/{self.test_commit_id}',
    )
    self.assertEqual(commit.patched_files.keys(), {'modified.txt', 'added.bin'})
    self.assertEqual(commit.unpatched_files.keys(), {'modified.txt', 'deleted'})
    modified_tmp_file = commit.get_file_at_rev('modified.txt')
    with open(modified_tmp_file, 'rt', encoding='utf-8') as f:
      self.assertEqual(f.read(), 'modified')
    added_tmp_file = commit.get_file_at_rev('added.bin')
    with open(added_tmp_file, 'rb') as f:
      self.assertEqual(f.read(), b'\x00\x01')

  @parameterized.named_parameters(
      (
          'gitiles',
          'https://android.com/test_repo/+/',
      ),
      (
          'github',
          'git+ssh://github.com/google/test_repo/commit/',
      ),
      (
          'ssh_url',
          'git://normalized.url/test_repo@',
      ),
      (
          'generic_url',
          'sso://generic.url/test_repo/',
      ),
  )
  def test_init_with_normalized_url(self, url_prefix):
    commit = git_commit.GitCommit(
        f'{url_prefix}{self.test_commit_id}',
        git_path=self.git_bin,
        git_exec_path=self.exec_path,
        git_working_dir=self.create_tempdir().full_path,
        git_instead_ofs=[
            ('https://android.com', f'file://{self.git_repo_root}'),
            ('git+ssh://github.com/google', f'file://{self.git_repo_root}'),
            ('git://normalized.url', f'file://{self.git_repo_root}'),
            ('sso://generic.url', f'file://{self.git_repo_root}'),
        ],
    )
    self.assertEqual(commit.url, url_prefix + self.test_commit_id)

  @parameterized.named_parameters(
      (
          'no_rev',
          'https://xy.z/test_repo/+/',
          code_extractor_base.IncompatibleUrlError,
      ),
      (
          'bad_rev',
          'https://xy.z/test_repo/+/deadbeef',
          code_extractor_base.CommitDataFetchError,
      ),
  )
  def test_init_with_invalid_url(self, url, exception_type):
    with self.assertRaises(exception_type):
      git_commit.GitCommit(
          url,
          git_path=self.git_bin,
          git_exec_path=self.exec_path,
          git_working_dir=self.create_tempdir().full_path,
          git_instead_ofs=[('https://xy.z', f'file://{self.git_repo_root}')],
      )

  def test_init_with_git_merge(self):
    # create a merge commit in the test repo
    self._run_git(self.git_repo_dir, ['checkout', '-B', 'main'])
    self._run_git(self.git_repo_dir, ['checkout', '-B', 'branch1'])
    with open(
        os.path.join(self.git_repo_dir, 'branch_file'), 'wt', encoding='utf-8'
    ) as f:
      f.write('branch_file')
    self._run_git(self.git_repo_dir, ['add', 'branch_file'])
    self._run_git(self.git_repo_dir, ['commit', '-m', 'branch_commit'])
    self._run_git(self.git_repo_dir, ['checkout', 'main'])
    with open(
        os.path.join(self.git_repo_dir, 'main_file'), 'wt', encoding='utf-8'
    ) as f:
      f.write('main_file')
    self._run_git(self.git_repo_dir, ['add', 'main_file'])
    self._run_git(self.git_repo_dir, ['commit', '-m', 'main_commit'])
    self._run_git(self.git_repo_dir, ['merge', 'branch1'])
    merge_commit = self._run_git(self.git_repo_dir, ['rev-parse', 'HEAD'])

    with self.assertRaises(code_extractor_base.CommitDataFetchError):
      decoded_commit = merge_commit.decode('utf-8').strip()
      git_commit.GitCommit(
          f'file://{self.git_repo_dir}@{decoded_commit}',
          git_path=self.git_bin,
          git_exec_path=self.exec_path,
          git_working_dir=self.create_tempdir().full_path,
      )

  def test_get_file_at_rev(self):
    url = f'file://{self.git_repo_dir}@{self.test_commit_id}'
    commit = git_commit.GitCommit(
        url,
        git_path=self.git_bin,
        git_exec_path=self.exec_path,
        git_working_dir=self.create_tempdir().full_path,
    )
    modified_local_path = commit.get_file_at_rev('modified.txt')
    self.assertIsNotNone(modified_local_path)
    with open(modified_local_path, 'rt', encoding='utf-8') as f:
      self.assertEqual(f.read(), 'modified')
    unrelated_local_path = commit.get_file_at_rev('unrelated.txt')
    self.assertIsNotNone(unrelated_local_path)
    with open(unrelated_local_path, 'rt', encoding='utf-8') as f:
      self.assertEqual(f.read(), 'unchanged')

  def test_get_file_at_rev_fails_on_nonexistent_file(self):
    url = f'file://{self.git_repo_dir}@{self.test_commit_id}'
    commit = git_commit.GitCommit(
        url,
        git_path=self.git_bin,
        git_exec_path=self.exec_path,
        git_working_dir=self.create_tempdir().full_path,
    )
    with self.assertRaises(code_extractor_base.CommitDataFetchError):
      commit.get_file_at_rev('deleted')
    with self.assertRaises(code_extractor_base.CommitDataFetchError):
      commit.get_file_at_rev('nonexistent')

  def test_init_with_unrelated_args(self):
    url = f'file://{self.git_repo_dir}@{self.test_commit_id}'
    commit = git_commit.GitCommit(
        url,
        git_path=self.git_bin,
        git_exec_path=self.exec_path,
        git_working_dir=self.create_tempdir().full_path,
        unrelated_arg='some_value',
    )
    self.assertEqual(commit.url, url)
    self.assertEqual(commit.patched_files.keys(), {'modified.txt', 'added.bin'})
    self.assertEqual(commit.unpatched_files.keys(), {'modified.txt', 'deleted'})

  def test_init_with_renamed_file_path(self):
    """Tests that unpatched files are correctly extracted when renamed."""
    # Reuse the existing test repo, but isolate changes in a new branch
    self._run_git(self.git_repo_dir, ['checkout', '-B', 'rename_branch'])
    with open(os.path.join(self.git_repo_dir, 'old_name.txt'), 'wt') as f:
      f.write('content before rename')
    self._run_git(self.git_repo_dir, ['add', 'old_name.txt'])
    self._run_git(self.git_repo_dir, ['commit', '-m', 'add file'])
    # Rename the file to trigger file.is_rename
    self._run_git(self.git_repo_dir, ['mv', 'old_name.txt', 'new_name.txt'])
    self._run_git(self.git_repo_dir, ['commit', '-m', 'rename file'])
    commit_id = self._run_git(
        self.git_repo_dir, ['rev-parse', 'HEAD']
    ).decode('utf-8').strip()
    # Initialize GitCommit with the new commit
    url = f'file://{self.git_repo_dir}@{commit_id}'
    commit = git_commit.GitCommit(
        url,
        git_path=self.git_bin,
        git_exec_path=self.exec_path,
        git_working_dir=self.create_tempdir().full_path,
    )
    self.assertEqual(commit.url, url)
    self.assertEqual(commit.patched_files.keys(), {'new_name.txt'})
    self.assertEqual(commit.unpatched_files.keys(), {'new_name.txt'})
    with open(commit.unpatched_files['new_name.txt'], 'rt') as f:
      self.assertEqual(f.read(), 'content before rename')


if __name__ == '__main__':
  absltest.main()
