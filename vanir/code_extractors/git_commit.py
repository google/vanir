"""Commit class representing one Git commit."""

import functools
import logging
import os
import re
import subprocess
import tempfile
from typing import Mapping, Optional, Sequence, Tuple
import urllib.error
import urllib.request

import tenacity
from vanir.code_extractors import code_extractor_base


# https://android.googlesource.com/platform/art/+/android14-security-release
_GITILES_URL_PATTERN = re.compile(
    r'(?P<remote>[^:]+://[^/]+/.+)/\+/(refs/[^/]+/)?(?P<rev>[^/]+)/?'
)
# https://github.com/google/vanir/commit/fe4afbc9215e
_GITHUB_URL_PATTERN = re.compile(
    r'(?P<remote>[^:]+://[^/]*github.com/[^/]+/[^/]+)/commit/(?P<rev>[^/]+)'
)
# git+ssh://myserver.com/path/to/repo@fe4afbc9215e
_NORMALIZED_URL_PATTERN = re.compile(r'(?P<remote>[^@]+)@(?P<rev>[^/]+)')
# git://myserver.com/some/repo/fe4afbc9215e
_GENERIC_URL_PATTERN = re.compile(
    r'(?P<remote>[^:]+://[^/]+/.+)/(?P<rev>[^/]+)'
)
# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=dc59e4fea9d8
# https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=dc59e4fea9d8
# https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git/commit/?id=26490a375cb9
_CGIT_URL_PATTERN = re.compile(
    r'(?P<remote>[^:]+://[^/]+/.+\.git)/commit/\?id=(?P<rev>[^/]+)'
)
# https://git.kernel.org/linus/dc59e4fea9d8
# https://git.kernel.org/torvalds/c/dc59e4fea9d8
# https://git.kernel.org/stable/c/dc59e4fea9d8
# https://git.kernel.org/bpf/bpf/c/26490a375cb9
_GIT_KERNEL_SHORT_PATTERN = re.compile(
    r'(?P<remote>[^:]+://git\.kernel\.org/)(?P<path>[^/]+(/(?!c/)[^/]+){0,2})/(c/)?(?P<rev>[0-9a-fA-F]+)'
)

# Matches the first line of a CGit patch, e.g.:
# From dc59e4fea9d83f03bad6bddf3fa2e52491777482 Mon Sep 17 00:00:00 2001
_CGIT_PATCH_FROM_PATTERN = re.compile(r'^From\s+(?P<rev>[0-9a-fA-F]{40})\b')


@functools.cache
def parse_url(url: str) -> Tuple[str, str]:
  """Extracts git remote and revision strings from a commit URL."""
  # Resolve git.kernel.org short URLs (e.g., <developer> like torvalds,
  # stable trees using this convention) to their full long URLs using
  # HTTP redirects. This is necessary because these short URLs cannot be
  # used for cloning or fetching directly as they lack the full repository path.
  if _GIT_KERNEL_SHORT_PATTERN.fullmatch(url):
    try:
      req = urllib.request.Request(url, method='HEAD')
      with urllib.request.urlopen(req, timeout=10) as response:
        url = response.url
    except urllib.error.URLError as e:
      raise code_extractor_base.CommitDataFetchError(
          f'Failed to resolve redirect for CGit shortlink {url}: {e}'
      ) from e
  for pattern in (
      _NORMALIZED_URL_PATTERN,
      _GITILES_URL_PATTERN,
      _GITHUB_URL_PATTERN,
      _CGIT_URL_PATTERN,
      _GENERIC_URL_PATTERN,
  ):
    match = pattern.fullmatch(url)
    if match:
      return (match.group('remote'), match.group('rev'))
  raise code_extractor_base.IncompatibleUrlError(f'Unrecognized git URL: {url}')


class GitCommit(code_extractor_base.Commit):
  """Commit Class for Git commit URLs.

  This class extracts information from a git commit using git shallow and
  blobless clone (with --filter=blob:none and --depth=2), essentially only
  fetches the trees and blobs needed to extract the patch and all patched and
  unpatched files. Other files at the revision are fetched on demand.

  If git is not installed in exec path, provide path to git executable and its
  binaries via git_path and git_exec_path arguments.

  This commit class can take several optional arguments in its constructor
  related to git command execution:
  - git_path: path to the git executable (e.g. 'git').
  - git_exec_path: path to where the core Git programs are installed; to be
    passed to git's --exec-path (e.g. '/usr/lib/git-core').
  - git_working_dir: path to the local git repo directory to clone to. If not
    provided, a temporary directory will be created and cleaned up when this
    object is deleted.
  - git_instead_ofs: a list of (source, destination) tuples, where the source
    URL will be redirected to the destination URL in git's insteadOf config.
  - **kwargs: additional arguments, currently unused.
  """

  def _run_git(self, cmd: Sequence[str]) -> bytes:
    """Runs git command in a subprocess and returns the output."""
    git_cmd = [self._git_path, f'--git-dir={self._git_dir}', '--no-pager']
    if self._git_exec_path:
      git_cmd.append(f'--exec-path={self._git_exec_path}')
    git_cmd.extend(cmd)
    try:
      logging.debug('Running git command: %s', ' '.join(git_cmd))
      env = os.environ.copy()
      env['GIT_TERMINAL_PROMPT'] = '0'
      return subprocess.run(
          git_cmd,
          capture_output=True,
          check=True,
          env=env,
      ).stdout
    except subprocess.CalledProcessError as e:
      logging.debug('git command failed: %d: %s', e.returncode, e.stderr)
      raise code_extractor_base.CommitDataFetchError(
          f'Failed to run git command: {git_cmd}. Output: {e.stderr}'
      ) from e

  @tenacity.retry(
      wait=tenacity.wait_random_exponential(min=1, max=60),
      stop=tenacity.stop_after_attempt(5),
      reraise=True,
  )
  def _run_git_with_retry(self, cmd: Sequence[str]) -> bytes:
    return self._run_git(cmd)

  def __init__(
      self,
      url: str,
      *,
      git_path: Optional[str] = None,
      git_exec_path: Optional[str] = None,
      git_working_dir: Optional[str] = None,
      git_instead_ofs: Sequence[Tuple[str, str]] = (),
      **kwargs,
  ):
    del kwargs  # unused
    self._remote, self._rev = parse_url(url)
    self._git_path = git_path or 'git'
    self._git_exec_path = git_exec_path
    if git_working_dir:
      working_root_dir = git_working_dir
    else:
      self._working_root_dir_obj = tempfile.TemporaryDirectory()
      working_root_dir = self._working_root_dir_obj.name

    sanitized_remote = re.sub(r'[^a-zA-Z0-9]', '_', self._remote)
    self._git_dir = os.path.join(working_root_dir, sanitized_remote)
    self._run_git(['init', '--quiet'])
    self._run_git(['config', '--add', 'gc.auto', '0'])
    for src, dest in git_instead_ofs:
      self._run_git(['config', '--add', f'url.{dest}.insteadOf', src])
    # git fetch requires a full 40-character hash, so expand short hashes from
    # CGit before fetching.
    self._expand_short_rev_if_cgit(url)
    self._fetch()
    parents = (
        self._run_git(['rev-parse', f'{self._rev}^@'])
        .decode('utf-8')
        .strip()
        .split()
    )
    if len(parents) != 1:
      raise code_extractor_base.CommitDataFetchError(
          f'Failed to determine parent commit for {url}. '
          f'Expected 1 parent commit, got {parents}. Is this a git-merge?'
      )
    self._parent_commit = parents[0]
    super().__init__(url)

  def _fetch(self):
    return self._run_git_with_retry([
        'fetch',
        '--quiet',
        '--filter=blob:none',
        '--no-tags',
        '--depth=2',
        self._remote,
        self._rev,
    ])

  def _expand_short_rev_if_cgit(self, url: str):
    """Expands a short commit hash to a full 40-character hash via HTTP."""
    if len(self._rev) < 40 and (
        _CGIT_URL_PATTERN.fullmatch(url)
        or _GIT_KERNEL_SHORT_PATTERN.fullmatch(url)
    ):
      patch_url = f'{self._remote}/patch/?id={self._rev}'
      try:
        with urllib.request.urlopen(patch_url, timeout=10) as response:
          first_line = response.readline().decode('utf-8')
          match = _CGIT_PATCH_FROM_PATTERN.match(first_line)
          if match:
            full_rev = match.group('rev')
            logging.info('Expanded short hash %s to %s', self._rev, full_rev)
            self._rev = full_rev
          else:
            raise code_extractor_base.CommitDataFetchError(
                f'CGit patch at {patch_url} did not start with a valid From'
                ' line. (e.g. From <full_commit_hash>...)'
            )
      except urllib.error.URLError as e:
        raise code_extractor_base.CommitDataFetchError(
            f'Failed to fetch patch URL {patch_url}: {e}'
        ) from e

  def _normalize_url(self) -> str:
    # Validation is already done in __init__(), inside _parse_url().
    if 'github.com' in self._remote:
      return f'{self._remote}/commit/{self._rev}'
    return self._original_url

  def _fetch_raw_patch(self) -> str:
    """Returns the raw string output of git format-patch."""
    cmd = [
        'format-patch',
        '--stdout',
        '-1',
        '--no-binary',
        '--no-signature',
        self._rev,
    ]
    return self._run_git_with_retry(cmd).decode('utf-8')

  def _get_description(self) -> Optional[str]:
    cmd = ['show', '-s', '--format=%B', self._rev]
    return self._run_git_with_retry(cmd).decode('utf-8').strip() or None

  def get_commit_time(self) -> int:
    """Returns the commit timestamp."""
    return int(
        self._run_git_with_retry(
            ['show', '-s', '--format=%ct', self._rev]
        ).strip()
    )

  def _get_file(self, revision: str, path: str) -> str:
    return self._create_temp_file(
        self._run_git(['show', f'{revision}:{path}']),
        suffix=f'_{os.path.basename(path)}',
    )

  def _extract_patched_files(self) -> Mapping[str, str]:
    return {
        file.path: self._get_file(self._rev, file.path)
        for file in self._patch.added_files + self._patch.modified_files
    }

  def _extract_unpatched_files(self) -> Mapping[str, str]:
    return {
        file.path: self._get_file(self._parent_commit, file.path)
        for file in self._patch.removed_files + self._patch.modified_files
    }

  def get_file_at_rev(self, file_path: str) -> str:
    """Downloads a file at the commit's revision and returns the local path."""
    return self._get_file(self._rev, file_path)

  def cleanup(self):
    """Explicitly cleans up temporary directories used by this commit."""
    # Clean up the temporary directory managed by the base Commit class.
    super().cleanup()
    if hasattr(self, '_working_root_dir_obj'):
      self._working_root_dir_obj.cleanup()
