# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Vanir detector scanner that scans a source tree managed with repo tool."""

import collections
import dataclasses
import itertools
import multiprocessing
import os
import re
import subprocess
from typing import Optional, Sequence, Tuple
from absl import logging

from vanir import signature
from vanir import vulnerability
from vanir import vulnerability_manager
from vanir import vulnerability_overwriter
from vanir.scanners import package_identifier
from vanir.scanners import scanner_base
from vanir.scanners import target_selection_strategy


def _apply(func, args, kwargs):
  return func(*args, **kwargs)


def _run_cmd(
    cmd: Sequence[str], cwd: Optional[str] = None,
    stdin: Optional[str] = None, check: bool = False,
) -> Tuple[int, str, str]:
  """Run cmd in cwd. Return a tuple of exit code, stdout, and stderr."""
  # PYTHONSAFEPATH does not work with repo before 2.40. Older repo versions are
  # still being used in a lot of distros.
  if 'PYTHONSAFEPATH' in os.environ:
    env = os.environ.copy()
    env.pop('PYTHONSAFEPATH')
  else:
    env = None
  result = subprocess.run(
      cmd, cwd=cwd, check=check, text=True, env=env,
      stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  return result.returncode, result.stdout, result.stderr


def _skipped_stats(path: str) -> scanner_base.ScannedFileStats:
  return scanner_base.ScannedFileStats(
      analyzed_files=0,
      skipped_files=sum(len(files) for _, _, files in os.walk(path)))


def _get_file_list(path: str) -> Sequence[str]:
  file_list = []
  for dirpath, subdirs, filenames in os.walk(path, topdown=True):
    subdirs[:] = [d for d in subdirs if d not in ('.git', '.repo')]
    file_list.extend(os.path.join(dirpath, filename) for filename in filenames)
  return file_list


class RepoScanner(scanner_base.ScannerBase):
  """Scan a source tree that's managed with repo tool."""

  def __init__(
      self,
      ecosystem: str,
      code_location: str,
      package_agnostic_analysis: bool = False,
      min_package_truncated_paths: Optional[int] = None,
  ):
    """Vanir scanner for code on a source tree managed with repo tool.

    Android uses repo tool (https://source.android.com/docs/setup/create/repo)
    to manage multiple git repositories that get checked out into specific
    subdirectories under the source tree. Each git repository corresponds to a
    "package" in OSV. This scanner takes a source tree location for a project
    that utilizes repo (e.g. Android, Chromium), figures out which
    vulnerabilities apply to which subdirectory and run Vanir scans on each
    subdir accordingly, and aggregate the results.

    This requires the repo tool to be installed.

    Args:
      ecosystem: The ecosystem to use for the scan (e.g. "Android").
      code_location: The location of the source tree managed with repo tool.
      package_agnostic_analysis: if True, scan projects against all signatures.
        If False (default), signatures will be limited to their corresponding
        signature packages matched against the project.
      min_package_truncated_paths: Optional minimum number of unique file paths
        (after truncation) to be considered in package matching. A package must
        have more than this number of files to be considered for heuristic
        matching against differently named packages.
    """
    super().__init__()
    self._code_location = code_location
    self._ecosystem = ecosystem
    self._package_agnostic_analysis = package_agnostic_analysis
    self._min_package_truncated_paths = min_package_truncated_paths

  @classmethod
  def name(cls):
    return 'repo_scanner'

  def _scan_one_subdir(
      self,
      subdir: str,
      signature_bundle: signature.SignatureBundle,
      strategy: target_selection_strategy.Strategy = (
          target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH
      ),
  ) -> Tuple[scanner_base.Findings, scanner_base.ScannedFileStats]:
    """Scan a single repo subdir pertaining to a one git repository."""
    current_scan_path = os.path.join(self._code_location, subdir)
    return scanner_base.scan(
        current_scan_path, signature_bundle, strategy=strategy,
    )

  def scan(
      self,
      strategy: target_selection_strategy.Strategy = (
          target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH
      ),
      override_vuln_manager: Optional[
          vulnerability_manager.VulnerabilityManager
      ] = None,
      extra_vulnerability_filters: Optional[
          Sequence[vulnerability_manager.VulnerabilityFilter]
      ] = None,
      vulnerability_overwrite_specs: Optional[
          Sequence[vulnerability_overwriter.OverwriteSpec]
      ] = None,
  ) -> Tuple[
      scanner_base.Findings,
      scanner_base.ScannedFileStats,
      vulnerability_manager.VulnerabilityManager,
  ]:
    """Run the scan and returns a tuple of Findings and ScannedFileStats."""
    # Use repo to get the mapping from directory to corresponding git repository
    logging.info('Querying repo list...')
    _, stdout, _ = _run_cmd(
        cmd=['repo', 'list'], cwd=self._code_location, check=True)
    repository_names = {}  # key: subdir, value: repository name
    for line in stdout.strip().splitlines():
      match = re.match(r'(?P<subdir>.*) : (?P<proj>.*)', line)
      if not match:
        raise ValueError('Unexpected repo command output: "%s"' % line)
      match_dict = match.groupdict()
      repository_names[match_dict['subdir']] = match_dict['proj']

    # Use override_vuln_manager if given; download from OSV otherwise
    if override_vuln_manager is not None:
      vuln_manager = vulnerability_manager.generate_from_managers(
          [override_vuln_manager],
          vulnerability_filters=extra_vulnerability_filters,
      )
    else:
      vuln_manager = vulnerability_manager.generate_from_osv(
          self._ecosystem,
          vulnerability_filters=extra_vulnerability_filters,
          vulnerability_overwrite_specs=vulnerability_overwrite_specs,
      )

    # Identify package name for each subdirectory.
    logging.info('Determining packages for each subdirectory...')
    pkg_identifier = package_identifier.PackageIdentifier(
        vuln_manager, self._ecosystem
    )

    # Holds scan results per subdir
    results = {}

    args = [
        (repo_name, _get_file_list(os.path.join(self._code_location, subdir)))
        for subdir, repo_name in repository_names.items()
    ]
    kwargs = {}
    if self._min_package_truncated_paths is not None:
      kwargs = dict(
          min_package_truncated_paths=self._min_package_truncated_paths,
      )
    starmap_args = zip(
        itertools.repeat(pkg_identifier.packages_for_repo),
        args, itertools.repeat(kwargs),
    )
    context = multiprocessing.get_context('forkserver')
    with context.Pool() as pool:
      subdirs_packages = pool.starmap(_apply, starmap_args)
      pool.close()
      pool.join()

    packages_to_scan = {}
    subdirs_with_unknown_packages = []
    # We treat the Linux kernel differently: if the kernel source exists in
    # a source tree, it's likely that there will be out-of-tree drivers too.
    # This toggle will tell the scanner to go look for those.
    is_kernel_repo_existing = False

    for (subdir, packages) in zip(repository_names, subdirs_packages):
      if not packages:
        subdirs_with_unknown_packages.append(subdir)

      else:
        logging.info('Dir %s maps to %s', subdir, packages)
        packages_to_scan[subdir] = packages

      if any(
          pkg for pkg in packages
          if pkg is vulnerability.MetaPackage.ANDROID_KERNEL
      ):
        is_kernel_repo_existing = True
        logging.info(
            'Found kernel repo in: %s. All unrecognized repos will be scanned '
            'against kernel signatures',
            subdir
        )
    logging.info(
        '%d dirs did not map to known packages',
        len(subdirs_with_unknown_packages)
    )
    logging.debug('Unmatched dirs: %s', subdirs_with_unknown_packages)

    # Process repositories with no matching package.
    for subdir in subdirs_with_unknown_packages:
      if self._package_agnostic_analysis:
        # Package name won't matter. Just use the repo name as package name.
        packages_to_scan[subdir] = repository_names[subdir]
      elif is_kernel_repo_existing:
        # If a kernel repository exists in the manifest, there can be kernel
        # module repositories. We will try scanning all uknown repos with kernel
        # signatures. Note that this wouldn't necessarily download all files
        # unless the strategy is ALL_FILES.
        packages_to_scan[subdir] = {
            vulnerability.MetaPackage.ANDROID_KERNEL
        }
      else:
        # Signatures will be tested against only their corresponding packages'
        # files. Thus, repositories with no matching package won't be considered
        # as further analysis targets.
        results[subdir] = {}, _skipped_stats(subdir)

    # Run the scans
    logging.info('Running scans...')
    for subdir, packages in packages_to_scan.items():
      if self._package_agnostic_analysis:
        logging.info('Scanning %s', subdir)
        results[subdir] = self._scan_one_subdir(
            subdir, signature.SignatureBundle(vuln_manager.signatures), strategy
        )
      else:
        logging.info('Scanning %s (against %s)', subdir, packages)
        signatures = itertools.chain.from_iterable(
            vuln_manager.get_signatures_for_package(self._ecosystem, package)
            for package in packages
        )
        results[subdir] = self._scan_one_subdir(
            subdir, signature.SignatureBundle(signatures), strategy
        )

      findings, _ = results[subdir]
      if findings:
        logging.info('  %d matches (before filters)', len(findings))

    # Combine Findings into one, prepending file paths with subdirs
    logging.info('Collecting results...')
    all_findings = collections.defaultdict(list)
    for subdir, (findings, _) in results.items():
      for sig in findings:
        for chunk in findings[sig]:
          all_findings[sig].append(dataclasses.replace(
              chunk, target_file=os.path.join(subdir, chunk.target_file)))

    # Combine ScannedFileStats into one
    analyzed_files = 0
    skipped_files = 0
    errors = []
    for _, stats in results.values():
      analyzed_files += stats.analyzed_files
      skipped_files += stats.skipped_files
      if stats.errors:
        errors.extend(stats.errors)
    stats = scanner_base.ScannedFileStats(
        analyzed_files=analyzed_files,
        skipped_files=skipped_files,
        errors=errors if errors else None,
    )

    return all_findings, stats, vuln_manager
