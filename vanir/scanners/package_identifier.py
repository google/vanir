# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Pakcage Identifier identifies maps a directory to a package."""

import functools
from typing import Collection, FrozenSet, Optional, Sequence

from absl import logging
from vanir import truncated_path
from vanir import vulnerability_manager

DEFAULT_TRUNCATED_PATH_LEVEL = 2

_DEFAULT_TRHESHOLD = 0.5
_DEFAULT_MIN_PACKAGE_TRUNCATED_PATHS = 5


class PackageIdentifier:
  """Class to heuristically identify if a directory belongs to a package."""

  def __init__(
      self,
      vuln_manager: vulnerability_manager.VulnerabilityManager,
      ecosystem: str,
  ):
    # Mapping from a package name to its signatures from vuln manager
    self._signatures_per_package = {}
    for package_name in vuln_manager.affected_package_names:
      self._signatures_per_package[package_name] = (
          vuln_manager.get_signatures_for_package(ecosystem, package_name)
      )

  @functools.lru_cache
  def get_truncated_paths(
      self,
      package_name: str,
  ) -> FrozenSet[truncated_path.TruncatedPath]:
    """Returns truncated paths of signatures of the given package."""
    signatures = self._signatures_per_package.get(package_name)
    truncated_paths = set()
    for sign in signatures:
      if sign.truncated_path_level is not None:
        level = sign.truncated_path_level
      else:
        level = min(
            DEFAULT_TRUNCATED_PATH_LEVEL,
            truncated_path.TruncatedPath.get_max_level(sign.target_file)
        )
      if truncated_path.TruncatedPath.is_level_ok(sign.target_file, level):
        truncated_paths.add(
            truncated_path.TruncatedPath(sign.target_file, level)
        )
    return frozenset(truncated_paths)

  def get_package_name_if_signature_exist(
      self,
      package_name: str,
  ) -> Optional[str]:
    """Returns package name if any signature under the pkg exists.

    This function checks if any signatures mapped to |package_name| exist
    and returns the package name if exists. If the returning package belongs to
    a meta package, this function will return the meta package instead.

    Args:
      package_name: the string package name or meta package to check.

    Returns:
      The mapped package name or meta package if corresponding signature exist.
    """
    if package_name not in self._signatures_per_package:
      logging.debug(
          'Found no signatures registered for package %s',
          package_name,
      )
      return None
    return package_name

  def is_package_mapped_to_repo(
      self,
      package_name: str,
      repo_file_list: Sequence[str],
      threshold: float = _DEFAULT_TRHESHOLD,
      min_package_truncated_paths: int = _DEFAULT_MIN_PACKAGE_TRUNCATED_PATHS,
  ) -> bool:
    """Heuristically checks if a repository maps to the given package.

    Note that the use of this function is not necessarily limited to
    repositories. Repository here essentially means a collection of files.

    Args:
      package_name: the package name to check.
      repo_file_list: names of all files in the repository.
      threshold: the minimum truncated path inclusion rate for a package to be
        determined as being mapped to the the repository.
      min_package_truncated_paths: the minimum number of truncated paths found
        for the package. If the number of the truncated paths for the package
        found from the signatures is less than this, this function will blindly
        return False.

    Returns:
      True if the package is mapped to the repository; False, otherwise.
    """

    package_name = self.get_package_name_if_signature_exist(package_name)

    package_truncated_paths = self.get_truncated_paths(package_name)

    if len(package_truncated_paths) < min_package_truncated_paths:
      logging.debug(
          'Too few truncated paths found for the package %s. '
          'The directory will be regarded as not mapped. '
          'Found: %d. Required: %d.',
          package_name,
          len(package_truncated_paths),
          min_package_truncated_paths,
      )
      return False

    inclusion_rate = (
        truncated_path.check_inclusion_rate_of_truncated_paths_in_file_list(
            package_truncated_paths, repo_file_list
        )
    )
    logging.debug('inclusion rate of %s: %f', package_name, inclusion_rate)

    return inclusion_rate >= threshold

  def packages_for_repo(
      self,
      repo_name: str,
      repo_file_list: Sequence[str],
      threshold: float = _DEFAULT_TRHESHOLD,
      min_package_truncated_paths: int = _DEFAULT_MIN_PACKAGE_TRUNCATED_PATHS,
  ) -> Collection[str]:
    """Returns normalized OSV package names corresponding to this repo.

    This function checks which OSV packages the given repo maps to by
    1) checking its repository name maps to any package name in the signatures
    registered in this PackageIdentifier; 2) heuristically checking if the file
    list of this repo maps to one or more known packages.

    Note that for OSV package names that belongs to a meta package, the names
    are normalized to their closest meta package
    e.g. ":linux_kernel:Qualcomm" -> ":linux_kernel:".

    Args:
      repo_name: Name of the repo as listed in the manifest.
      repo_file_list: list of all files in |repo|.
      threshold: the minimum truncated path inclusion rate for a package to be
        determined as being mapped to the the repository.
      min_package_truncated_paths: the minimum number of truncated paths found
        for this repo to be matched to this package.

    Returns:
      Zero or more normalized OSV package name that the given repo maps to.
    """
    packages = set()
    # Many packages use its manifest project name as their package name
    # e.g. "platform/packages/apps/Bluetooth".
    normalized_pkg_name = self.get_package_name_if_signature_exist(repo_name)
    if normalized_pkg_name:
      packages.add(normalized_pkg_name)

    # Also heuristically identify the packages that could be mapped to this repo
    packages.update(
        package for package in self._signatures_per_package
        if self.is_package_mapped_to_repo(
            package, repo_file_list, threshold, min_package_truncated_paths
        )
    )
    return packages
