# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""This module extracts the version of the target system.

Version extractor is to extract version numbers of the scanned target system.
Note that the version number should not be regarded as a reliable source of
truth of the immunity against certain vulnerabilities since it can be simply
modified without actual code patching.
"""

import abc
import collections
import collections.abc
import enum
import os
import re
from typing import Optional, Sequence

from absl import logging


@enum.unique
class TargetSystem(str, enum.Enum):
  UNKNOWN = 'unknown'
  KERNEL = 'kernel'


def get_target_version_files(
    target_system_type: Optional[TargetSystem] = None,
) -> Sequence[str]:
  """Returns a list of files containing version information.

  Args:
    target_system_type: optional arg for specifying the type of the target
      system. If None, try all known target systems to scan the version string.

  Returns a sequence of files containing version information.
  """
  target_version_files = []
  for cls in VersionExtractor.__subclasses__():
    if target_system_type and target_system_type != cls.get_target_system():
      continue
    target_version_files += cls.get_version_files()
  return target_version_files


def extract_version(
    target_root: str, target_system_type: Optional[TargetSystem] = None
) -> Optional[str]:
  """Returns the version string of the target system.

  Args:
    target_root: the absolute path to the root of the target system.
    target_system_type: optional arg for specifying the type of the target
      system. If None, try all known target systems to scan the version string.

  Raises:
    RuntimeError: if the target system contains more than one version.

  Returns:
    The version string extracted if found. Returns None otherwise.
  """
  versions = {}
  for cls in VersionExtractor.__subclasses__():
    if target_system_type and target_system_type != cls.get_target_system():
      continue
    ver = cls.extract_version(target_root)
    if ver:
      versions[cls] = ver
  if len(versions) > 1:
    raise RuntimeError(
        'Multiple versions were found from the target root: %s' % versions
    )
  if len(versions) < 1:
    return None
  matched_extractor = list(versions.keys())[0]
  target_system = matched_extractor.get_target_system()
  version = versions[matched_extractor]
  logging.info(
      'Extracted version: %s (Target system is recoganized as %s)',
      version,
      target_system.value,
  )
  return version


class VersionExtractor(metaclass=abc.ABCMeta):
  """Abstract class for version extractor classes."""

  @classmethod
  @abc.abstractmethod
  def get_version_files(cls) -> Sequence[str]:
    """Returns a list of files that may contain version information."""

  @classmethod
  @abc.abstractmethod
  def get_target_system(cls) -> TargetSystem:
    """Returns the target system of the class."""

  @classmethod
  @abc.abstractmethod
  def extract_version(cls, target_root: str) -> Optional[str]:
    """Extracts the version string from the target system."""


class KernelVersionExtractor(VersionExtractor):
  """Class to extract Linux kernel version."""

  @classmethod
  def get_version_files(cls) -> Sequence[str]:
    return [cls._get_version_file()]

  @classmethod
  def get_target_system(cls) -> TargetSystem:
    return TargetSystem.KERNEL

  @classmethod
  def _get_version_file(cls) -> str:
    return 'Makefile'

  @classmethod
  def extract_version(cls, target_root: str) -> Optional[str]:
    target_root = os.path.abspath(target_root)
    if not os.path.isdir(target_root):
      raise ValueError('Invalid directory: %s' % target_root)

    version_file_path = os.path.join(target_root, cls._get_version_file())
    if not os.path.isfile(version_file_path):
      return None

    with open(version_file_path) as vfile:
      return cls._parse_makefile(vfile.read())

  @classmethod
  def _parse_makefile(cls, makefile_content: str) -> str:
    """Parses the given Makefile line and returns kernel version.

    Args:
      makefile_content: the content of the Makefile in the string format.

    Returns:
      Kernel version string if version info is found. Empty string otherwise.
    """
    patterns = {
        'version': r'^VERSION\s?=\s?(?P<version>[0-9]*)\s*$',
        'patchlevel': r'^PATCHLEVEL\s?=\s?(?P<patchlevel>[0-9]*)\s*$',
        'sublevel': r'^SUBLEVEL\s?=\s?(?P<sublevel>[0-9]*)\s*$',
        'extraversion': r'^EXTRAVERSION\s?=\s?(?P<extraversion>\S*)\s*$',
    }
    version_info = collections.defaultdict(lambda: '')
    delimiters = collections.defaultdict(lambda: '')
    delimiters['patchlevel'] = '.'
    delimiters['sublevel'] = '.'

    for name, pattern in patterns.items():
      match = re.search(pattern, makefile_content, flags=re.MULTILINE)
      if not match:
        continue
      version_info[name] = match.group(name)

    kernelversion = ''
    ordered_names = ['version', 'patchlevel', 'sublevel', 'extraversion']

    for name in ordered_names:
      if not version_info[name]:
        return kernelversion
      kernelversion += '%s%s' % (delimiters[name], version_info[name])
    return kernelversion
