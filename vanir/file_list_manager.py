# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Module for managing known files for each ecosystem/package.

This module manages lists of known files for each ecysostem & package needed
for calculating truncated path level.
"""

from vanir import file_path_utils
import enum
import json
from typing import Mapping, Sequence

from importlib import resources

ECOSYSTEM_FILE_LISTS_CACHE = (
    file_path_utils.get_root_file_path('cache/ecosystem_file_lists.json')
)


_GITFS_TIMEOUT_SEC = 60
_GITFS_ADDR = 'blade:git'

ANDROID_ECOSYSTEM = 'Android'
KERNEL_PACKAGE = ':linux_kernel:'
_MAINLINE_KERNEL_PROJECT = 'android:kernel/common:refs/heads/android-mainline:'

_KNOWN_SOURCES = [(ANDROID_ECOSYSTEM, KERNEL_PACKAGE, _MAINLINE_KERNEL_PROJECT)]


@enum.unique
class Source(enum.Enum):
  CACHE = 'cache'


def get_file_lists(
    source: Source = Source.CACHE,
) -> Mapping[str, Mapping[str, Sequence[str]]]:
  """Returns reference file lists for signature generation.

  Args:
    source: source to retrieve file lists.

  Returns:
    Reference file list map where the first key is ecosystem, the second key is
    package name and the value is list of files.
  """
  if source == Source.CACHE:
    resource = resources.files('vanir').joinpath(ECOSYSTEM_FILE_LISTS_CACHE).read_bytes()
    file_lists = json.loads(resource)
    return file_lists
  else:
    raise ValueError(f'Unknown file list source: {source}')
