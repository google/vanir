# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Extracts code snippets and metadata needed for CVE signature generation.

This module contains utility classes and functions to extract code snippets and
metadata of CVEs such as patch files (i.e., file diff) and unpatched files.
"""

from typing import Collection, Optional, Sequence, Tuple, Type, TypeVar

import requests
from vanir import vulnerability
# Simply importing the extractors will register them as subclasses of the
# abstract extractor class and therefore available for use.
# pylint: disable=unused-import
from vanir.code_extractors import code_extractor_android
from vanir.code_extractors import code_extractor_base
from vanir.code_extractors import code_extractor_git
# pylint: enable=unused-import

_P = TypeVar('_P', bound=code_extractor_base.AbstractCodeExtractor)

OSV_ID = 'id'
REF_URL = 'url'
REF_TYPE = 'type'
REF_TYPE_FIX = 'FIX'
VULN_AFFECTED = 'affected'
AFFECTED_PACKAGE = 'package'
PACKAGE_NAME = 'name'
PACKAGE_ECOSYSTEM = 'ecosystem'
AFFECTED_ECOSYSTEM_SPECIFIC = 'ecosystem_specific'


class DuplicatedCodeExtractorError(Exception):
  pass


def _get_extractor_class(ecosystem: str) -> Optional[Type[_P]]:
  """Returns the extractor class for the given ecosystem, or None."""
  extractors = code_extractor_base.AbstractCodeExtractor.__subclasses__()
  found_extractors = []
  for extractor_class in extractors:
    if extractor_class.is_supported_ecosystem(ecosystem):
      found_extractors.append(extractor_class)

  if not found_extractors:
    return None
  if len(found_extractors) > 1:
    raise DuplicatedCodeExtractorError(
        'Multiple code extractors supported ecosystem "%s": %s' %
        (ecosystem, found_extractors))
  return found_extractors[0]


def extract_for_affected_entry(
    affected: vulnerability.AffectedEntry,
    session: Optional[requests.sessions.Session] = None,
) -> Tuple[Sequence[code_extractor_base.Commit],
           Sequence[code_extractor_base.FailedCommitUrl]]:
  """Extracts fix commit data for the given Vulnerability.

  For each commit, this class extracts the following data:
  1. commit message
  2. per-file patch (diff)
  3. unmodified & modified versions of the files changed by the patch

  Args:
    affected: the OSV affected entry to extract fixes for.
    session: requests session to use for retrieving files and patches. If
      None, a new session will be used.

  Returns:
    A tuple where the first item is the list of |Commit| objects pertaining
    to the given |vuln|, and the second item is the list of URLs found but
    failed to be converted to |Commit| objects.
  """
  extractor_class = _get_extractor_class(affected.ecosystem)
  if not extractor_class:
    raise NotImplementedError(f'Unsupported ecosystem: {affected.ecosystem}')
  return extractor_class().extract_commits_for_affected_entry(
      affected, requests_session=session
  )


def extract_files_at_tip_of_unaffected_versions(
    ecosystem: str,
    package_name: str,
    affected_versions: Sequence[str],
    files: Collection[str],
    session: Optional[requests.sessions.Session] = None,
) -> Tuple[
    Sequence[code_extractor_base.Commit],
    Sequence[code_extractor_base.FailedCommitUrl],
]:
  """Extracts files tip of unmentioned versions of the given package.

  This method checks the list of given versions and determine the active tips of
  branches that are not mentioned in the list and extract the listed files at
  the those tips.

  Args:
    ecosystem: the ecosystem of the package.
    package_name: the name of the package.
    affected_versions: the list of affected versions of the package. Tip of
      versions not in this list will be extracted.
    files: the list of files to include.
    session: requests session to use for retrieving files and patches. If
      None, a new session will be used.

  Returns:
    A tuple where the first item is the list of |Commit| objects pertaining
    to the tip of a version not mentioned in |versions|, and the second item
    is the list of tip URLs failed to convert to |Commit| objects.
  """
  extractor_class = _get_extractor_class(ecosystem)
  if not extractor_class:
    raise NotImplementedError(f'Unsupported ecosystem: {ecosystem}')
  return extractor_class().extract_files_at_tip_of_unaffected_versions(
      package_name, affected_versions, files, requests_session=session,
  )
