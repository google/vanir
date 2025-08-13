# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Manages flags common for Vanir Detector offerings.

This module is to manage flags that are commonly used by Detector offerings
such as Detector Runner. Note that this module is not for the Scanners so
scanner implementations, utilities or any other underlying modules should
neither import this module nor directly use the flag values.
"""

import datetime
import os
import re
from typing import Optional, Sequence

from absl import flags
import dateutil.relativedelta
from vanir import vulnerability_manager
from vanir import vulnerability_overwriter
from vanir.scanners import scanner_base
from vanir.scanners import target_selection_strategy



_OSV_ID_IGNORE_LIST = flags.DEFINE_list(
    'osv_id_ignore_list', [], 'Comma-separated list of OSV IDs of the'
    'vulnerabilities to exclude from scanning. '
    'E.g., \'--osv_id_ignore_list=ASB-A-1234,ASB-A-4567\''
)

_OSV_ID_ALLOWED_PREFIX = flags.DEFINE_list(
    'osv_id_allowed_prefix',
    None,
    'Comma-separated list of OSV ID prefixes of the vulnerabilities to include'
    ' from scanning. All other vulnerabilities will be excluded. E.g., '
    '\'--osv_id_allowed_prefix=ASB-A-,PUB-A-\' for limiting the scanning to'
    'Android Security Bulletin and Pixel Security Bulletin vulnerabilities.',
)

_CVE_ID_IGNORE_LIST = flags.DEFINE_list(
    'cve_id_ignore_list', [], 'Comma-separated list of CVE IDs of the'
    'vulnerabilities to exclude from scanning. '
    'E.g., \'--cve_id_ignore_list=CVE-1234-12345,CVE-4567-45678\''
)

_ANDROID_MIN_SEVERITY_LEVEL = flags.DEFINE_enum(
    'android_min_severity_level',
    None, [level.name for level in vulnerability_manager.AndroidSeverityLevel],
    'The minimum severity level of vulnerabilities to be tested. Android '
    'vulnerabilities with the severity level lower than this will be excluded. '
    'Vulnerabilities under other than Android ecosystem will not be affected.',
    case_sensitive=False
)

_ANDROID_SPL = flags.DEFINE_string(
    'android_spl', None, 'The Security Patch Level (SPL) for the scanning. '
    'Vulnerabilities with SPL after this value will be excluded. The SPL '
    'format should be YYYY-MM-DD. E.g., \'--android_spl=2020-01-05\'.'
)

_ANDROID_SPL_RELATIVE_MONTHS = flags.DEFINE_integer(
    'android_spl_relative_months',
    None,
    'The Security Patch Level (SPL) for scanning. Vulnerabilities with SPL '
    'after today\'s date plus this number of months will be excluded. Example: '
    '--android_spl_relative_months=1 will exclude vulnerabilities with SPL '
    'after next month. The offset can be negative. Mutually exclusive with '
    '--android_spl.',
)

_SIGN_TARGET_PATH_FILTER = flags.DEFINE_multi_string(
    'sign_target_path_filter', [], 'Regex string of a target file path '
    'pattern. Any vulnerability signature with target files that match this '
    'pattern will be excluded from scanning. Note that the pattern should '
    'fully match to work. When this flag is used multiple times, any '
    'signature that matches any of the regex will be excluded. E.g., '
    '\'--sign_target_path_filter=drivers/nvme/.*\' will filter out '
    'signature having target file drivers/nvme/host/core.c but '
    '\'--sign_target_path_filter=drivers/nvme/\' will not.'
)

_SIGN_TARGET_ARCH = flags.DEFINE_multi_enum(
    'sign_target_arch', [],
    [arch.name for arch in list(vulnerability_manager.Architecture)],
    'Flag to exclude architecture-specific signatures other than the target '
    'architecture. Multiple flags are allowed. E.g., '
    '\'--sign_target_arch=arm --sign_target_arch=arm64\' will exclude '
    'architecture specific signatures other than those for ARM and ARM64.',
    case_sensitive=False
)

_VULNERABILITY_FILE_NAMES = flags.DEFINE_multi_string(
    'vulnerability_file_name', None, 'The name of the OSV vulnerability file '
    'that contains Vanir signatures. If specified, the vulnerability file '
    'content will be used instead of OSV. Can be specified multiple times to '
    'use signatures from multiple files.'
)

_TARGET_SELECTION_STRATEGY = flags.DEFINE_enum_class(
    'target_selection_strategy',
    'truncated_path_match',
    target_selection_strategy.Strategy,
    'The target selection strategy defines how Vanir scanners choose files for'
    'analysis. For instance, "all_files" strategy selects all files with '
    'supported extensions as analysis targets; whereas"exact_path_match" '
    'strategy selects only files that exactly match the paths specified in the '
    'signatures. "truncated_path_match" strategy heuristically selects files '
    'potentially affected using the Truncated Path algorithm (please see '
    '|truncated_path| module for details).',
)

_INCLUDE_DEPRECATED_SIGNATURES = flags.DEFINE_bool(
    'include_deprecated_signatures', False,
    'If True, also use signatures that are marked as "deprecated".'
)

_IGNORE_SCAN_PATHS = flags.DEFINE_multi_string(
    'ignore_scan_path', None,
    'Any matches in files within this path will be ignored. For example, if '
    'you don\'t care about files under packages/apps/Bluetooth, specify '
    '--ignore_scan_path=packages/apps/Bluetooth/. Can be specified '
    'multiple times to ignore multiple paths.'
)

_PACKAGE_VERSIONS = flags.DEFINE_multi_string(
    'package_version', None,
    'One or more package versions your target code is under (e.g. for Android, '
    'this can be "11", "12L", etc.). When given, signatures that are specific '
    'to those versions will be used; signatures specific to other versions '
    'will be ignored. If not given, no versions-specific signatures will be '
    'used. Note that non-version-specific signatures will always be used '
    '(subjected to other flags). This flag can be specified multiple times.'
)

_OVERWRITE_SPECS = flags.DEFINE_string(
    'overwrite_specs',
    None,
    'Path to a JSON file containing vulnerability overwrite specifications. '
    'This file should contain a JSON array of OverwriteSpec objects, each '
    'defining how to modify specific vulnerabilities. See the '
    'vulnerability_overwriter module for detailed information about the '
    'OverwriteSpec format and examples.',
)


def _android_spl_validator(spl: Optional[str]) -> bool:
  if not spl:
    return True
  try:
    datetime.datetime.strptime(spl, vulnerability_manager.SPL_FORMAT)
  except ValueError:
    return False
  return True


def _sign_target_path_filter_validator(
    target_path_patterns: Sequence[str]) -> bool:
  if not target_path_patterns:
    return True
  for pattern in target_path_patterns:
    try:
      re.compile(pattern)
    except re.error:
      return False
  return True

flags.mark_flags_as_mutual_exclusive(
    [_ANDROID_SPL, _ANDROID_SPL_RELATIVE_MONTHS]
)

flags.register_validator(
    'android_spl',
    _android_spl_validator,
    message='--android_spl format must be YYYY-MM-DD.'
)

flags.register_validator(
    'sign_target_path_filter',
    _sign_target_path_filter_validator,
    message='--sign_target_path_filter must be a valid regular expression.',
)


def generate_vulnerability_filters_from_flags(
) -> Sequence[vulnerability_manager.VulnerabilityFilter]:
  """Parses vulnerability filter flags for detector and returns filters."""
  vfilters = []
  if _OSV_ID_IGNORE_LIST.value:
    vfilters.append(
        vulnerability_manager.OsvIdFilter(_OSV_ID_IGNORE_LIST.value))
  if _OSV_ID_ALLOWED_PREFIX.value:
    vfilters.append(
        vulnerability_manager.OsvIdAllowedPrefixFilter(
            _OSV_ID_ALLOWED_PREFIX.value
        )
    )
  if _CVE_ID_IGNORE_LIST.value:
    vfilters.append(
        vulnerability_manager.CveIdFilter(_CVE_ID_IGNORE_LIST.value))
  if (_ANDROID_MIN_SEVERITY_LEVEL.value and
      vulnerability_manager.AndroidSeverityLevel[
          _ANDROID_MIN_SEVERITY_LEVEL.value] !=
      vulnerability_manager.AndroidSeverityLevel.LOW):
    vfilters.append(
        vulnerability_manager.AndroidSeverityFilter(
            vulnerability_manager.AndroidSeverityLevel[
                _ANDROID_MIN_SEVERITY_LEVEL.value]))
  if _ANDROID_SPL.value:
    vfilters.append(vulnerability_manager.AndroidSplFilter(_ANDROID_SPL.value))
  elif _ANDROID_SPL_RELATIVE_MONTHS.present:
    today = datetime.date.today()
    offset = _ANDROID_SPL_RELATIVE_MONTHS.value
    offset_delta = dateutil.relativedelta.relativedelta(months=offset)
    spl = (today + offset_delta).strftime(vulnerability_manager.SPL_FORMAT)
    vfilters.append(vulnerability_manager.AndroidSplFilter(spl))
  if _SIGN_TARGET_PATH_FILTER.value:
    for path_pattern_str in set(_SIGN_TARGET_PATH_FILTER.value):
      path_pattern = re.compile(path_pattern_str)
      vfilters.append(vulnerability_manager.TargetPathFilter(path_pattern))
  # Note: this doesn't support arch filter without exception.
  if _SIGN_TARGET_ARCH.value:
    allowed_arches = [
        vulnerability_manager.Architecture[arch]
        for arch in _SIGN_TARGET_ARCH.value
    ]
    vfilters.append(vulnerability_manager.ArchitectureFilter(allowed_arches))
  if not _INCLUDE_DEPRECATED_SIGNATURES.value:
    vfilters.append(vulnerability_manager.DeprecatedSignatureFilter())
  return vfilters


def generate_overwrite_specs_from_flags() -> (
    Sequence[vulnerability_overwriter.OverwriteSpec]
):
  """Parses vulnerability overwriters flags and returns a list of OverwriteSpec."""
  path_to_overwrite_specs = _OVERWRITE_SPECS.value
  if not path_to_overwrite_specs:
    return []
  return vulnerability_overwriter.load_overwrite_specs_from_file(
      path_to_overwrite_specs
  )


def generate_vuln_manager_from_flags(
) -> Optional[vulnerability_manager.VulnerabilityManager]:
  """Create and return vuln manager containing vulns from vulnerability_file_name flag.

  Returns:
    The |VulnerabilityManager| object containing the vulns found in files
    specified in the flag, with the optional filter applied. Return None if
    vulnerability_file_name flag was not set.
  """
  if not _VULNERABILITY_FILE_NAMES.value:
    return None

  vulnerability_overwrite_specs = generate_overwrite_specs_from_flags()
  vuln_managers = []
  for vuln_file_name in _VULNERABILITY_FILE_NAMES.value:
    vuln_file_path = os.path.abspath(vuln_file_name)
    if not os.path.isfile(vuln_file_path):
      raise ValueError(
          f'Failed to find vulnerability file at {vuln_file_path}')
    vuln_managers.append(
        vulnerability_manager.generate_from_file(
            vuln_file_path,
            vulnerability_overwrite_specs=vulnerability_overwrite_specs,
        )
    )
  return vulnerability_manager.generate_from_managers(
      vuln_managers,
      overwrite_older_duplicate=True,
      vulnerability_filters=generate_vulnerability_filters_from_flags())


def generate_finding_filters_from_flags(
) -> Sequence[scanner_base.FindingsFilter]:
  """Parses flags related to finding filters and return the list of filters."""
  filters = []
  if _IGNORE_SCAN_PATHS.value:
    filters.extend(
        scanner_base.PathPrefixFilter(path) for path in _IGNORE_SCAN_PATHS.value
    )
  versions = _PACKAGE_VERSIONS.value if _PACKAGE_VERSIONS.value else []
  filters.append(scanner_base.PackageVersionSpecificSignatureFilter(versions))
  return filters
