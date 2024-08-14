# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""The main module to run Signature Generator."""

import datetime
import json
import os
import re
from typing import Sequence

from absl import app
from absl import flags
from absl import logging
import requests
import requests.adapters
from vanir import file_list_manager
from vanir import sign_generator
from vanir import vulnerability
from vanir import vulnerability_manager

_SIGNATURE_FILE_NAME = flags.DEFINE_string(
    'signature_file_name', None,
    'The file name to store the generated signature file. If not specified '
    ' "/tmp/vanir/signature-<current datetime>.json" will be used.')

_VULNERABILITY_FILE_NAME = flags.DEFINE_string(
    'vulnerability_file_name', None,
    'Generating signatures based on a local vulnerability file instead of '
    'vulnerabilities in OSV. The vulnerability file should be in JSON format '
    'containing a list of vulnerabilities, and each vulnerability should be '
    'compatible with OSV schema (https://ossf.github.io/osv-schema/).')

_OSV_ECOSYSTEM = flags.DEFINE_string(
    'osv_ecosystem', None,
    'Name of the OSV ecosystem to generate signatures for, e.g. "Android". '
    'Also need to specify osv_package. Incompatible with '
    '--vulnerability_file_name or --use_osv_android_kernel_vulns.')

_OSV_PACKAGES = flags.DEFINE_multi_string(
    'osv_package', None,
    'Name of the OSV package to generate signatures for, e.g. '
    '"platform/frameworks/base". Also need to specify osv_ecosystem. '
    'Can be specified multiple times to get vulns from multiple packages. '
    'Incompatible with --vulnerability_file_name or '
    '--use_osv_android_kernel_vulns.')

_USE_OSV_ANDROID_KERNEL = flags.DEFINE_bool(
    'use_osv_android_kernel_vulns', False,
    'Shortcut flag to use all OSV Android kernel as the source of vulns to '
    'generate signatures for. Incompatible with --vulnerability_file_name, '
    '--osv_ecosystem, or --osv_package.')

_DEPRECATED_SIGNATURES = flags.DEFINE_multi_string(
    'deprecated_signatures', None,
    'JSON file that contains the list of signatures that should be deprecated. '
    'The file format is a list of JSON structs, each contains a "reason" '
    'field, which contains a string with reason why those listed signatures '
    'should be deprecated, and either: "patch_urls" which is a list of '
    'patch URLs, "vuln_id" which contains a vulnerability that should be '
    'deprecated, or "signature_ids" which is a list of signature IDs. '
    'Example: '
    '[{"reason": "Noisy",'
    '  "patch_urls": ["https://android.googlesource.com/platform/art/+/234"]},'
    ' {"reason": "no longer relevant", "vuln_id": "ASB-A-789"},'
    ' {"reason": "too broad", "signature_ids": ["ASB-A-789-123456"]}]'
    'Can be specified multiple times.')

_EXACT_MATCH_ONLY_SIGNATURES = flags.DEFINE_multi_string(
    'exact_target_file_match_only_signatures', None,
    'JSON file that contains the list of signatures that should match only '
    'against its target file. By default, Vanir compares all signatures '
    'against all files selected by the strategy. This json file will list '
    'signatures that should only be matched against its exact target file. '
    'The file format is a list of JSON structs, each contains a "reason" '
    'field, which contains a string with reason why those listed signatures '
    'should be matching with its target file only, and "signature_ids" which '
    'is a list of signature ID strings or "patch_urls" which is a list of '
    'patches. Example: '
    '[{"reason": "File was copied to unrelated features", '
    '  "patch_urls": ["https://android.googlesource.com/platform/art/+/234"]}'
    ' {"reason": "File was also copied to other unrelated features", '
    '  "signature_ids": ["ASB-A-789-123456"]}].'
    'Can be specified multiple times.')


_IGNORE_TEST_FILES = flags.DEFINE_bool(
    'ignore_test_files', True,
    'Ignore known test files being patched when generating signatures.')

_REF_FILE_LIST_SOURCE = flags.DEFINE_enum_class(
    'ref_file_list_source',
    'cache',
    file_list_manager.Source,
    'Source of the reference file lists needed for calculating truncated path'
    ' levels of signatures.',
)

_DRIVER_FILE_PATTERN = re.compile(r'drivers/.*')


def _validate_vuln_source_flags(flags_to_check: dict[str, str]) -> bool:
  source_flags = (
      'vulnerability_file_name',
      'osv_ecosystem',
      'use_osv_android_kernel_vulns')
  only_one_source = 1 == sum(1 for flag in source_flags if flags_to_check[flag])
  package_and_ecosystem_together = (
      (flags_to_check['osv_ecosystem'] and flags_to_check['osv_package']) or
      (not flags_to_check['osv_ecosystem'] and
       not flags_to_check['osv_package']))
  return only_one_source and bool(package_and_ecosystem_together)


def main(argv: Sequence[str]) -> None:
  if len(argv) > 1:
    raise app.UsageError('Too many command-line arguments.')
  logging.use_python_logging()

  deprecated_signs = set()
  deprecated_patches = set()
  deprecated_vulns = set()
  if _DEPRECATED_SIGNATURES.value:
    for deprecated_signs_file in _DEPRECATED_SIGNATURES.value:
      with open(deprecated_signs_file, 'rt') as fd:
        for deprecated_signs_block in json.load(fd):
          deprecated_signs.update(
              deprecated_signs_block.get('signature_ids', ()))
          deprecated_patches.update(
              deprecated_signs_block.get('patch_urls', ()))
          if 'vuln_id' in deprecated_signs_block:
            deprecated_vulns.add(deprecated_signs_block['vuln_id'])

  exact_match_only_signs = set()
  exact_match_only_patches = set()
  if _EXACT_MATCH_ONLY_SIGNATURES.value:
    for exact_match_only_signs_file in _EXACT_MATCH_ONLY_SIGNATURES.value:
      with open(exact_match_only_signs_file, 'rt') as fd:
        for exact_match_only_signs_block in json.load(fd):
          exact_match_only_signs.update(
              exact_match_only_signs_block.get('signature_ids', ()))
          exact_match_only_patches.update(
              exact_match_only_signs_block.get('patch_urls', ()))

  output_file = _SIGNATURE_FILE_NAME.value
  if not output_file:
    output_file = '/tmp/vanir/signature-%s.json' % datetime.datetime.now(
    ).strftime('%Y%m%d%H%M%S')
  directory = os.path.dirname(os.path.realpath(output_file))
  os.makedirs(directory, exist_ok=True)

  session = requests.Session()
  retries = requests.adapters.Retry(total=10, backoff_factor=0.5)
  session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retries))

  if _VULNERABILITY_FILE_NAME.value:
    vuln_file_path = os.path.abspath(_VULNERABILITY_FILE_NAME.value)
    vuln_manager = vulnerability_manager.generate_from_file(vuln_file_path)
  elif _USE_OSV_ANDROID_KERNEL.value:
    vuln_manager = vulnerability_manager.generate_from_osv(
        ecosystem='Android',
        packages=vulnerability.MetaPackage.ANDROID_KERNEL,
        session=session,
    )
  elif _OSV_ECOSYSTEM.value and _OSV_PACKAGES.value:
    vuln_manager = vulnerability_manager.generate_from_osv(
        ecosystem=_OSV_ECOSYSTEM.value,
        packages=_OSV_PACKAGES.value,
        session=session,
    )
  else:
    
    # all of Android in one go
    raise ValueError(
        'Must provide either --osv_ecosystem together with --osv_package, or '
        'point to a custom vuln JSON file with --vulnerability_file_name, or '
        'specify --use_osv_android_kernel_vulns.')

  filters = []
  if _IGNORE_TEST_FILES.value:
    java_test_file_filter = sign_generator.EcosystemAndFileNameFilter(
        'Android', r'(^|.*/)tests?/.*[^/]Tests?(Base)?.java')
    cpp_test_file_filter = sign_generator.EcosystemAndFileNameFilter(
        'Android', r'(^|.*/)tests?/.*[^/]Tests?.(cpp|cc)')
    filters += [java_test_file_filter, cpp_test_file_filter]

  ref_file_lists = file_list_manager.get_file_lists(
      source=_REF_FILE_LIST_SOURCE.value
  )
  conditions = {
      file_list_manager.ANDROID_ECOSYSTEM: {
          file_list_manager.KERNEL_PACKAGE: _DRIVER_FILE_PATTERN
      }
  }
  tp_level_finder = sign_generator.TruncatedPathLevelFinder(
      ref_file_lists, conditions
  )
  generator = sign_generator.SignGenerator(
      filters=filters,
      truncated_path_level_finder=tp_level_finder,
      session=session,
  )
  vuln_manager.generate_signatures(
      session=session,
      generator=generator,
      deprecated_signatures=deprecated_signs,
      deprecated_vulns=deprecated_vulns,
      deprecated_patch_urls=deprecated_patches,
      exact_match_only_signatures=exact_match_only_signs,
      exact_match_only_patch_urls=exact_match_only_patches,
  )

  with open(output_file, 'w') as f:
    f.write(vuln_manager.to_json())


if __name__ == '__main__':
  flags.register_multi_flags_validator(
      [_VULNERABILITY_FILE_NAME, _OSV_ECOSYSTEM, _OSV_PACKAGES,
       _USE_OSV_ANDROID_KERNEL],
      _validate_vuln_source_flags,
      message=(
          'Must provide either --osv_ecosystem together with --osv_package, '
          'or point to a custom vuln JSON file with --vulnerability_file_name, '
          'or specify --use_osv_android_kernel_vulns.'))
  app.run(main)
