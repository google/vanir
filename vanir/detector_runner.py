# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

r"""The main module to run Vanir Detector.

Usage:
  ./detector_runner [flags] scanner_name scannerarg1 scannerarg2 ...

For example, to scan /test/source against all signatures in /vanir/sigs.json:
  ./detector_runner \
      --vulnerability_file_name=/vanir/sigs.json \
      offline_directory_scanner /test/source
"""
import collections
import datetime
import functools
import inspect
import itertools
import json
import os
import sys
import textwrap
from typing import Any, Mapping, Sequence, Type, TypeVar

from absl import app
from absl import flags
from absl import logging
import jinja2
import requests
from vanir import detector_common_flags
from vanir import osv_client
from vanir import reporter

from vanir.scanners import scanner_base

# Simply importing the scanners will register them as subclasses of the
# abstract extractor class and therefore available for use.
# pylint: disable=unused-import,g-bad-import-order
from vanir.scanners import android_kernel_scanner
from vanir.scanners import offline_directory_scanner
from vanir.scanners import package_scanner
from vanir.scanners import repo_scanner
# pylint: enable=unused-import,g-bad-import-order

ScannerClass = TypeVar('ScannerClass', bound=scanner_base.ScannerBase)

flags.declare_key_flag('osv_id_ignore_list')
flags.declare_key_flag('cve_id_ignore_list')
flags.declare_key_flag('android_min_severity_level')
flags.declare_key_flag('android_spl')
flags.declare_key_flag('sign_target_path_filter')
flags.declare_key_flag('sign_target_arch')
flags.declare_key_flag('vulnerability_file_name')
flags.declare_key_flag('target_selection_strategy')
flags.declare_key_flag('ignore_scan_path')

_REPORT_FILE_NAME_PREFIX = flags.DEFINE_string(
    'report_file_name_prefix',
    None,
    'The output report file name prefix. If not '
    'specified "/tmp/vanir/report-<current datetime>" will be used.',
)

_MINIMUM_NUMBER_OF_FILES = flags.DEFINE_integer(
    'minimum_number_of_files',
    10,
    'The minimum number of files expected to exist in the target source tree. '
    'If the target source tree contains less files than this theshold, '
    'detector will fail. This is just a safety knob for preventing mistakes of '
    'scanning a wrong target. If you intend to scan directory containing few '
    'files, please update this flag.',
)

_SCANNER = flags.DEFINE_string(
    'scanner',
    None,
    'The name of the scanner to use for the detection run. This can also be '
    'provided as the first positional argument. If no scanner is specified, '
    'the list of available scanners will be printed.',
)

_SCANNER_ARGS = flags.DEFINE_string(
    'scanner_args',
    None,
    'A JSON object containing arguments for the scanner. The key is the '
    'argument name and the value is the argument value. This flag can be used '
    'to pass arbitraty arguments to the scanner that are not possible with the '
    'positional-only arguments, as well as to improve readability. See each '
    'scanner\'s help message for the list of its supported arguments.'
    'Example: --scanner_args=\'{"code_location": "/path/to/source"}\'.',
)

_HTML_REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Vanir Detector Report {{ report_file_name }}</title>
    <style>
    body {
      font-family: Roboto, sans-serif;
    }
    table {
      border-collapse: collapse;
      border: 2px solid black;
    }
    th, td {
      border: 1px solid gray;
      word-break: keep-all;
      padding: 5px;
      vertical-align: top;
    }
    h3 {
      padding: 0.3em;
      background-color: lightgray;
    }
    .expand-toggle {
        cursor: pointer;
    }
    .expand-toggle.collapsed:before {
      content: "▸ ";
    }
    .expand-toggle:before {
      content: "▾ ";
    }
    .expand-toggle.collapsed + * {
        display: none;
    }
    </style>
    <script>
    function toggle(element) {
      element.classList.toggle("collapsed");
    }
    </script>
  </head>
  <body>
    <h1>Vanir Detector Report {{ report_file_name }}</h1>
    <h3 onclick="toggle(this);" class="expand-toggle collapsed">Options</h3>
    <pre style="white-space: pre-wrap;">{{ options }}</pre>

    <h3 onclick="toggle(this);" class="expand-toggle collapsed">
    Coverage
    ({{ covered_cves|length }} CVE{{ 's' if covered_cves|length > 1 else '' }})
    </h3>
    <table>
      <tr>
        <th>Covered CVEs</th>
        <td>
        <pre>{% for cve in covered_cves %}<nobr>{{ '%-15s' | format(cve) | replace(' ','&nbsp;')}}</nobr>&nbsp;<wbr>{% endfor %}
        </pre>
        </td>
      </tr>
      <tr>
        <th>Unpatched CVEs</th>
        <td>
        <pre>{% for cve in unpatched_cves %}<nobr>{{ '%-15s' | format(cve) | replace(' ','&nbsp;')}}</nobr>&nbsp;<wbr>{% endfor %}
        </pre>
        </td>
      </tr>
    </table>

    <h3 onclick="toggle(this);" class="expand-toggle">
    Missing Patches in Target Files
    (in {{ target_missing_patches|length }}
     vuln{{ 's' if target_missing_patches|length > 1 else '' }})
    </h3>
    <table>
      {% for osv_id, details in target_missing_patches.items()|sort %}
      <tr>
        <td>{{osv_id}}</td>
        <td>
          {% for summary in details['summaries']|sort %}{{summary}}<br>
          {% endfor %}
          {% if details['osv_url'] == 'Not published.' %}
            OSV: {{details['osv_url']}}<br>
          {% else %}
            OSV: <a href=\"{{details['osv_url']}}\">{{details['osv_url']}}</a><br>
          {% endif %}
          CVE: {% for cve_id in details['cve_ids'] %}{{cve_id}} {% endfor %}<br>
        </td>
      </tr>
      {% endfor %}
    </table>

    <h3 onclick="toggle(this);" class="expand-toggle">
    Missing Patches in Non-target Files
    (in {{ non_target_missing_patches|length }}
     vuln{{ 's' if non_target_missing_patches|length > 1 else '' }})
    </h3>
    <table>
      {% for osv_id, details in non_target_missing_patches.items()|sort %}
      <tr>
        <td>{{osv_id}}</td>
        <td>
          {% for summary in details['summaries']|sort %}{{summary}}<br>
          {% endfor %}
          {% if details['osv_url'] == 'Not published.' %}
            OSV: {{details['osv_url']}}<br>
          {% else %}
            OSV: <a href=\"{{details['osv_url']}}\">{{details['osv_url']}}</a><br>
          {% endif %}
          CVE: {% for cve_id in details['cve_ids'] %}{{cve_id}} {% endfor %}<br>
        </td>
      </tr>
      {% endfor %}
    </table>

    {% if errors %}
    <h3 onclick="toggle(this);" class="expand-toggle">Errors ({{ errors|length }})</h3>
    <table>
      {% for error in errors|sort %}
      <tr><td>{{ error|e }}</td></tr>
      {% endfor %}
    </table>
    {% endif %}
    <h3 onclick="toggle(this);" class="expand-toggle collapsed">Scan metadata and stats</h3>
    <table>
      {% for key, value in metadata.items()|sort %}
      <tr><td>{{key}}</td><td>{{value|escape|replace('\n', '<br />')}}</td></tr>
      {% endfor %}
    </table>
  </body>
</html>
"""

_CMDLINE_ARGS_TYPES = (
    inspect.Parameter.POSITIONAL_ONLY,
    inspect.Parameter.POSITIONAL_OR_KEYWORD,
    inspect.Parameter.VAR_POSITIONAL)


def _get_all_scanners() -> Mapping[str, Type[ScannerClass]]:
  """Return all known scanners that can be run from the command line.

  This covers all scanners that do not require keyword-only arguments.

  Returns:
    A map from scanner name to scanner class for all supported scanners.
  """
  scanner_map = {}
  scanners = scanner_base.ScannerBase.__subclasses__()
  while scanners:
    scanner = scanners.pop()
    scanners += scanner.__subclasses__()
    scanner_params = inspect.signature(scanner.__init__).parameters.values()
    unsupported_params = (arg for arg in scanner_params
                          if arg.kind is inspect.Parameter.KEYWORD_ONLY
                          and arg.default is inspect.Parameter.empty)
    if any(unsupported_params):
      continue
    scanner_name = scanner.name()
    if scanner_name in scanner_map:
      raise ValueError(
          f'Found more than one scanner with the same name "{scanner_name}": '
          f'\n{scanner_map.get(scanner_name)}'
          f'\n{scanner}'
      )
    scanner_map[scanner_name] = scanner
  return scanner_map


def _get_scanner_usage_str(scanner: Type[ScannerClass]) -> str:
  """Returns commandline usage instruction string for the given scanner."""
  all_args = inspect.signature(scanner.__init__).parameters.values()
  scanner_args = [arg for arg in all_args if arg.name != 'self'
                  and arg.kind in _CMDLINE_ARGS_TYPES]
  arg_strs = []
  for arg in scanner_args:
    if arg.kind is inspect.Parameter.VAR_POSITIONAL:
      if arg.default is inspect.Parameter.empty:
        arg_strs.append(f'{arg.name} [{arg.name}...]')
      else:
        arg_strs.append(f'[{arg.name}...]')
    elif arg.default is inspect.Parameter.empty:
      arg_strs.append(f'{arg.name}')
    else:
      arg_strs.append(f'[{arg.name}]')
  init_doc = (
      textwrap.indent(inspect.cleandoc(scanner.__init__.__doc__), '  ')
      if scanner.__init__.__doc__ else ''
  )
  class_doc = (
      textwrap.indent(inspect.cleandoc(scanner.__doc__), '  ')
      if scanner.__doc__ else ''
  )
  sample_json_args = f'\'{{"{arg_strs[0]}": "some_value..."}}\''
  return (
      f'Documentation for {scanner.name()}:\n'
      '  Usage (with positional args):\n'
      f'    detector_runner.py {scanner.name()} {" ".join(arg_strs)}\n\n'
      '  Usage (with argument json object):\n'
      f'    detector_runner.py {scanner.name()} '
      f'--scanner_args={sample_json_args}\n\n'
      f'{init_doc or class_doc}'
  ).strip()


def _is_valid_scanner_args(
    scanner: Type[ScannerClass],
    positional_args: Sequence[str],
    kwargs: Mapping[str, Any],
) -> bool:
  """Returns whether the given args pass validity check for the scanner."""
  all_args = inspect.signature(scanner.__init__).parameters.values()
  scanner_args = [arg for arg in all_args if arg.name != 'self'
                  and arg.kind in _CMDLINE_ARGS_TYPES]
  scanner_arg_names = [arg.name for arg in scanner_args]
  required_arg_names = [
      arg.name for arg in scanner_args
      if (arg.default is inspect.Parameter.empty)
  ]
  has_vararg = any(
      1 for arg in scanner_args if arg.kind is inspect.Parameter.VAR_POSITIONAL
  )
  # Check to see if number of args is valid for the given scanner
  if len(positional_args) > len(scanner_args):
    if not has_vararg:
      return False
    args_given_as_positional = set(scanner_arg_names)
  else:
    args_given_as_positional = set(scanner_arg_names[:len(positional_args)])
  # Check to see if any arg is given more than once
  if args_given_as_positional & set(kwargs):
    return False
  # Check to see if any required arg is missing
  if set(required_arg_names) - (set(kwargs) | args_given_as_positional):
    return False
  return True


@functools.cache
def _get_public_osv_url(osv_id: str) -> str:
  """Returns OSV URL for the given |osv_id| if available from public OSV."""
  try:
    vuln_info = osv_client.OsvClient().get_vuln(osv_id)
  except requests.RequestException:
    logging.error('Failed to connect to OSV. Assuming the vuln exists.')
    return osv_client.get_osv_url(osv_id)
  if 'code' in vuln_info:
    logging.debug(
        'Failed to get %s (code: %s, reason: %s)',
        osv_id,
        vuln_info['code'],
        vuln_info.get('message', ''),
    )
    return 'Not published.'
  return osv_client.get_osv_url(osv_id)


def _generate_json_report(
    report_file_name: str,
    report_book: reporter.ReportBook,
    covered_cves: Sequence[str],
) -> None:
  """Generates a JSON report based on the findings.

  Args:
    report_file_name: a JSON report file name to create.
    report_book: a report book instance containing all reports.
    covered_cves: a sequence of CVEs covered by this run.

  Returns:
    None
  """
  json_report = collections.OrderedDict()
  missing_patches = []
  for osv_id in report_book.unpatched_vulnerabilities:
    report_group = report_book.get_report_group(osv_id)
    if not report_group:
      continue
    details = []
    missing_patches.append({
        'ID': osv_id,
        'CVE': report_group.cve_ids,
        'OSV': _get_public_osv_url(osv_id),
        'details': details,
    })
    for report in report_group.reports:
      unpatched_code = report.unpatched_file
      if report.unpatched_function_name:
        unpatched_code += '::' + report.unpatched_function_name
      details.append({
          'unpatched_code': unpatched_code,
          'patch': report.signature_source,
          'is_non_target_match': report.is_non_target_match,
          'matched_signature': report.signature_id,
      })
  json_report['options'] = ' '.join(sys.argv[1:])
  json_report['covered_cves'] = covered_cves
  json_report['missing_patches'] = missing_patches
  with open(report_file_name, 'w') as report_file:
    json.dump(json_report, report_file, indent=4)


def _generate_html_report(
    report_file_name: str,
    report_book: reporter.ReportBook,
    covered_cves: Sequence[str],
    stats: scanner_base.ScannedFileStats,
) -> None:
  """Generates a HTML file summarizing the report in a human-readable format.

  Args:
    report_file_name: a HTML report file name to create.
    report_book: a report book instance containing all reports.
    covered_cves: a sequence of CVEs covered by this run.
    stats: |ScannedFileStats| object with scan result stats.

  Returns:
    None
  """
  env = jinja2.Environment()
  template = env.from_string(_HTML_REPORT_TEMPLATE)
  target_missing_patches = collections.defaultdict(
      lambda: collections.defaultdict(set))
  non_target_missing_patches = collections.defaultdict(
      lambda: collections.defaultdict(set))

  for osv_id in report_book.unpatched_vulnerabilities:
    report_groups = report_book.get_report_group(osv_id)
    if not report_groups:
      continue

    target_match_summaries = set()
    non_target_match_summaries = set()
    for report in report_groups.reports:
      summary = report.get_simple_report(
          include_patch_source=True, use_html_link_for_patch_source=True)
      if report.is_non_target_match:
        non_target_match_summaries.add(summary)
      else:
        target_match_summaries.add(summary)

    cve_ids = report_groups.cve_ids
    if target_match_summaries:
      target_missing_patches[osv_id]['summaries'] = target_match_summaries
      target_missing_patches[osv_id]['osv_url'] = _get_public_osv_url(osv_id)
      target_missing_patches[osv_id]['cve_ids'] = cve_ids if cve_ids else []
    if non_target_match_summaries:
      non_target_missing_patches[osv_id]['summaries'] = (
          non_target_match_summaries)
      non_target_missing_patches[osv_id]['osv_url'] = _get_public_osv_url(
          osv_id)
      non_target_missing_patches[osv_id]['cve_ids'] = cve_ids if cve_ids else []

  metadata = {
      **(stats.scan_metadata or {}),
      'analyzed_files': stats.analyzed_files,
      'skipped_files': stats.skipped_files}
  html_report = template.render(
      report_file_name=report_file_name,
      covered_cves=covered_cves,
      unpatched_cves=report_book.unpatched_cves,
      target_missing_patches=target_missing_patches,
      non_target_missing_patches=non_target_missing_patches,
      options=' '.join(sys.argv[1:]),
      metadata=metadata,
      errors=stats.errors,
  )

  with open(report_file_name, 'w') as f:
    f.write(html_report)


def main(argv: Sequence[str]) -> None:
  scanners = _get_all_scanners()
  scanners_list_str = '\n\n'.join(
      f'- {scanner.name()}: {scanner.__doc__ if scanner.__doc__ else ""}'
      for scanner in scanners.values())
  if len(argv) <= 0 or (len(argv) <= 1 and not _SCANNER.value):
    raise app.UsageError(
        f'Scanner is not specified. Known scanners:\n{scanners_list_str}')
  if _SCANNER.value:
    scanner_name = _SCANNER.value
    scanner_args = argv[1:]
  else:
    scanner_name = argv[1]
    scanner_args = argv[2:]

  if scanner_name not in scanners:
    raise app.UsageError(
        f'{scanner_name} is not a valid scanner. Known scanners:\n'
        f'{scanners_list_str}')
  scanner_class = scanners[scanner_name]
  scanner_kwargs = (
      json.loads(_SCANNER_ARGS.value) if _SCANNER_ARGS.value else {}
  )
  if not _is_valid_scanner_args(scanner_class, scanner_args, scanner_kwargs):
    raise app.UsageError(_get_scanner_usage_str(scanner_class))

  if not flags.FLAGS['verbosity'].present:
    # If verbosity was not explicitly set, use default INFO verbosity.
    # This is needed because app.run() overwrites the verbosity.
    flags.FLAGS.verbosity = logging.INFO
  logging.use_python_logging(quiet=True)

  # Check if output file can be generated before start scanning.
  output_file_name_prefix = _REPORT_FILE_NAME_PREFIX.value
  if not output_file_name_prefix:
    output_file_name_prefix = (
        '/tmp/vanir/report-%s'
        % datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    )

  directory = os.path.dirname(os.path.realpath(output_file_name_prefix))
  os.makedirs(directory, exist_ok=True)
  json_output_file_name = output_file_name_prefix + '.json'
  html_output_file_name = output_file_name_prefix + '.html'
  for output_file_name in [json_output_file_name, html_output_file_name]:
    report_file = open(output_file_name, 'w')
    report_file.close()

  scanner = scanner_class(*scanner_args, **scanner_kwargs)
  findings, stats, vuln_manager = scanner.scan(
      strategy=flags.FLAGS['target_selection_strategy'].value,
      override_vuln_manager=(
          detector_common_flags.generate_vuln_manager_from_flags()
      ),
      extra_vulnerability_filters=(
          detector_common_flags.generate_vulnerability_filters_from_flags()
      ),
      vulnerability_overwrite_specs=detector_common_flags.generate_overwrite_specs_from_flags(),
  )
  finding_filters = (
      [scanner_base.ShortFunctionFilter()]
      + list(detector_common_flags.generate_finding_filters_from_flags())
  )
  findings = scanner_base.ShortFunctionFilter().filter(findings)
  for finding_filter in finding_filters:
    findings = finding_filter.filter(findings)

  report_book = reporter.ReportBook(
      reporter.generate_reports(findings), vuln_manager
  )
  unpatched_cves = report_book.unpatched_cves

  signatures = vuln_manager.signatures
  covered_cves = itertools.chain.from_iterable(
      [vuln_manager.sign_id_to_cve_ids(sign.signature_id)
       for sign in signatures]
  )
  covered_cves = sorted(set(covered_cves))

  # Generate a machine-readable JSON report.
  _generate_json_report(json_output_file_name, report_book, covered_cves)

  # Generate a human-readable HTML report.
  _generate_html_report(html_output_file_name, report_book, covered_cves, stats)

  # Generate a console output.
  scanned_files = stats.analyzed_files + stats.skipped_files
  if scanned_files < _MINIMUM_NUMBER_OF_FILES.value:
    logging.error(
        'The scanned target directory contains only %s file(s) supported by'
        ' Vanir. Please confirm that this is intended.\n',
        scanned_files,
    )
  elif stats.analyzed_files < _MINIMUM_NUMBER_OF_FILES.value:
    logging.error(
        'The scanned target directory contains only %s file(s) analyzed by'
        ' Vanir (%s file(s) were skipped). Please confirm that this is'
        ' intended. This might happen when a wrong |target_root| is passed.',
        stats.analyzed_files,
        stats.skipped_files,
    )

  message = (
      f'Scanned {stats.analyzed_files} source files '
      f'(skipped {stats.skipped_files} source files likely unaffected by '
      'known vulnerabilities).\n'
      f'Found {len(unpatched_cves)} potentially unpatched vulnerabilities: '
      f'{", ".join(unpatched_cves)}\n'
      f'Detailed report:\n - {html_output_file_name}\n'
      f' - {json_output_file_name}'
  )
  print(message)

if __name__ == '__main__':
  app.run(main)
