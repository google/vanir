# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Reporter module for managing Vanir report data structures."""

import collections
import dataclasses
import functools
import itertools
from typing import Optional, Sequence, Union
from vanir import vulnerability_manager
from vanir.scanners import scanner_base


@dataclasses.dataclass(frozen=True)
class Report:
  """Dataclass to contain an individual finding to report.

  Each report corresponds to a mapping of one signature and one matched chunk.

  Attributes:
    signature_id: unique ID of the matched signature.
    signature_target_file: original target file of the signature.
    signature_target_function: original target function of the signature.
    signature_source: the source of the patch used to generate the signature.
    unpatched_file: the file matched the signature in the target system.
    unpatched_function_name: the function matched the signature in the target
      system.
    is_non_target_match: whether this matches against a signature's target
      file, or match against other files in the scanned code.
  """

  signature_id: str
  signature_target_file: str
  signature_target_function: str
  signature_source: str
  unpatched_file: str
  unpatched_function_name: str
  is_non_target_match: bool

  def get_simple_report(
      self,
      include_patch_source: bool = False,
      use_html_link_for_patch_source: bool = False,
  ) -> str:
    """Returns unpatched file and optionally unpatched function name."""
    simple_report = self.unpatched_file
    if self.unpatched_function_name:
      simple_report += '::%s()' % self.unpatched_function_name
    if include_patch_source:
      if use_html_link_for_patch_source:
        simple_report += '  (<a href="%s">patch</a>, %s)' % (
            self.signature_source,
            self.signature_id,
        )
      else:
        simple_report += '  (patch:%s, signature:%s)' % (
            self.signature_source,
            self.signature_id,
        )
    return simple_report


@dataclasses.dataclass(frozen=True)
class ReportGroup:
  """Dataclass for managing multiple reports grouped by a vulnerability ID."""

  osv_id: str
  cve_ids: Sequence[str]
  reports: Sequence[Report]


class ReportBook:
  """Class for managing multiple report groups."""

  def __init__(
      self,
      reports: Sequence[Report],
      vul_manager: vulnerability_manager.VulnerabilityManager,
  ):
    """Generates a report book for the given reports."""
    self._report_group_dict = {}
    reports_per_vul = collections.defaultdict(list)
    for report in reports:
      osv_id = vul_manager.sign_id_to_osv_id(report.signature_id)
      reports_per_vul[osv_id].append(report)
    for osv_id, reports in reports_per_vul.items():
      report_group = ReportGroup(
          osv_id, vul_manager.osv_id_to_cve_ids(osv_id), reports
      )
      self._report_group_dict[osv_id] = report_group

  @property
  def unpatched_vulnerabilities(self) -> Sequence[Union[str, None]]:
    """Returns a list of OSV IDs of vulns reported as not patched."""
    return list(self._report_group_dict.keys())

  @functools.cached_property
  def unpatched_cves(self) -> Sequence[str]:
    """Returns a list of CVEs reported as not patched."""
    cves = itertools.chain.from_iterable(
        [rgroup.cve_ids for rgroup in self._report_group_dict.values()]
    )
    return sorted(set(cves))

  def get_report_group(self, osv_id: str) -> Optional[ReportGroup]:
    """Returns a report group mapped to |osv_id|.

    Args:
      osv_id: the OSV ID string.

    Returns:
      Returns a report group mapped to |osv_id| or None if none matches.
    """
    return self._report_group_dict.get(osv_id)


def generate_reports(
    findings: scanner_base.Findings
) -> Sequence[Report]:
  """A helper function to convert a Scanner's Findings to a list of Reports."""
  reports = []
  for sign, chunks in findings.items():
    for chunk in chunks:
      is_non_target_match = not chunk.target_file.endswith(sign.target_file)
      reports.append(
          Report(
              signature_id=sign.signature_id,
              signature_target_file=sign.target_file,
              signature_target_function=getattr(sign, 'target_function', ''),
              signature_source=sign.source,
              unpatched_file=chunk.target_file,
              unpatched_function_name=getattr(chunk.base, 'name', ''),
              is_non_target_match=is_non_target_match,
          )
      )
  return reports
