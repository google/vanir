# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Vanir detector scanner that scans Android Linux Kernel vulns.
"""

import dataclasses
from typing import Optional, Sequence, Tuple

from absl import logging
from vanir import version_extractor
from vanir import vulnerability
from vanir import vulnerability_manager
from vanir import vulnerability_overwriter
from vanir.scanners import package_scanner
from vanir.scanners import scanner_base
from vanir.scanners import target_selection_strategy


class AndroidKernelScanner(package_scanner.PackageScanner):
  """Vanir detector scanner that scans Android Linux Kernel vulns.

  AndroidKernelScanner is an offline package scanner specialized for Android
  kernel vulnerabilities, which scans the designated directory with kernel
  vuln signatures. Any non-kernel vuln signatures included in the vulnerability
  manager will be ignored.
  """

  def __init__(self, code_location):
    super().__init__(
        ecosystem='Android',
        package=vulnerability.MetaPackage.ANDROID_KERNEL,
        code_location=code_location,
    )

  @classmethod
  def name(cls):
    return 'android_kernel_scanner'

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

    logging.info(
        'Scanning %s against Android kernel signatures...', self._code_location)
    findings, stats, vuln_manager = super().scan(
        strategy,
        override_vuln_manager,
        extra_vulnerability_filters,
        vulnerability_overwrite_specs
    )

    logging.info('Collecting findings...')
    version_data = {
        'version': version_extractor.extract_version(self._code_location)}
    new_stats = dataclasses.replace(
        stats, scan_metadata={**(stats.scan_metadata or {}), **version_data})
    return findings, new_stats, vuln_manager
