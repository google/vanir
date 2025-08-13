# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Vanir detector scanner that scans vulns pertaining to one OSV package.
"""

from typing import Optional, Sequence, Tuple

from absl import logging
from vanir import vulnerability
from vanir import vulnerability_manager
from vanir import vulnerability_overwriter
from vanir.scanners import offline_directory_scanner
from vanir.scanners import scanner_base
from vanir.scanners import target_selection_strategy


class PackageScanner(offline_directory_scanner.OfflineDirectoryScanner):
  """Scan a code directory against vulns within a single OSV package.

  PackageScanner is an offline directory scanner with pacakage filters. I.e.,
  this scanner first filters out all signatures unrelated to the package and
  ecosystem designated in |ecosystem| and |package|, and run against
  the offline directory designated in |code_location|.
  """

  def __init__(
      self, ecosystem: str, package: scanner_base.Package, code_location: str
  ):
    super().__init__(code_location)
    self._ecosystem = ecosystem
    self._package = package

  @classmethod
  def name(cls):
    return 'package_scanner'

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
    is_meta_package = isinstance(self._package, vulnerability.MetaPackage)
    if is_meta_package:
      package_vfilter = vulnerability_manager.AffectedPackageNameFilter(
          self._package.package_pattern
      )
    else:
      package_vfilter = vulnerability_manager.AffectedPackageNameFilter(
          self._package
      )
    ecosystem_filter = vulnerability_manager.AffectedEcosystemFilter(
        self._ecosystem
    )
    vfilters = [ecosystem_filter, package_vfilter] + (
        extra_vulnerability_filters or []
    )

    if override_vuln_manager is not None:
      vuln_manager = vulnerability_manager.generate_from_managers(
          [override_vuln_manager], vulnerability_filters=vfilters
      )
    else:
      vuln_manager = vulnerability_manager.generate_from_osv(
          self._ecosystem,
          self._package if is_meta_package else [self._package],
          vulnerability_filters=vfilters,
          vulnerability_overwrite_specs=vulnerability_overwrite_specs,
      )

    logging.info(
        'Scanning %s against signatures for %s...',
        self._code_location, self._package)
    findings, stats = self.scan_offline_directory(vuln_manager, strategy)

    return findings, stats, vuln_manager
