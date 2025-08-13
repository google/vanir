# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Vanir detector scanner that scans a given directory against given signatures.
"""

from typing import Optional, Sequence, Tuple

from absl import logging
from vanir import signature
from vanir import vulnerability_manager
from vanir import vulnerability_overwriter
from vanir.scanners import scanner_base
from vanir.scanners import target_selection_strategy


class OfflineDirectoryScanner(scanner_base.ScannerBase):
  """Vanir scanner that scans a directory against a local vulns json file.

  This scanner requires signatures to be given in vul_file_path.
  """

  def __init__(self, code_location: str):
    self._code_location = code_location

  @classmethod
  def name(cls):
    return 'offline_directory_scanner'

  def scan_offline_directory(
      self,
      vuln_manager: vulnerability_manager.VulnerabilityManager,
      strategy: target_selection_strategy.Strategy = (
          target_selection_strategy.Strategy.TRUNCATED_PATH_MATCH
      ),
  ) -> Tuple[scanner_base.Findings, scanner_base.ScannedFileStats]:
    """Scans the local direcotry designated in |_code_location|."""
    return scanner_base.scan(
        self._code_location,
        signature.SignatureBundle(vuln_manager.signatures),
        strategy=strategy,
    )

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
    if override_vuln_manager is None:
      raise ValueError(
          f'{self.name()} requires at least one --vulnerability_file_name')
    vuln_manager = vulnerability_manager.generate_from_managers(
        [override_vuln_manager],
        vulnerability_filters=extra_vulnerability_filters,
    )
    logging.info('Scanning %s against all signatures...', self._code_location)
    findings, stats = self.scan_offline_directory(vuln_manager, strategy)

    return findings, stats, vuln_manager
