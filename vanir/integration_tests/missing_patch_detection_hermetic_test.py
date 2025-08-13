# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

import base64
import collections
import dataclasses
import enum
import json
import re
import tarfile
from typing import Any, Callable, Collection
from unittest import mock
from absl import logging
from absl.testing import parameterized
import requests
from vanir import file_path_utils
from vanir import osv_client
from vanir import reporter
from vanir import signature
from vanir import vanir_test_base
from vanir import vulnerability
from vanir import vulnerability_manager
from vanir.code_extractors import code_extractor_android
from vanir.scanners import scanner_base
from vanir.testdata import test_signatures
from absl.testing import absltest

_TESTDATA_DIR = file_path_utils.get_root_file_path('testdata/')
_GITILES_TESTDATA_DIR = _TESTDATA_DIR + 'gitiles/'

_TEST_FRAMEWORKS_BASE = _TESTDATA_DIR + 'test_frameworks_base.tar.gz'
_TEST_PLATFORM_VULN_PATH = _TESTDATA_DIR + 'test_vulnerabilities_platform.json'
_TEST_PLATFORM_VULNERABILITIES = open(_TEST_PLATFORM_VULN_PATH, mode='rb').read()

# test_vulnerabilities.json contains 3 vulns with 4 patches, necessitating fake
# HTTP downloads of those 4 patches as well as files from 8 revs (before/after).
# These are supposed to be from gitiles, which serves the patch/file content
# as base64-encoded data when requested with "?format=TEXT".
# Files are named in the format "<sha>_<cleaned_filename>.base64".
# |sha| is the same sha as requested in the URL.
# |cleaned_filename| is filename with slashes "/" replaced with underscores "_"
# If test_vulnerabilities.json is modified, corresponding patches and file
# contents will need to be added to testdata/gitiles/.
# An easy way to do this is to watch the log for any 404 response and run
# |curl| on those URLs to a file.

_FULL_SHA_URL_PATTERN = (
    r'https://android\.googlesource\.com/(?P<proj>.*)/\+/(?P<sha>[0-9a-f]+)'
)
_PATCH_INFO_URL_PATTERN = _FULL_SHA_URL_PATTERN + r'\?format=TEXT'
_PATCH_URL_PATTERN = _FULL_SHA_URL_PATTERN + r'\^\!\?format=TEXT'
_FILE_URL_PATTERN = _FULL_SHA_URL_PATTERN + r'/(?P<file>[^?]+)\?format=TEXT'

# https://android.googlesource.com/kernel/common/+/android14-security-release/net/core/filter.c?format=TEXT
_BRANCH_TIP_FILE_URL_PATTERN = (
    r'https://android\.googlesource\.com/(?P<proj>.*)/\+/'
    r'(?P<branch>([^/]*-security-release|main))/(?P<file>[^?]+)\?format=TEXT'
)

_FULL_SHA = {
    'e80c3533c354e': 'e80c3533c354ede56146ab0e4fbb8304d0c1209f',
    'f5893af2704eb': 'f5893af2704eb763eb982f01d573f5b19f06b623',
    'bce1305c0ece3': 'bce1305c0ece3dc549663605e567655dd701752c',
}

_OSV_QUERY_URL = 'https://api.osv.dev/v1/query'


def _mock_request_error(msg: str, status: int = 404) -> Any:
  mock_response = absltest.mock.MagicMock(text=msg, ok=False, status=status)
  mock_response.raise_for_status.side_effect = requests.RequestException(msg)
  return mock_response


@enum.unique
class VulnerabilityDataSource(enum.Enum):
  """Enumeration of vulnerability data source for testing."""
  OSV = 'osv'
  FILE = 'file'


def _fake_gitiles_response(url: str):
  """Returns files/patches that would be queried from Android gitiles."""
  fake_source = ''
  try:
    if m := re.fullmatch(_FULL_SHA_URL_PATTERN, url):
      res = _FULL_SHA[m.group('sha')]
    elif m := re.fullmatch(_PATCH_INFO_URL_PATTERN, url):
      fake_source = f'{_GITILES_TESTDATA_DIR}{m.group("sha")}.patchinfo.base64'
      res = open(fake_source, mode='rb').read()
    elif m := re.fullmatch(_PATCH_URL_PATTERN, url):
      fake_source = f'{_GITILES_TESTDATA_DIR}{m.group("sha")}.patch.base64'
      res = open(fake_source, mode='rb').read()
    elif m := re.fullmatch(_FILE_URL_PATTERN, url):
      fake_source = (f'{_GITILES_TESTDATA_DIR}{m.group("sha")}_'
                     f'{m.group("file").replace("/", "_")}.base64')
      res = open(fake_source, mode='rb').read()
    elif m := re.fullmatch(_BRANCH_TIP_FILE_URL_PATTERN, url):
      fake_source = (f'{_GITILES_TESTDATA_DIR}{m.group("branch")}_'
                     f'{m.group("file").replace("/", "_")}.base64')
      res = open(fake_source, mode='rb').read()
    else:
      raise RuntimeError('Unexpected gitiles URL: "%s"' % url)

  except FileNotFoundError as e:
    # File is not found; simulate a 404 (e.g. newly created file)
    logging.warning('Fake response not found for: "%s". Returning 404.', url)
    return _mock_request_error(str(e), 404)

  logging.info('Faking "%s" --> "%s" (%d bytes)', url, fake_source, len(res))
  return absltest.mock.MagicMock(text=res, ok=True, status=200)


def _make_fake_osv_response(json_str: str) -> Callable[[str, str], Any]:
  """Returns a mock side_effect function that returns OSV responses in 2 pages.
  """
  def fake_osv_response(url: str, data: str) -> Any:
    if _OSV_QUERY_URL not in url:
      raise RuntimeError('Unexpected POST URL: "%s"' % url)
    data_json = json.loads(data)
    vulns_json = json.loads(json_str)
    if ('package' not in data_json
        or data_json['package']['ecosystem'] != 'Android'
        or data_json['package']['name'] != ':linux_kernel:'):
      res = json.dumps({'vulns': []})
    elif 'page_token' not in data_json:
      res = json.dumps({'vulns': vulns_json[:-1], 'next_page_token': 'token'})
    elif data_json['page_token'] == 'token':
      res = json.dumps({'vulns': vulns_json[-1:]})
    else:
      raise RuntimeError('Unexpected page token "%s"' % data_json['page_token'])
    return absltest.mock.MagicMock(text=res, ok=True, status=200)

  return fake_osv_response


class MissingPatchDetectionHermeticTest(
    vanir_test_base.VanirTestBase, parameterized.TestCase):

  def _compare_signatures(
      self,
      signatures: Collection[signature.Signature],
      expected_signatures: Collection[signature.Signature],
  ):
    cleaned_sigs = {
        dataclasses.replace(sig, signature_id='')
        for sig in signatures
    }
    cleaned_expected_sigs = {
        dataclasses.replace(sig, signature_id='')
        for sig in expected_signatures
    }
    self.assertSetEqual(cleaned_sigs, cleaned_expected_sigs)

  @parameterized.named_parameters(
      {
          'testcase_name': 'userspace_via_json_file',
          'vuln_source_type': VulnerabilityDataSource.FILE,
          'vulns_json': _TEST_PLATFORM_VULNERABILITIES,
          'tarball_path': _TEST_FRAMEWORKS_BASE,
          'expected_signatures': test_signatures.EXPECTED_SIGNATURES_PLATFORM,
          'expected_covered_vulns': {'ASB-A-202768292'},
          'expected_unpatched_vulns': {'ASB-A-202768292'},
      }, {
          'testcase_name': 'userspace_via_osv',
          'vuln_source_type': VulnerabilityDataSource.OSV,
          'vulns_json': _TEST_PLATFORM_VULNERABILITIES,
          'tarball_path': _TEST_FRAMEWORKS_BASE,
          'expected_signatures': test_signatures.EXPECTED_SIGNATURES_PLATFORM,
          'expected_covered_vulns': {'ASB-A-202768292'},
          'expected_unpatched_vulns': {'ASB-A-202768292'},
      }
  )
  @absltest.mock.patch.object(requests.sessions, 'Session', autospec=True)
  def test_missing_patch_detection(
      self,
      mock_session,
      expected_unpatched_vulns: set[str],
      expected_covered_vulns: set[str],
      expected_signatures: set[signature.Signature],
      tarball_path: str,
      vulns_json: str,
      vuln_source_type: VulnerabilityDataSource,
  ):
    self.enter_context(
        mock.patch.object(
            code_extractor_android.AndroidCodeExtractor,
            'VERSION_BRANCH_MAP',
            new={
                '13': 'android13-security-release',
                '14': 'android14-security-release',
                '15': 'android15-security-release',
                '15-next': 'main',
            },
        )
    )
    mock_session().get.side_effect = _fake_gitiles_response

    with self.runtime_reporter('vul_ingest'):
      if vuln_source_type == VulnerabilityDataSource.FILE:
        vul_manager = vulnerability_manager.generate_from_json_string(
            vulns_json
        )
      else:
        mock_session().post.side_effect = _make_fake_osv_response(vulns_json)
        vul_manager = vulnerability_manager.generate_from_osv(
            'Android', vulnerability.MetaPackage.ANDROID_KERNEL)

    with self.runtime_reporter('sign_gen'):
      vul_manager.generate_signatures()

    signatures = vul_manager.signatures
    self._compare_signatures(signatures, expected_signatures)
    pass

    covered_vulns = set(
        vuln.id for vuln in vul_manager.vulnerabilities
        if any(affected.vanir_signatures for affected in vuln.affected)
    )
    covered_vulns_str = ' '.join(sorted(covered_vulns))
    pass
    logging.info('Covered Vulnerabilities: %s', covered_vulns_str)
    pass
    self.assertSetEqual(expected_covered_vulns, covered_vulns)

    with self.runtime_reporter('target_extraction'):
      test_src_dir = self.create_tempdir()
      with open(tarball_path, mode='rb') as tarball_obj:
        with tarfile.open(fileobj=tarball_obj, mode='r:gz') as f:
          f.extractall(test_src_dir)

    with self.runtime_reporter('detection'):
      findings, _ = scanner_base.scan(
          test_src_dir, signature.SignatureBundle(signatures),
      )
      findings = scanner_base.ShortFunctionFilter().filter(findings)

    with self.runtime_reporter('report_gen'):
      reports = reporter.generate_reports(findings)
      summaries_per_vul = collections.defaultdict(set)
      for report in reports:
        osv_id = vul_manager.sign_id_to_osv_id(report.signature_id)
        summary = report.get_simple_report(include_patch_source=True)
        summaries_per_vul[osv_id].add(summary)
      unpatched_vuls = []
      for osv_id, summaries in summaries_per_vul.items():
        summaries = sorted(summaries)
        summaries.append('OSV: %s' % osv_client.get_osv_url(osv_id))
        cve_ids = vul_manager.osv_id_to_cve_ids(osv_id)
        if cve_ids:
          summaries.append('CVE: %s' % ', '.join(cve_ids))
        pass
        unpatched_vuls.append(osv_id)

    self.assertSetEqual(expected_unpatched_vulns, set(unpatched_vuls))


if __name__ == '__main__':
  absltest.main()
