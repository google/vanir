# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""This module abstracts the usage of OSV APIs for retrieving Android CVEs."""

import enum
import io
import json
from typing import Any, Dict, Optional, Sequence
import zipfile

from absl import flags
from google.cloud import storage
import requests


_OSV_PROD_URL_BASE = 'https://api.osv.dev/v1/'

_OSV_API_KEY = 'AIzaSyAVJKt1YY0yNWHz2TBZU6Hj1nAJq1O-9Gc'

_OSV_QUERY_POSTFIX = 'query'
_OSV_VULNERABILITY_POSTFIX = 'vulns'

_OSV_VULNERABILITIES = 'vulns'
_OSV_NEXT_PAGE_TOKEN = 'next_page_token'
_ANDROID_ECOSYSTEM = 'Android'

_ANDROID_COMPONENT_KERNEL = ':linux_kernel:'

_KNOWN_SOC_SUBCOMPONENTS = (
    'AMLogic',
    'ARM',
    'Broadcom',
    'MediaTek',
    'Marvell',
    'NVIDIA',
    'Qualcomm',
    'Unisoc',
)

ANDROID_KERNEL_PACKAGES = (_ANDROID_COMPONENT_KERNEL,) + tuple(
    _ANDROID_COMPONENT_KERNEL + soc_subcomponent
    for soc_subcomponent in _KNOWN_SOC_SUBCOMPONENTS)

_OSV_LINK_PREFIX = 'https://osv.dev/vulnerability/'

# https://google.github.io/osv.dev/data/#data-dumps
_OSV_GCS_BUCKET = 'osv-vulnerabilities'


def get_osv_url(osv_id: str) -> str:
  """Returns public OSV URL for the given OSV entry."""
  return _OSV_LINK_PREFIX + osv_id


class OsvClient:
  """Class to abstract OSV APIs for retrieving Android CVEs."""

  def __init__(self, session: Optional[requests.sessions.Session] = None):
    self._session = session or requests.session()
    self._osv_api_key = _OSV_API_KEY
    self._osv_url_base = _OSV_PROD_URL_BASE

  def get_vuln(self, osv_id: str) -> Dict[str, Any]:
    """Retrieve specific vulnerability for the given OSV ID from OSV."""
    osv_vulnerability_url = '%s%s/%s?key=%s' % (
        self._osv_url_base,
        _OSV_VULNERABILITY_POSTFIX,
        osv_id,
        self._osv_api_key,
    )
    response = self._session.get(osv_vulnerability_url)
    return json.loads(response.text)

  def get_vulns_for_packages(
      self, ecosystem: str, package_names: Sequence[str]
  ) -> list[Dict[str, Any]]:
    """Retrieve all vulns in the given ecosystem and package list from OSV."""
    vulnerabilities = []
    for package_name in package_names:
      osv_query_url = '%s%s?key=%s' % (
          self._osv_url_base,
          _OSV_QUERY_POSTFIX,
          self._osv_api_key,
      )
      payload = {
          'package': {
              'ecosystem': ecosystem,
              'name': package_name,
          }
      }
      while True:
        response = self._session.post(osv_query_url, data=json.dumps(payload))
        osv_data = json.loads(response.text)
        vulnerabilities += osv_data.get(_OSV_VULNERABILITIES, [])
        next_page_token = osv_data.get(_OSV_NEXT_PAGE_TOKEN, None)
        if not next_page_token:
          break
        payload['page_token'] = next_page_token

    return vulnerabilities

  def get_vulns_for_ecosystem(self, ecosystem: str) -> list[Dict[str, Any]]:
    """Retrieve all vulns in the given ecosystem from OSV."""
    vulnerabilities = []
    bucket_name = _OSV_GCS_BUCKET
    blob_name = f'{ecosystem}/all.zip'

    storage_client = storage.Client.create_anonymous_client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    with io.BytesIO() as zip_in_memory:
      blob.download_to_file(zip_in_memory)
      zip_in_memory.seek(0)
      with zipfile.ZipFile(zip_in_memory) as zip_file:
        for filename in zip_file.namelist():
          if filename.endswith('.json'):
            vulnerabilities.append(json.loads(zip_file.read(filename)))
    return vulnerabilities
