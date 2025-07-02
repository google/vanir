# Copyright 2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""The test to validate the overwrite specs file.

Use this test to validate the overwrite specs file.
The test makes sure:
1. The overwrite specs are valid.
2. 'Reason' field is provided.
3. Each spec matches a vulnerability (if signature files are provided).
4. Each 'replace' operation has a JSON Path that yields a match (if signature
files are provided).

For future reference, each overwrite spec should include a reason for the
overwrite.

If you provide a list of signature files, the test will also verify that each
spec has a matching vulnerability ID, ensuring accuracy and preventing typos.
The test will verify that each 'replace' operation has a valid
JSONPath expression that yields a match, ensuring the expression is not
mistyped. Note that empty matches at runtime do not raise an error.
"""

from collections.abc import Mapping
from collections.abc import Sequence
import json
import logging
from typing import Any
from absl import flags
from vanir import vulnerability_overwriter
from absl.testing import absltest

_OVERWRITE_SPECS = flags.DEFINE_string(
    'overwrite_specs',
    None,
    'Path to a file containing vulnerability overwrite specs. The file should '
    'be a JSON array with vulnerability_overwriter.OverwriteSpec objects.',
    required=True,
)

_SIGNATURE_FILES = flags.DEFINE_multi_string(
    'signature_files',
    None,
    'List of files containing vulnerability signatures to ensure that overwrite'
    ' specs have a matching vulnerability id.',
    required=False,
)

_NO_SIGNATURE_VALIDATION = flags.DEFINE_bool(
    'no_signature_validation',
    False,
    'Skip validation of overwrite specs against signature files.',
    required=False,
)


class OverwriteSpecValidityTest(absltest.TestCase):

  def _load_from_signature_files(self) -> Sequence[dict[str, Any]]:
    """Loads signature files and returns a list of OSV vulnerability objects."""

    vulnerabilities = []
    if _SIGNATURE_FILES.value:
      for signature_file in _SIGNATURE_FILES.value:
        logging.info('Loading vulnerabilities from %s', signature_file)
        with open(signature_file) as f:
          signature_file_content = f.read()
          vulnerabilities.extend(json.loads(signature_file_content))
    return vulnerabilities

  def _to_specs_map(
      self,
      overwrite_specs: Sequence[vulnerability_overwriter.OverwriteSpec],
  ) -> Mapping[str, vulnerability_overwriter.OverwriteSpec]:
    """Converts a list of overwrite specs to a map keyed by vulnerability ID.

    Args:
      overwrite_specs: A list of overwrite specs.

    Returns:
      A map of overwrite specs, keyed by vulnerability ID.
    """
    overwrite_specs_map = {}
    for spec in overwrite_specs:
      if spec.vuln_id in overwrite_specs_map:
        self.fail(
            'Found multiple specs for vulnerability'
            f' "{spec.vuln_id}". There should be only one spec for a'
            ' vulnerability'
        )
      else:
        overwrite_specs_map[spec.vuln_id] = spec
    return overwrite_specs_map

  def test_validate_overwrite_spec(self):

    # Validate overwrite specs during loading and raise an error if
    # the file or its contents are invalid.
    overwrite_specs_file_path = _OVERWRITE_SPECS.value
    overwrite_specs = vulnerability_overwriter.load_overwrite_specs_from_file(
        overwrite_specs_file_path
    )

    # Need a map to quickly find the spec for a given vulnerability by ID.
    overwrite_specs_map = self._to_specs_map(overwrite_specs)
    self.assertNotEmpty(
        overwrite_specs_map, msg='No overwrite specs found in the file'
    )

    vulnerabilities = self._load_from_signature_files()
    if not vulnerabilities or _NO_SIGNATURE_VALIDATION.value:
      logging.info('Validated overwrite specs without signature files.')
      return

    # Track vulnerabilities that should be overwritten but haven't been yet.
    target_vulnerabilities = set(overwrite_specs_map.keys())
    for vulnerability in vulnerabilities:
      if vulnerability['id'] in overwrite_specs_map:
        target_vulnerabilities.discard(vulnerability['id'])

        # Check that the spec has a path yielding a match, since 'overwrite'
        # does not raise an error if no matches are found.
        for replace in overwrite_specs_map[vulnerability['id']].replace:
          if not replace.path.find(vulnerability):
            self.fail(
                f'Overwrite spec for {vulnerability["id"]} has a path yielding '
                'no matches.'
            )

        # Make sure the spec doesn't cause any runtime errors.
        vulnerability_overwriter.overwrite(
            [vulnerability], [overwrite_specs_map[vulnerability['id']]]
        )
    self.assertEmpty(
        target_vulnerabilities,
        'All overwrite specs are loaded correctly and have required fields, but'
        ' some specs do not match any vulnerabilities in the signature files. '
        'You may suppress this error by setting --no_signature_validation=True.'
        ' Missing vulnerabilities: %s' % target_vulnerabilities,
    )


if __name__ == '__main__':
  absltest.main()
