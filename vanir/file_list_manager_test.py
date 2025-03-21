# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Test for file list manager module."""

import json

from vanir import file_list_manager

from absl.testing import absltest

_TEST_SUPPORTED_FILE_LIST = ['foo.c', 'bar.c']
_TEST_UNSUPPORTED_FILE_LIST = ['unsupported_filetype.asp']
_TEST_FILE_LIST = _TEST_SUPPORTED_FILE_LIST + _TEST_UNSUPPORTED_FILE_LIST
_TEST_SHA = 'abcdef1234567890'
_TEST_FILE_LISTS_JSON_STR = json.dumps(
    {'Android': {':linux_kernel:': _TEST_SUPPORTED_FILE_LIST}}
)


class FileListManagerTest(absltest.TestCase):

  def test_get_file_lists_with_cache(self):
    file_lists = file_list_manager.get_file_lists(
        file_list_manager.Source.CACHE
    )
    kernel_file_list = file_lists.get('Android', {}).get(':linux_kernel:')
    self.assertGreater(len(kernel_file_list), 50000)

  def test_get_file_lists_fail_with_unknown_source(self):
    with self.assertRaises(ValueError):
      file_list_manager.get_file_lists('unknown_source')


if __name__ == '__main__':
  absltest.main()
