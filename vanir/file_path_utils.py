# Copyright 2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Module for managing file paths in the vanir package."""

import os.path


def get_root_file_path(relative_path):
  """Gets the absolute path to a file within the 'vanir' package."""
  vanir_dir = os.path.dirname(os.path.abspath(__file__))
  return os.path.join(vanir_dir, relative_path)
