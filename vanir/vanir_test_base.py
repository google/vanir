# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Vanir test base module.

This module contains the base class of Vanir tests that includes utility
methods and constants for internal tests.
"""

from collections import abc
import contextlib
import time

from absl import logging
from absl.testing import absltest


class VanirTestBase(absltest.TestCase):
  """Vanir test base class containing common utility methods for tests."""

  @contextlib.contextmanager
  def runtime_reporter(self, name: str) -> abc.Generator[None, None, None]:
    start = time.monotonic()
    try:
      yield
    finally:
      elapsed = time.monotonic() - start
      logging.info('runtime::%s %d seconds', name, elapsed)
      pass
